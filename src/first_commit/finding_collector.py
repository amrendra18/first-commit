import hashlib
from collections.abc import Iterable, Iterator, Mapping, Sequence

from first_commit.checks.privacy import (
    PrivacyPolicy,
    forbidden_path_policy,
    privacy_findings,
    privacy_policy,
)
from first_commit.checks.text import no_commit_findings, text_findings
from first_commit.models import Candidate, Finding, Origin, Result, capped
from first_commit.policy import REQUIRED_DOCUMENTS, Policy

TOO_LARGE_RULE = "files.too-large"


def _sort_key(item: Finding) -> tuple[str, int, str]:
    return (item.path, item.line or 0, item.rule_id)


class FindingCollector:
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.items: list[Finding] = []

    @property
    def room(self) -> int:
        return self.cap - len(self.items)

    def full(self) -> bool:
        return self.room <= 0

    def add(self, findings: Iterable[Finding]) -> None:
        self.items.extend(capped(findings, self.room))

    def result(self, scope: str) -> Result:
        return Result(scope=scope, findings=tuple(sorted(self.items, key=_sort_key)))


def split_forbidden(
    paths: Sequence[str], policy: Policy
) -> tuple[tuple[str, ...], frozenset[str]]:
    excluded = frozenset(
        path for path in paths if forbidden_path_policy(path, policy.forbidden_paths)
    )
    return tuple(path for path in paths if path not in excluded), excluded


def too_large_findings(paths: Sequence[str], *, max_findings: int) -> list[Finding]:
    summary = "File is over the size limit, so its content was not checked."
    findings = (
        Finding(rule_id=TOO_LARGE_RULE, path=path, summary=summary) for path in paths
    )
    return capped(findings, max_findings)


def _required_document_findings(
    documents: Mapping[str, Candidate],
) -> Iterator[Finding]:
    for path in REQUIRED_DOCUMENTS:
        candidate = documents.get(path)
        if candidate is None or not candidate.content:
            yield Finding(
                rule_id="documents.required",
                path=path,
                summary="Required public document is missing or empty.",
            )


def _is_immutable_vendor(
    candidate: Candidate, vendor_hashes: Mapping[str, str]
) -> bool:
    return (
        candidate.origin != Origin.MESSAGE
        and candidate.regular_file
        and candidate.path in vendor_hashes
        and hashlib.sha256(candidate.content).hexdigest()
        == vendor_hashes[candidate.path]
    )


def _candidate_findings(
    found: FindingCollector,
    candidate: Candidate,
    privacy: PrivacyPolicy,
    vendor_hashes: Mapping[str, str],
) -> None:
    found.add(no_commit_findings(candidate, max_findings=found.room))
    if found.full():
        return
    immutable_vendor = _is_immutable_vendor(candidate, vendor_hashes)
    found.add(
        text_findings(
            candidate, max_findings=found.room, immutable_vendor=immutable_vendor
        )
    )
    if found.full():
        return
    found.add(
        privacy_findings(
            candidate,
            privacy,
            max_findings=found.room,
            immutable_vendor=immutable_vendor,
        )
    )


def evaluate(
    found: FindingCollector,
    candidates: Iterable[Candidate],
    policy: Policy,
    documents: Mapping[str, Candidate] | None,
    private_values: Sequence[str],
) -> None:
    if documents is not None:
        found.add(_required_document_findings(documents))
    vendor_hashes = {item.path: item.sha256 for item in policy.immutable_vendor_files}
    privacy = privacy_policy(policy, private_values)
    for candidate in candidates:
        if found.full():
            break
        _candidate_findings(found, candidate, privacy, vendor_hashes)
