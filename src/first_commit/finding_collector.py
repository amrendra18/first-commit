import hashlib
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence

from first_commit.checks.privacy import (
    PrivacyPolicy,
    forbidden_path_policy,
    privacy_findings,
    privacy_policy,
)
from first_commit.checks.text import no_commit_findings, text_findings
from first_commit.models import Candidate, Finding, KeptFindings, Origin, Result, capped
from first_commit.policy import REQUIRED_DOCUMENTS, Policy

TOO_LARGE_RULE = "files.too-large"


def _sort_key(item: Finding) -> tuple[str, int, str]:
    return (item.path, item.line or 0, item.rule_id)


# The cap limits what is shown; every finding added counts for pass or fail, as an
# error always takes the place of a warning. One finding more than the cap is held,
# so a run that stops early has left a finding out and the result says so.
class FindingCollector:
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self._kept = KeptFindings(cap + 1)
        self._not_shown = 0

    @property
    def items(self) -> list[Finding]:
        return self._kept.items

    # The budget of each check: warnings held take no room from its errors.
    @property
    def room(self) -> int:
        return self._kept.room - self._kept.errors

    def full(self) -> bool:
        return self._kept.full()

    def add(self, findings: Iterable[Finding], *, not_shown: int = 0) -> None:
        for finding in findings:
            self._kept.add(finding)
        self._not_shown += not_shown

    def result(self, scope: str) -> Result:
        shown = KeptFindings(self.cap)
        for finding in self.items:
            shown.add(finding)
        return Result(
            scope=scope,
            findings=tuple(sorted(shown.items, key=_sort_key)),
            not_shown=self._kept.dropped + shown.dropped + self._not_shown,
        )


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


# An oversized document is present; its files.too-large finding names it.
def required_document_findings(
    documents: Mapping[str, Candidate], oversized: Collection[str]
) -> Iterator[Finding]:
    for path in REQUIRED_DOCUMENTS:
        candidate = documents.get(path)
        if path not in oversized and (candidate is None or not candidate.content):
            yield Finding(
                rule_id="documents.required",
                path=path,
                summary="Required public document is missing or empty.",
            )


def is_immutable_vendor(candidate: Candidate, vendor_hashes: Mapping[str, str]) -> bool:
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
    immutable_vendor = is_immutable_vendor(candidate, vendor_hashes)
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
    private_values: Sequence[str],
) -> None:
    vendor_hashes = {item.path: item.sha256 for item in policy.immutable_vendor_files}
    privacy = privacy_policy(policy, private_values)
    for candidate in candidates:
        if found.full():
            break
        _candidate_findings(found, candidate, privacy, vendor_hashes)
