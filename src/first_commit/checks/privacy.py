import hashlib
import re
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from itertools import chain
from typing import AnyStr

from first_commit.contributor import email_spans
from first_commit.models import Candidate, Finding, Origin, capped
from first_commit.policy import Policy
from first_commit.policy_fields import (
    DetectorExceptionEntry,
    ForbiddenPath,
    LiteralExceptionEntry,
)

PATTERNS: tuple[tuple[str, str, str], ...] = (
    (
        "privacy.private-key",
        r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----",
        "Detected a private-key block.",
    ),
    (
        "privacy.github-token",
        r"gh[pousr]_[A-Za-z0-9]{20,}",
        "Detected a GitHub credential shape.",
    ),
    (
        "privacy.aws-access-key",
        r"AKIA[0-9A-Z]{16}",
        "Detected an AWS access-key shape.",
    ),
    (
        "privacy.ssh-fingerprint",
        r"SHA256:[A-Za-z0-9+/]{20,}={0,2}",
        "Detected an SSH fingerprint.",
    ),
    (
        "privacy.user-home-path",
        r"(?:/Users|/home)/[A-Za-z0-9._-]+",
        "Detected a literal user-home path.",
    ),
)
EXAMPLE_DOMAINS = {"example.com", "example.net", "example.org"}
RESERVED_TEST_SUFFIXES = (".invalid", ".test")
# Protocol namespaces, not mail domains. SSH names its algorithms, ciphers, and
# certificate formats "<name>@openssh.com" or "<name>@libssh.org", which match
# the address shape without being anyone's address.
PROTOCOL_DOMAINS = {"openssh.com", "libssh.org"}
GITHUB_OWNER_PREFIX = re.compile(r"(?:https?://|ssh://git@|git@)github\.com[/:]$")
GITHUB_SSH_USER = "git" + "@" + "github.com"
UTF16_MARKS = (b"\xff\xfe", b"\xfe\xff")
# Every private key of one type starts with the same line, so its exceptions hash
# the whole file.
FILE_DIGEST_RULES = frozenset({"privacy.private-key"})
# Each call yields the line bytes again, one at a time: a list of a 10 MiB file's
# lines took up to 300 MiB.
RawLines = Callable[[], Iterator[bytes]]


@dataclass(frozen=True)
class PrivacyPolicy:
    content_emails: Sequence[str] = ()
    private_values: Sequence[str] = ()
    literal_exceptions: Sequence[LiteralExceptionEntry] = ()
    detector_exceptions: Sequence[DetectorExceptionEntry] = ()
    public_github_owner_urls: bool = False


def privacy_policy(policy: Policy, private_values: Sequence[str]) -> PrivacyPolicy:
    return PrivacyPolicy(
        content_emails=(*policy.contributor_emails, *policy.public_emails),
        private_values=private_values,
        literal_exceptions=policy.literal_exceptions,
        detector_exceptions=policy.detector_exceptions,
        public_github_owner_urls=policy.public_github_owner_urls,
    )


def _forbidden(
    paths: Sequence[str], policies: Sequence[ForbiddenPath]
) -> Iterator[Finding]:
    for path in sorted(set(paths)):
        policy = forbidden_path_policy(path, policies)
        if policy is not None:
            yield Finding(
                rule_id="privacy.forbidden-path",
                path=path,
                summary=f"Project policy forbids this path: {policy.reason}",
            )


def forbidden_path_findings(
    paths: Sequence[str], policies: Sequence[ForbiddenPath], *, max_findings: int
) -> list[Finding]:
    return capped(_forbidden(paths, policies), max_findings)


def forbidden_path_policy(
    path: str, policies: Sequence[ForbiddenPath]
) -> ForbiddenPath | None:
    for policy in policies:
        if (
            (policy.match == "exact" and path == policy.value)
            or (policy.match == "prefix" and path.startswith(policy.value))
            or (policy.match == "suffix" and path.endswith(policy.value))
        ):
            return policy
    return None


def _line(text: str, start: int) -> int:
    return text.count("\n", 0, start) + 1


def _reserved_example_address(address: str) -> bool:
    _, _, domain = address.lower().rpartition("@")
    return (
        domain in EXAMPLE_DOMAINS
        or domain in PROTOCOL_DOMAINS
        or domain.endswith(RESERVED_TEST_SUFFIXES)
    )


# Each exception approves one copy of its line: the first matching lines, in order.
def _approved_lines(
    raw_lines: RawLines, approved_copies: Counter[tuple[str, str]]
) -> dict[str, set[int]]:
    approved: dict[str, set[int]] = {}
    if not approved_copies:
        return approved
    remaining = Counter(approved_copies)
    wanted = {digest for _, digest in approved_copies}
    for number, raw in enumerate(raw_lines(), start=1):
        digest = hashlib.sha256(raw).hexdigest()
        if digest not in wanted:
            continue
        for key, key_digest in approved_copies:
            if key_digest == digest and remaining[key, key_digest] > 0:
                remaining[key, key_digest] -= 1
                approved.setdefault(key, set()).add(number)
    return approved


def _github_owner(normalized: str, start: int, value: str) -> bool:
    end = start + len(value)
    if normalized[end : end + 1] != "/":
        return False
    return (
        GITHUB_OWNER_PREFIX.search(normalized[max(0, start - 32) : start]) is not None
    )


def _pattern_findings(
    path: str, text: str, approved: dict[str, set[int]], *, vendor: bool
) -> Iterator[Finding]:
    for rule_id, expression, summary in PATTERNS:
        if vendor and rule_id == "privacy.user-home-path":
            continue
        for match in re.finditer(expression, text):
            line = _line(text, match.start())
            if line in approved.get(rule_id, ()):
                continue
            yield Finding(rule_id=rule_id, path=path, line=line, summary=summary)
            break


# The SSH transport user in `ssh://git@github.com/owner/repo` and in the scp-like
# `git@github.com:owner/repo`; the latter is never inside a URL.
def _github_ssh_user(text: str, start: int, end: int) -> bool:
    if text[start:end] != GITHUB_SSH_USER:
        return False
    if text[max(0, start - 6) : start] == "ssh://":
        return text[end : end + 1] == "/"
    return text[end : end + 1] == ":" and text[start - 1 : start] != "/"


def _email_findings(
    path: str, text: str, approved: dict[str, set[int]], content_emails: Sequence[str]
) -> Iterator[Finding]:
    allowed = set(content_emails)
    exempt_lines = approved.get("privacy.unapproved-email", set())
    for start, end in email_spans(text):
        address = text[start:end]
        if (
            address in allowed
            or _reserved_example_address(address)
            or _github_ssh_user(text, start, end)
        ):
            continue
        line = _line(text, start)
        if line in exempt_lines:
            continue
        yield Finding(
            rule_id="privacy.unapproved-email",
            path=path,
            line=line,
            summary="Detected an unapproved email address.",
        )


def _literal_exempt(
    normalized: str, start: int, value: str, approved: set[int], *, owner_urls: bool
) -> bool:
    if owner_urls and _github_owner(normalized, start, value):
        return True
    return _line(normalized, start) in approved


def _literal_findings(
    candidate: Candidate,
    text: str,
    raw_lines: RawLines,
    policy: PrivacyPolicy,
    *,
    is_file_content: bool,
) -> Iterator[Finding]:
    normalized = unicodedata.normalize("NFC", text).casefold()
    approved = _approved_lines(
        raw_lines,
        Counter(
            ("literal", item.sha256)
            for item in policy.literal_exceptions
            if is_file_content and item.path == candidate.path
        ),
    ).get("literal", set())
    owner_urls = policy.public_github_owner_urls and is_file_content
    for value in policy.private_values:
        start = normalized.find(value)
        while start >= 0 and _literal_exempt(
            normalized, start, value, approved, owner_urls=owner_urls
        ):
            start = normalized.find(value, start + 1)
        if start >= 0:
            yield Finding(
                rule_id="privacy.private-literal",
                path=candidate.path,
                line=_line(normalized, start),
                summary="Detected a configured private literal.",
            )


def _split(value: AnyStr, separator: AnyStr) -> Iterator[AnyStr]:
    start = 0
    end = value.find(separator)
    while end >= 0:
        yield value[start:end]
        start = end + 1
        end = value.find(separator, start)
    yield value[start:]


# Binary and non-UTF-8 content is read too: a NUL or bad byte must not hide a finding.
def _views(content: bytes) -> Iterator[tuple[str, RawLines]]:
    yield content.decode("utf-8", errors="replace"), lambda: _split(content, b"\n")
    if content.startswith(UTF16_MARKS):
        text = content.decode("utf-16", errors="replace")
        yield text, lambda: (line.encode("utf-8") for line in _split(text, "\n"))


def _file_digest_lines(
    candidate: Candidate, policy: PrivacyPolicy, *, is_file_content: bool
) -> dict[str, set[int]]:
    approved: dict[str, set[int]] = {}
    digest = hashlib.sha256(candidate.content).hexdigest()
    for item in policy.detector_exceptions:
        if (
            is_file_content
            and item.rule in FILE_DIGEST_RULES
            and item.path == candidate.path
            and item.sha256 == digest
        ):
            approved.setdefault(item.rule, set()).add(item.line)
    return approved


def _view_findings(
    candidate: Candidate,
    view: tuple[str, RawLines],
    policy: PrivacyPolicy,
    *,
    immutable_vendor: bool,
) -> Iterator[Finding]:
    text, raw_lines = view
    is_file_content = candidate.origin != Origin.MESSAGE
    detector_lines = _approved_lines(
        raw_lines,
        Counter(
            (item.rule, item.sha256)
            for item in policy.detector_exceptions
            if is_file_content
            and item.path == candidate.path
            and item.rule not in FILE_DIGEST_RULES
        ),
    )
    detector_lines.update(
        _file_digest_lines(candidate, policy, is_file_content=is_file_content)
    )
    yield from _pattern_findings(
        candidate.path, text, detector_lines, vendor=immutable_vendor
    )
    if not immutable_vendor:
        yield from _email_findings(
            candidate.path, text, detector_lines, policy.content_emails
        )
    yield from _literal_findings(
        candidate, text, raw_lines, policy, is_file_content=is_file_content
    )


def _new_view_findings(
    candidate: Candidate, policy: PrivacyPolicy, *, immutable_vendor: bool
) -> Iterator[Finding]:
    earlier: set[Finding] = set()
    for view in _views(candidate.content):
        current = []
        for item in _view_findings(
            candidate, view, policy, immutable_vendor=immutable_vendor
        ):
            if item not in earlier:
                current.append(item)
                yield item
        earlier.update(current)
        # Frees this view's text before the next view is decoded.
        del view


# A message's path is a label, not a name that Git records.
def _path_findings(candidate: Candidate, policy: PrivacyPolicy) -> Iterator[Finding]:
    if candidate.origin == Origin.MESSAGE:
        return
    path = unicodedata.normalize("NFC", candidate.path).casefold()
    if any(value in path for value in policy.private_values):
        yield Finding(
            rule_id="privacy.private-path",
            path=candidate.path,
            summary="The file path contains a configured private literal.",
        )


def privacy_findings(
    candidate: Candidate,
    policy: PrivacyPolicy,
    *,
    max_findings: int,
    immutable_vendor: bool = False,
) -> list[Finding]:
    return capped(
        chain(
            _path_findings(candidate, policy),
            _new_view_findings(candidate, policy, immutable_vendor=immutable_vendor),
        ),
        max_findings,
    )
