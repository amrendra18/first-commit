import bisect
import os
import re
from collections.abc import Collection, Iterable, Iterator, Sequence
from pathlib import Path
from typing import NamedTuple

from first_commit.candidates import staged_candidates
from first_commit.git import run_git
from first_commit.gitleaks import RULE_ID, STAGED_SCOPE_PATH, STAGED_SUMMARY, scan_stdin
from first_commit.gitleaks_ignore import check_ignore_file
from first_commit.gitleaks_report import ReportEntry
from first_commit.gitleaks_scanner import Scanner
from first_commit.models import Candidate, Finding, Origin, capped
from first_commit.paths import MEBIBYTE

# The [allowlist] paths of the default configuration built into Gitleaks 8.30.0.
# Gitleaks skips every file whose path matches one. A test compares this list with
# the pinned binary.
DEFAULT_ALLOWLIST_PATHS = (
    r"gitleaks\.toml",
    r"(?i)\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
    r"(?i)\.(?:eot|[ot]tf|woff2?)$",
    r"(?i)\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
    r"go\.(?:mod|sum|work(?:\.sum)?)$",
    r"(?:^|/)vendor/modules\.txt$",
    (
        r"(?:^|/)vendor/(?:github\.com|golang\.org/x|google\.golang\.org|gopkg\.in"
        r"|istio\.io|k8s\.io|sigs\.k8s\.io)(?:/.*)?$"
    ),
    r"(?:^|/)gradlew(?:\.bat)?$",
    r"(?:^|/)gradle\.lockfile$",
    r"(?:^|/)mvnw(?:\.cmd)?$",
    r"(?:^|/)\.mvn/wrapper/MavenWrapperDownloader\.java$",
    r"(?:^|/)node_modules(?:/.*)?$",
    (
        r"(?:^|/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json"
        r"|pnpm-lock\.yaml|yarn\.lock)$"
    ),
    r"(?:^|/)bower_components(?:/.*)?$",
    (
        r"(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)"
        r"[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$"
    ),
    r"(?:^|/)javascript\.json$",
    r"(?:^|/)(?:Pipfile|poetry)\.lock$",
    r"(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$",
    (
        r"(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\.\d{1,2})+"
        r"|python/[23](?:\.\d{1,2})+/lib(?:64)?)(?:/.*)?$"
    ),
    r"(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:/.+)?$",
    r"(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$",
    r"\.gem$",
    r"verification-metadata\.xml",
    r"Database.refactorlog",
    r"(?:^|/)\.git$",
)
ALLOWLIST = tuple(re.compile(pattern) for pattern in DEFAULT_ALLOWLIST_PATHS)
# `git diff --numstat` prints this for a file it shows as binary.
BINARY_NUMSTAT = b"-\t-\t"
# The bytes one `gitleaks stdin` process reads; one file over this gets its own.
BATCH_BYTES = 32 * MEBIBYTE
# `gitleaks stdin` guesses the file type of each read until a read holds a newline,
# with h2non/filetype 1.1.3. A file type such as PDF, ZIP, ELF, tar, or ISO 9660
# makes it scan nothing and exit 0. That check reads bytes up to offset 32773 (the
# ISO 9660 signature) of a read. Each batch starts with this prefix: its first
# newline is at byte 12, so each checked read starts by byte 12, and the check
# reads only prefix bytes. So no blob decides the type.
TYPE_CHECK_BYTES = 32774
BATCH_PREFIX = b"first-commit\n" + b"#" * TYPE_CHECK_BYTES + b"\n"
MESSAGE_PATH = "<commit-message>"
MESSAGE_SUMMARY = "Gitleaks reported a commit-message finding."


class _Batch(NamedTuple):
    content: bytes
    starts: tuple[int, ...]
    paths: tuple[str, ...]


# Hidden: the staged bytes of these paths are never read by `gitleaks git --staged`.
def hidden_staged_paths(root: Path, paths: Sequence[str]) -> tuple[str, ...]:
    raw = run_git(
        root,
        (
            "diff",
            "--cached",
            "--numstat",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--diff-filter=ACMRT",
        ),
    )
    binary = {
        os.fsdecode(entry.removeprefix(BINARY_NUMSTAT))
        for entry in raw.split(b"\0")
        if entry.startswith(BINARY_NUMSTAT)
    }
    return tuple(
        path
        for path in paths
        if path in binary or any(pattern.search(path) for pattern in ALLOWLIST)
    )


def _batches(candidates: Iterable[Candidate]) -> Iterator[_Batch]:
    first_line = 1 + BATCH_PREFIX.count(b"\n")
    parts: list[bytes] = [BATCH_PREFIX]
    starts: list[int] = []
    paths: list[str] = []
    size, line = len(BATCH_PREFIX), first_line
    for candidate in candidates:
        content = candidate.content
        if not content:
            continue
        if not content.endswith(b"\n"):
            content += b"\n"
        if paths and size + len(content) > BATCH_BYTES:
            yield _Batch(b"".join(parts), tuple(starts), tuple(paths))
            parts, starts, paths = [BATCH_PREFIX], [], []
            size, line = len(BATCH_PREFIX), first_line
        parts.append(content)
        starts.append(line)
        paths.append(candidate.path)
        size += len(content)
        line += content.count(b"\n")
    if paths:
        yield _Batch(b"".join(parts), tuple(starts), tuple(paths))


def _blob_line(entry: ReportEntry, batch: _Batch) -> tuple[str, int] | None:
    if entry.line is None or entry.line < batch.starts[0]:
        return None
    index = bisect.bisect_right(batch.starts, entry.line) - 1
    return batch.paths[index], entry.line - batch.starts[index] + 1


# An entry with no usable line, or on a prefix line, counts for all staged content.
def _finding(
    entry: ReportEntry, batch: _Batch, ignored: Collection[tuple[str, str, int]]
) -> Finding | None:
    location = _blob_line(entry, batch)
    if location is None:
        return Finding(rule_id=RULE_ID, path=STAGED_SCOPE_PATH, summary=STAGED_SUMMARY)
    path, line = location
    if entry.rule is not None and (path, entry.rule, line) in ignored:
        return None
    return Finding(rule_id=RULE_ID, path=path, summary=STAGED_SUMMARY, line=line)


# A blob over the byte limit is not read: the staged check reports it as too large.
def scan_hidden_staged(
    root: Path,
    paths: Sequence[str],
    limits: tuple[int, int],
    *,
    max_findings: int,
    scanner: Scanner | None = None,
) -> tuple[Finding, ...]:
    if not paths or max_findings <= 0:
        return ()
    hidden = hidden_staged_paths(root, paths)
    if not hidden:
        return ()
    ignored = {
        (entry.path, entry.rule, entry.line)
        for entry in check_ignore_file(root)
        if entry.commit is None
    }
    scanner = scanner or Scanner("gitleaks", None)
    max_files, max_bytes = limits
    findings: set[Finding] = set()
    for batch in _batches(staged_candidates(root, max_files, max_bytes, hidden)):
        for entry in scan_stdin(root, scanner, batch.content):
            finding = _finding(entry, batch, ignored)
            if finding is not None:
                findings.add(finding)
        if len(findings) >= max_findings:
            break
    ordered = sorted(findings, key=lambda item: (item.path, item.line or 0))
    return tuple(capped(ordered, max_findings))


def message_locations(
    root: Path, messages: Iterable[Candidate], scanner: Scanner | None = None
) -> Iterator[tuple[str | None, int | None]]:
    scanner = scanner or Scanner("gitleaks", None)
    for batch in _batches(messages):
        found: set[tuple[str | None, int | None]] = {
            _blob_line(entry, batch) or (None, None)
            for entry in scan_stdin(root, scanner, batch.content)
        }
        yield from sorted(found, key=lambda item: (item[0] or "", item[1] or 0))


def scan_message(
    root: Path,
    content: bytes,
    *,
    max_findings: int,
    scanner: Scanner | None = None,
) -> tuple[Finding, ...]:
    if max_findings <= 0:
        return ()
    message = Candidate(MESSAGE_PATH, content, Origin.MESSAGE)
    lines = {line for _, line in message_locations(root, (message,), scanner)}
    return tuple(
        Finding(rule_id=RULE_ID, path=MESSAGE_PATH, summary=MESSAGE_SUMMARY, line=line)
        for line in sorted(lines, key=lambda line: line or 0)[:max_findings]
    )
