import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from first_commit.git import SHORT_COMMIT, GitError, run_git
from first_commit.gitleaks_ignore import check_ignore_file
from first_commit.gitleaks_ignore_format import IGNORE_PATH
from first_commit.gitleaks_report import (
    ReportEntry,
    ReportLocation,
    report_entries,
    report_locations,
)
from first_commit.gitleaks_scanner import (
    FINDINGS_EXIT,
    HISTORY_TIMEOUT_SECONDS,
    SCAN_TIMEOUT_SECONDS,
    STDIN_ARGUMENTS,
    DependencyError,
    RunOptions,
    Scanner,
    run_scanner,
    validate_scanner,
)
from first_commit.models import Finding, RepositoryContentError, capped
from first_commit.pushed import HISTORY_REVISIONS, PushedScope, push_revisions

RULE_ID = "secrets.gitleaks"
REPORT_NAME = "report.json"
REPORT_FOLDER_PREFIX = "first-commit-scan-"
HISTORY_SCOPE_PATH = ".git"
HISTORY_SUMMARY = "Gitleaks reported a repository-history finding."
STAGED_SCOPE_PATH = "<staged-content>"
STAGED_SUMMARY = "Gitleaks reported a staged-content finding."
HISTORY_ARGUMENTS = (
    "git",
    "--redact",
    "--no-banner",
    f"--exit-code={FINDINGS_EXIT}",
    "--ignore-gitleaks-allow",
    "--gitleaks-ignore-path",
    IGNORE_PATH,
)
STAGED_ARGUMENTS = (
    "git",
    "--pre-commit",
    "--redact",
    "--staged",
    "--verbose",
    f"--exit-code={FINDINGS_EXIT}",
    "--ignore-gitleaks-allow",
    "--gitleaks-ignore-path",
    IGNORE_PATH,
)
REPORT_PLACEHOLDER = "{report}"
NO_TEXTCONV = "--no-textconv"
# Gitleaks 8.30.0 logs each line as "<time> <level> <text>", with color codes.
LOG_COLOR = re.compile(rb"\x1b\[[0-9;]*m")
LOGGED_ERROR = re.compile(rb"^\S+ ERR ", re.MULTILINE)
SCANNED_COMMITS = re.compile(rb"^\S+ INF ([0-9]+) commits scanned\.$", re.MULTILINE)
GITLEAKS_CONFIG_REFUSED = (
    "The repository root holds .gitleaks.toml, a Gitleaks rule file that could "
    "weaken the secret scan, so first-commit refuses to scan.\n"
    "fix: remove .gitleaks.toml (`git rm .gitleaks.toml` when Git tracks it), then "
    "rerun; first-commit scans with the pinned Gitleaks rules only."
)
INCOMPLETE_HISTORY = (
    "Gitleaks could not read the whole history, so the scan is incomplete.\n"
    "fix: fetch the missing objects, or run the check in a full clone "
    "(git clone without --filter)."
)


@dataclass(frozen=True)
class ScanSpec:
    arguments: Sequence[str]
    trailing: Sequence[str]
    scope_path: str
    summary: str
    timeout: int = SCAN_TIMEOUT_SECONDS
    revisions: tuple[str, ...] | None = None


# Gitleaks splits --log-opts on spaces into git log arguments. A textconv driver
# would give Gitleaks its output in place of the committed bytes.
def _log_options(revisions: tuple[str, ...]) -> str:
    return "--log-opts=" + " ".join((NO_TEXTCONV, *revisions))


def _reject_repository_overrides(root: Path) -> None:
    path = root / ".gitleaks.toml"
    if path.is_symlink() or path.exists():
        raise RepositoryContentError(GITLEAKS_CONFIG_REFUSED)


def _finding(location: ReportLocation, spec: ScanSpec) -> Finding:
    path = spec.scope_path if location.path is None else location.path
    if location.commit is None:
        return Finding(
            rule_id=RULE_ID, path=path, summary=spec.summary, line=location.line
        )
    commit = location.commit[:SHORT_COMMIT]
    return Finding(
        rule_id=RULE_ID,
        path=path,
        summary=f"{spec.summary.removesuffix('.')} in commit {commit}.",
        line=location.line,
        commit=commit,
    )


def _report_findings(
    entries: tuple[ReportEntry, ...], spec: ScanSpec, max_findings: int
) -> tuple[Finding, ...]:
    return tuple(
        capped(
            (_finding(location, spec) for location in report_locations(entries)),
            max_findings,
        )
    )


def _with_report(arguments: Sequence[str], report: Path) -> list[str]:
    return [
        item
        for argument in arguments
        for item in (
            ("--report-format=json", f"--report-path={report}")
            if argument == REPORT_PLACEHOLDER
            else (argument,)
        )
    ]


# Gitleaks counts each commit in which it reads a text file with added lines;
# Git lists the same commits with --numstat. A merge shows no diff.
def _text_commits(root: Path, revisions: tuple[str, ...]) -> int:
    raw = run_git(
        root,
        (
            "log",
            "--no-merges",
            NO_TEXTCONV,
            "--numstat",
            "--format=%H",
            *revisions,
            "--",
        ),
    )
    commits = set()
    commit = b""
    for line in raw.split(b"\n"):
        added, tab, _ = line.partition(b"\t")
        if not tab:
            commit = line or commit
        elif added.isdigit() and int(added) > 0:
            commits.add(commit)
    return len(commits)


def _listed_commits(root: Path, revisions: tuple[str, ...]) -> int | None:
    try:
        return _text_commits(root, revisions)
    except GitError:
        return None


# Gitleaks exits 0 when Git fails under it, as in a partial clone.
def _require_whole_history(listed: int | None, log: bytes) -> None:
    text = LOG_COLOR.sub(b"", log)
    if listed is None or LOGGED_ERROR.search(text):
        raise DependencyError(INCOMPLETE_HISTORY)
    scanned = SCANNED_COMMITS.search(text)
    if (0 if scanned is None else int(scanned[1])) < listed:
        raise DependencyError(INCOMPLETE_HISTORY)


def _reported_entries(
    root: Path,
    scanner: Scanner,
    arguments: Sequence[str],
    options: RunOptions,
    revisions: tuple[str, ...] | None = None,
) -> tuple[ReportEntry, ...]:
    listed = None if revisions is None else _listed_commits(root, revisions)
    folder = tempfile.mkdtemp(prefix=REPORT_FOLDER_PREFIX)
    try:
        report = Path(folder) / REPORT_NAME
        result = run_scanner(
            [scanner.executable, *_with_report(arguments, report)],
            root,
            scanner.environment,
            options
            if options.input_bytes is None
            else options._replace(folder=Path(folder)),
        )
        if result.returncode == 0:
            if revisions is not None:
                _require_whole_history(listed, result.stderr)
            return ()
        if result.returncode != FINDINGS_EXIT:
            raise DependencyError("Gitleaks scan failed.")
        return report_entries(root, report)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _validated(root: Path, scanner: Scanner) -> Scanner:
    executable = validate_scanner(root, scanner.executable, scanner.environment)
    return Scanner(executable, scanner.environment)


def _scan(
    root: Path, scanner: Scanner, spec: ScanSpec, max_findings: int
) -> tuple[Finding, ...]:
    _reject_repository_overrides(root)
    check_ignore_file(root, spec.revisions)
    entries = _reported_entries(
        root,
        _validated(root, scanner),
        (*spec.arguments, REPORT_PLACEHOLDER, *spec.trailing),
        RunOptions(capture_output=spec.revisions is not None, timeout=spec.timeout),
        spec.revisions,
    )
    return _report_findings(entries, spec, max_findings)


# The entries carry no path; their lines count from the first line of content.
# Gitleaks stdin reads <working folder>/.gitleaksignore whatever the ignore path
# says, so the scan runs in the private report folder: no repository entry applies.
def scan_stdin(root: Path, scanner: Scanner, content: bytes) -> tuple[ReportEntry, ...]:
    _reject_repository_overrides(root)
    return _reported_entries(
        root,
        _validated(root, scanner),
        (*STDIN_ARGUMENTS, REPORT_PLACEHOLDER),
        RunOptions(capture_output=False, input_bytes=content),
    )


def scan_history(
    root: Path,
    *,
    max_findings: int,
    executable: str = "gitleaks",
    environment: Mapping[str, str] | None = None,
    revisions: tuple[str, ...] = HISTORY_REVISIONS,
) -> tuple[Finding, ...]:
    return _scan(
        root,
        Scanner(executable, environment),
        ScanSpec(
            (*HISTORY_ARGUMENTS, _log_options(revisions)),
            (str(root),),
            HISTORY_SCOPE_PATH,
            HISTORY_SUMMARY,
            HISTORY_TIMEOUT_SECONDS,
            revisions,
        ),
        max_findings,
    )


def scan_pushed(
    root: Path,
    scope: PushedScope,
    *,
    max_findings: int,
    executable: str = "gitleaks",
    environment: Mapping[str, str] | None = None,
) -> tuple[Finding, ...]:
    if not scope.valid:
        raise DependencyError("Gitleaks push scope is invalid.")
    try:
        revisions = push_revisions(root, scope)
    except GitError as error:
        raise DependencyError(
            "Git cannot list the remote's commits for the push scan."
        ) from error
    findings = _scan(
        root,
        Scanner(executable, environment),
        ScanSpec(
            (*HISTORY_ARGUMENTS, _log_options(revisions)),
            (str(root),),
            HISTORY_SCOPE_PATH,
            HISTORY_SUMMARY,
            HISTORY_TIMEOUT_SECONDS,
            revisions,
        ),
        max_findings,
    )
    return tuple(replace(finding, pushed=True) for finding in findings)


def scan_staged(
    root: Path,
    *,
    max_findings: int,
    executable: str = "gitleaks",
    environment: Mapping[str, str] | None = None,
) -> tuple[Finding, ...]:
    return _scan(
        root,
        Scanner(executable, environment),
        ScanSpec(STAGED_ARGUMENTS, (), STAGED_SCOPE_PATH, STAGED_SUMMARY),
        max_findings,
    )
