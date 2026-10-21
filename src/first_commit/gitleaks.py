import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from first_commit.git import GitError
from first_commit.gitleaks_ignore import check_ignore_file
from first_commit.gitleaks_ignore_format import IGNORE_PATH
from first_commit.gitleaks_report import (
    ReportEntry,
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
from first_commit.models import Finding, capped
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


@dataclass(frozen=True)
class ScanSpec:
    arguments: Sequence[str]
    trailing: Sequence[str]
    scope_path: str
    summary: str
    timeout: int = SCAN_TIMEOUT_SECONDS
    revisions: tuple[str, ...] | None = None


def _reject_repository_overrides(root: Path) -> None:
    path = root / ".gitleaks.toml"
    if path.is_symlink() or path.exists():
        raise DependencyError("Gitleaks rule configuration is prohibited.")


def _report_findings(
    entries: tuple[ReportEntry, ...], spec: ScanSpec, max_findings: int
) -> tuple[Finding, ...]:
    return tuple(
        capped(
            (
                Finding(
                    rule_id=RULE_ID,
                    path=spec.scope_path if location.path is None else location.path,
                    summary=spec.summary,
                    line=location.line,
                )
                for location in report_locations(entries)
            ),
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


def _reported_entries(
    root: Path,
    scanner: Scanner,
    arguments: Sequence[str],
    options: RunOptions,
    *,
    run_in_report_folder: bool = False,
) -> tuple[ReportEntry, ...]:
    folder = tempfile.mkdtemp(prefix=REPORT_FOLDER_PREFIX)
    try:
        report = Path(folder) / REPORT_NAME
        result = run_scanner(
            [scanner.executable, *_with_report(arguments, report)],
            root,
            scanner.environment,
            options._replace(folder=Path(folder)) if run_in_report_folder else options,
        )
        if result.returncode == 0:
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
        RunOptions(capture_output=False, timeout=spec.timeout),
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
        run_in_report_folder=True,
    )


def scan_history(
    root: Path,
    *,
    max_findings: int,
    executable: str = "gitleaks",
    environment: Mapping[str, str] | None = None,
) -> tuple[Finding, ...]:
    return _scan(
        root,
        Scanner(executable, environment),
        ScanSpec(
            # Gitleaks splits --log-opts on spaces into git log arguments.
            (*HISTORY_ARGUMENTS, "--log-opts=" + " ".join(HISTORY_REVISIONS)),
            (str(root),),
            HISTORY_SCOPE_PATH,
            HISTORY_SUMMARY,
            HISTORY_TIMEOUT_SECONDS,
            HISTORY_REVISIONS,
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
    return _scan(
        root,
        Scanner(executable, environment),
        ScanSpec(
            (*HISTORY_ARGUMENTS, "--log-opts=" + " ".join(revisions)),
            (str(root),),
            HISTORY_SCOPE_PATH,
            HISTORY_SUMMARY,
            revisions=revisions,
        ),
        max_findings,
    )


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
