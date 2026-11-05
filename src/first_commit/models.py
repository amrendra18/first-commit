from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from itertools import islice
from pathlib import Path

GIT_CONFIG_PATH = ".git/config"
GIT_HOOKS_PATH = ".git/hooks"


# FINDING also covers a run that could not do its job, such as a missing scanner.
class ExitCode(IntEnum):
    PASSED = 0
    FINDING = 1
    INPUT = 2
    HELD = 5


# The help text and the ARCHITECTURE.md exit-code sentence read these meanings.
EXIT_CODE_MEANINGS = {
    ExitCode.PASSED: "done",
    ExitCode.FINDING: "a finding or not done (read the error)",
    ExitCode.INPUT: "bad call (unknown verb or flag, invalid or missing input)",
    ExitCode.HELD: "held for a person's yes",
}


class SetupError(ValueError):
    pass


class SetupCancelledError(SetupError):
    pass


class SetupTerminatedError(SetupError):
    pass


# A state outside the call stopped setup, such as a lock another process holds; a
# retry may succeed.
class SetupBlockedError(SetupError):
    pass


# Setup ran, but its result or its undo failed a check.
class SetupFailedError(SetupError):
    pass


# Setup stopped before it wrote anything, because only a person can confirm the
# plan; root is the folder the confirming call names.
class ConfirmationNeededError(SetupError):
    def __init__(self, message: str, root: Path) -> None:
        super().__init__(message)
        self.root = root


class Origin(StrEnum):
    WORKTREE = "worktree"
    INDEX = "index"
    MESSAGE = "message"


class FileState(StrEnum):
    TRACKED = "tracked"
    VISIBLE = "visible"
    IGNORED = "ignored"


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Candidate:
    path: str
    content: bytes
    origin: Origin
    regular_file: bool = True


@dataclass(frozen=True)
class EnvironmentFile:
    path: str
    state: FileState


@dataclass(frozen=True, kw_only=True)
class Finding:
    rule_id: str
    path: str
    summary: str
    severity: Severity = Severity.ERROR
    line: int | None = None
    # The fix line reads this, not the summary: masking may change summary text.
    on_remote: bool = False
    # The fix line reads this too: a repo: local hook declares more keys.
    local_hook: bool = False


# Checks pass a lazy iterable, so a spent budget skips the rest of the check's work.
def capped(findings: Iterable[Finding], max_findings: int) -> list[Finding]:
    return list(islice(findings, max(0, max_findings)))


@dataclass(frozen=True)
class Result:
    scope: str
    findings: tuple[Finding, ...]

    @property
    def passed(self) -> bool:
        return all(finding.severity == Severity.WARNING for finding in self.findings)
