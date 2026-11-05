from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path

GIT_CONFIG_PATH = ".git/config"
GIT_HOOKS_PATH = ".git/hooks"


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


class SetupBlockedError(SetupError):
    pass


class SetupFailedError(SetupError):
    pass


class ConfirmationNeededError(SetupError):
    def __init__(self, message: str, root: Path) -> None:
        super().__init__(message)
        self.root = root


class FileAccessError(RuntimeError):
    pass


class RepositoryContentError(RuntimeError):
    pass


class LimitExceededError(RuntimeError):
    pass


class Origin(StrEnum):
    WORKTREE = "worktree"
    INDEX = "index"
    MESSAGE = "message"


class FileState(StrEnum):
    TRACKED = "tracked"
    VISIBLE = "visible"


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
    local_hook: bool = False
    commit: str | None = None
    pushed: bool = False


class KeptFindings:
    def __init__(self, room: int) -> None:
        self.room = max(0, room)
        self.items: list[Finding] = []
        self.errors = 0
        self.dropped = 0

    def full(self) -> bool:
        return self.errors >= self.room

    def add(self, finding: Finding) -> None:
        if finding.severity == Severity.WARNING or self.full():
            if len(self.items) < self.room:
                self.items.append(finding)
            else:
                self.dropped += 1
            return
        if len(self.items) >= self.room:
            latest = max(
                index
                for index, item in enumerate(self.items)
                if item.severity == Severity.WARNING
            )
            del self.items[latest]
            self.dropped += 1
        self.items.append(finding)
        self.errors += 1


def capped(findings: Iterable[Finding], max_findings: int) -> list[Finding]:
    kept = KeptFindings(max_findings)
    if not kept.full():
        for finding in findings:
            kept.add(finding)
            if kept.full():
                break
    return kept.items


@dataclass(frozen=True)
class Result:
    scope: str
    findings: tuple[Finding, ...]
    not_shown: int = 0

    @property
    def passed(self) -> bool:
        return all(finding.severity == Severity.WARNING for finding in self.findings)
