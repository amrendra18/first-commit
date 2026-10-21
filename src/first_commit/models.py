from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from itertools import islice

GIT_CONFIG_PATH = ".git/config"
GIT_HOOKS_PATH = ".git/hooks"


class ExitCode(IntEnum):
    PASSED = 0
    FINDING = 1
    INPUT = 2
    DEPENDENCY = 3
    ACCESS = 4


# The help text and the ARCHITECTURE.md exit-code sentence read these meanings.
EXIT_CODE_MEANINGS = {
    ExitCode.PASSED: "pass",
    ExitCode.FINDING: "finding",
    ExitCode.INPUT: (
        "configuration or input (invalid arguments, identity input, a cancelled setup)"
    ),
    ExitCode.DEPENDENCY: "dependency",
    ExitCode.ACCESS: "Git or file access",
}


class SetupError(ValueError):
    pass


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
