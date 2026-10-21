from collections.abc import Iterator, Sequence
from pathlib import PurePosixPath

from first_commit.models import EnvironmentFile, FileState, Finding, capped
from first_commit.policy_fields import EnvironmentExceptionEntry

DOTENV_PATHSPECS = (
    ".env",
    ".env.*",
    "*.env",
    "*.env.*",
    ":(glob)**/.env",
    ":(glob)**/.env.*",
    ":(glob)**/*.env",
    ":(glob)**/*.env.*",
)
PUBLIC_BASENAMES = (".env.example", ".env.schema", ".env.template")


def _private_files(
    files: Sequence[EnvironmentFile], exceptions: Sequence[EnvironmentExceptionEntry]
) -> Iterator[Finding]:
    public_paths = {exception.path for exception in exceptions}
    for file in files:
        if (
            PurePosixPath(file.path).name in PUBLIC_BASENAMES
            or file.path in public_paths
            or file.state == FileState.IGNORED
        ):
            continue
        if file.state == FileState.TRACKED:
            rule_id = "environment.tracked-private-file"
            summary = "Private environment file is tracked."
        else:
            rule_id = "environment.not-ignored"
            summary = "Private environment file is not ignored."
        yield Finding(rule_id=rule_id, path=file.path, summary=summary)


def environment_findings(
    files: Sequence[EnvironmentFile],
    exceptions: Sequence[EnvironmentExceptionEntry],
    *,
    max_findings: int,
) -> list[Finding]:
    return capped(_private_files(files, exceptions), max_findings)
