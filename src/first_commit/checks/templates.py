from pathlib import Path

from first_commit.git_settings import effective_git_settings
from first_commit.models import GIT_CONFIG_PATH, Finding
from first_commit.paths import PathError, read_explicit_file_bytes

MAX_TEMPLATE_BYTES = 64 * 1024


def read_template(root: Path, value: str) -> bytes:
    if not value or value.startswith("~") or "\0" in value:
        raise PathError("Template path is invalid.")
    content = read_explicit_file_bytes(root, Path(value), MAX_TEMPLATE_BYTES)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PathError("Template is not UTF-8 text.") from error
    if not text.strip() or "\0" in text:
        raise PathError("Template is empty or contains NUL bytes.")
    return content


def template_findings(root: Path) -> list[Finding]:
    value = effective_git_settings(root, ("commit.template",)).get("commit.template")
    if value is None:
        return [
            Finding(
                rule_id="template.missing",
                path=GIT_CONFIG_PATH,
                summary="Commit template is not configured.",
            )
        ]
    try:
        read_template(root, value)
    except PathError:
        return [
            Finding(
                rule_id="template.unusable",
                path=GIT_CONFIG_PATH,
                summary="Commit template must be a non-empty UTF-8 regular file "
                "within this repository.",
            )
        ]
    return []
