import os
import re
from pathlib import Path

from first_commit.paths import MEBIBYTE, PathError, read_regular_bytes

HOOK_CONFIG = ".pre-commit-config.yaml"
SETUP_HOOK_ID = "first-commit-setup"
SETUP_HOOK_COMMAND = f"pre-commit run {SETUP_HOOK_ID} --hook-stage manual"
DOCTOR_HOOK_ID = "first-commit-doctor"
CHECK_HOOK_ID = "first-commit-check"
# --all-files stops pre-commit from setting unstaged changes aside, so check
# sees the working tree.
CHECK_HOOK_COMMAND = f"pre-commit run {CHECK_HOOK_ID} --hook-stage manual --all-files"
TOOL_SETUP_COMMAND = "first-commit setup"
# Set to 1 on the clone setup hook to trust your own signing key.
TRUST_SELF_VARIABLE = "FIRST_COMMIT_TRUST_SELF"
MAX_HOOK_CONFIG_BYTES = MEBIBYTE


# Hook environments have no PyYAML, so only the block layout setup writes is read.
def declares_hook(root: Path, hook_id: str) -> bool:
    path = root / HOOK_CONFIG
    if not os.path.lexists(path):
        return False
    try:
        raw = read_regular_bytes(path, MAX_HOOK_CONFIG_BYTES)
    except PathError:
        return False
    line = re.compile(
        rb"^[ \t]*-\s*id:\s*[\"']?"
        + re.escape(hook_id.encode())
        + rb"[\"']?\s*(?:#.*)?$",
        re.MULTILINE,
    )
    return line.search(raw) is not None


def declares_setup_hook(root: Path) -> bool:
    return declares_hook(root, SETUP_HOOK_ID)


def setup_command(*, setup_hook: bool) -> str:
    return SETUP_HOOK_COMMAND if setup_hook else TOOL_SETUP_COMMAND
