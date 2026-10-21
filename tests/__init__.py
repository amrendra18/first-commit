import atexit
import os
import shutil
import tempfile
from pathlib import Path

from first_commit.git import (
    COMMAND_LINE_CONFIG,
    COMMAND_LINE_CONFIG_PREFIXES,
    UNTRUSTED_GIT_ENVIRONMENT,
)
from tests.gitleaks_support import stop_tests_at_missing_scanner

# Git exports GIT_DIR and other variables that choose the repository to its hooks,
# and the pre-push hook runs these tests; fixture Git commands must use only their
# scratch repositories.
for _name in tuple(os.environ):
    if (
        _name in UNTRUSTED_GIT_ENVIRONMENT
        or _name in COMMAND_LINE_CONFIG
        or _name.startswith(COMMAND_LINE_CONFIG_PREFIXES)
    ):
        del os.environ[_name]
# pre-commit also exports the push range and remote to its hooks; a test that runs
# `hook pre-push` without its own range would read the real push's range. Its
# cache folder setting is kept.
for _name in tuple(os.environ):
    if _name.startswith("PRE_COMMIT") and _name != "PRE_COMMIT_HOME":
        del os.environ[_name]

# Tests never read or write the real per-machine identity file, and fixture Git
# commands never read the developer's global or system Git configuration.
# Product Git calls drop GIT_CONFIG_* on purpose, so they still read the system
# Git configuration (for example /etc/gitconfig); the scratch HOME below
# isolates only their global configuration. The one exception is commit_ident
# (src/first_commit/git.py): it keeps GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM, and
# GIT_CONFIG_NOSYSTEM, so it reads the scratch files set here.
_SCRATCH = tempfile.mkdtemp(prefix="first-commit tests ")
atexit.register(shutil.rmtree, _SCRATCH, ignore_errors=True)
os.environ["FIRST_COMMIT_IDENTITY_FILE"] = str(Path(_SCRATCH) / "identity.json")
_GLOBAL_GIT_CONFIG = Path(_SCRATCH) / "empty-global-gitconfig"
_GLOBAL_GIT_CONFIG.write_bytes(b"")
os.environ["GIT_CONFIG_GLOBAL"] = str(_GLOBAL_GIT_CONFIG)
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
# Product Git calls also read ~/.gitconfig, so HOME is a scratch folder too.
os.environ["HOME"] = str(Path(_SCRATCH) / "home")
os.environ.pop("XDG_CONFIG_HOME", None)
Path(os.environ["HOME"]).mkdir()
for _name in (
    "FIRST_COMMIT_AUTHOR_NAME",
    "FIRST_COMMIT_AUTHOR_EMAIL",
    "FIRST_COMMIT_SIGNING_KEY",
):
    os.environ.pop(_name, None)

# Without Gitleaks on PATH, each test that reaches the scanner fails with the
# install step, or skips when FIRST_COMMIT_TEST_ALLOW_NO_GITLEAKS=1.
stop_tests_at_missing_scanner()
