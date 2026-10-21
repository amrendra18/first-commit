import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.checks.identity import ALLOWED_SIGNERS_PATH
from first_commit.contributor import Contributor
from first_commit.setup_files import create_local_file
from tests.support import run_git

REVISION = "1" * 40
# Split so the fixture header is not read as a real private-key block.
PRIVATE_KEY_HEADER = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"


# HOME is the test suite's scratch folder (tests/__init__.py).
def home_public_key() -> Path:
    path = Path("~/.ssh/id_ed25519.pub").expanduser()
    path.parent.mkdir(mode=0o700, exist_ok=True)
    if not path.exists():
        path.write_text(synthetic_key() + " test\n", encoding="ascii")
    return path


def create_allowed_signers(root: Path, content: bytes) -> Path:
    return create_local_file(root, ALLOWED_SIGNERS_PATH, content, "trust")


def synthetic_key(key_type: str = "ssh-ed25519", data: bytes = b"\x2a" * 32) -> str:
    blob = b"".join(
        (
            len(key_type).to_bytes(4, "big"),
            key_type.encode("ascii"),
            len(data).to_bytes(4, "big"),
            data,
        )
    )
    return key_type + " " + base64.b64encode(blob).decode("ascii")


class SetupFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="first-commit setup ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        home_public_key()
        self.person = Contributor(
            "Example Contributor", "public@" + "example.net", "~/.ssh/id_ed25519.pub"
        )
        self.enterContext(patch("first_commit.setup_plan.validate_scanner"))
        self.enterContext(
            patch(
                "first_commit.setup_apply.install_scanner",
                side_effect=self.install_scanner,
            )
        )
        self.enterContext(
            patch.dict(os.environ, {"PRE_COMMIT_HOME": str(self.root / "cache")})
        )

    def install_scanner(self, root: Path) -> bool:
        target = root / ".local/bin/gitleaks"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"synthetic scanner")
        target.chmod(0o700)
        return True

    def local_hooks(self) -> None:
        hooks = []
        for name, stage, scope in (
            ("staged", "pre-commit", "pre-commit"),
            ("message", "commit-msg", "commit-msg"),
            ("push", "pre-push", "pre-push"),
        ):
            hooks.append(
                {
                    "id": "first-commit-" + name,
                    "name": name,
                    "entry": "first-commit hook " + scope,
                    "language": "system",
                    "stages": [stage],
                    "always_run": True,
                    "pass_filenames": name == "message",
                }
            )
        (self.root / ".pre-commit-config.yaml").write_text(
            json.dumps({"repos": [{"repo": "local", "hooks": hooks}]}) + "\n",
            encoding="utf-8",
        )

    def initialized_with_hooks(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()

    def files(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(self.root).parts
        }
