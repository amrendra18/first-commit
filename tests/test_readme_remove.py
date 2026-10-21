import tempfile
from pathlib import Path

from first_commit.setup import SetupRequest, setup_repository
from tests.setup_support import REVISION, SetupFixture
from tests.support import run_git

README = Path(__file__).resolve().parents[1] / "README.md"


def _local_keys(root: Path) -> set[str]:
    listed = run_git(root, "config", "--local", "--name-only", "--list")
    return set(listed.stdout.decode("utf-8").split())


def _remove_loop_keys() -> set[str]:
    section = README.read_text("utf-8").split("\n## Remove\n", 1)[1]
    loop = section.split("for key in ", 1)[1].split("; do", 1)[0]
    return {key.lower() for key in loop.split() if key != "\\"}


class ReadmeRemoveTest(SetupFixture):
    def test_remove_loop_names_every_key_setup_writes(self) -> None:
        with tempfile.TemporaryDirectory() as plain:
            run_git(Path(plain), "init", "-q")
            initial = _local_keys(Path(plain))
        self.local_hooks()
        setup_repository(
            self.root,
            SetupRequest(revision=REVISION, trust_self=True, confirmed=True),
            contributor=self.person,
        )
        self.assertEqual(_local_keys(self.root) - initial, _remove_loop_keys())
