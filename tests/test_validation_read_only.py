import hashlib
import io
import os
import socket
import stat
import subprocess
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stderr, redirect_stdout, suppress
from pathlib import Path
from unittest.mock import patch

from first_commit import cli, git, validation
from tests.gitleaks_support import commit_fixture, needs_real_scanner
from tests.support import commit_message, initialize_repository, run_git

MESSAGE_FILE = ".git/COMMIT_EDITMSG"
COMMANDS = (
    ("check",),
    ("doctor",),
    ("hook", "pre-commit"),
    ("hook", "pre-push"),
    ("hook", "commit-msg", MESSAGE_FILE),
)


def tree_digest(root: Path) -> dict[str, str]:
    digests = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            content = str(path.readlink()).encode()
        elif stat.S_ISREG(mode):
            content = path.read_bytes()
        else:
            content = b""
        digest = hashlib.sha256(content).hexdigest()
        digests[path.relative_to(root).as_posix()] = f"{oct(mode)} {digest}"
    return digests


NETWORK_GIT = frozenset({"clone", "fetch", "ls-remote", "pull", "push"})
GIT_OPTIONS_WITH_VALUE = frozenset({"-C", "-c"})


def offline(*_arguments: object, **_keywords: object) -> None:
    raise AssertionError("validation opened a network connection")


def git_subcommand(arguments: object) -> str | None:
    if not isinstance(arguments, (list, tuple)):
        return None
    parts = [str(item) for item in arguments]
    if not parts or Path(parts[0]).name != "git":
        return None
    index = 1
    while index < len(parts):
        if parts[index] in GIT_OPTIONS_WITH_VALUE:
            index += 2
        elif parts[index].startswith("-"):
            index += 1
        else:
            return parts[index]
    return None


class ReadOnlyOfflineTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        (self.root / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
        (self.root / "README.md").write_text("# Project\n", "utf-8")
        commit_fixture(self.root, ".repo-policy.json", "README.md")
        (self.root / "notes.txt").write_text("staged change\n", "utf-8")
        run_git(self.root, "add", "notes.txt")
        (self.root / "README.md").write_text("# Project\n\nUnstaged.\n", "utf-8")
        (self.root / MESSAGE_FILE).write_text(
            commit_message("feat: add notes"), "utf-8"
        )
        head = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        self.enterContext(patch.dict(os.environ, {"PRE_COMMIT_TO_REF": head}))
        self.enterContext(patch.object(urllib.request, "urlopen", offline))
        self.enterContext(patch.object(socket, "create_connection", offline))
        self.network_git: list[str] = []
        started = self.network_git

        class OfflinePopen(subprocess.Popen[bytes]):
            def __init__(self, args, *rest, **named):
                command = git_subcommand(args)
                if command in NETWORK_GIT or (command or "").startswith("remote-"):
                    started.append(str(command))
                    raise AssertionError(f"validation started git {command}")
                super().__init__(args, *rest, **named)

        self.enterContext(patch.object(subprocess, "Popen", OfflinePopen))

    def run_command(self, arguments: tuple[str, ...]) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return cli.main((*arguments, "--root", str(self.root)))

    def changed_paths(self, arguments: tuple[str, ...]) -> list[str]:
        before = tree_digest(self.root)
        self.run_command(arguments)
        after = tree_digest(self.root)
        return sorted(
            name
            for name in before.keys() | after.keys()
            if before.get(name) != after.get(name)
        )

    @needs_real_scanner
    def test_each_validation_command_changes_no_file(self) -> None:
        for arguments in COMMANDS:
            with self.subTest(command=" ".join(arguments)):
                self.assertEqual([], self.changed_paths(arguments))
                self.assertEqual([], self.network_git)

    @needs_real_scanner
    def test_the_comparison_sees_a_write_planted_in_doctor(self) -> None:
        checked = validation.doctor

        def writing_doctor(root, policy):
            (root / ".git/planted").write_text("written\n", "utf-8")
            return checked(root, policy)

        with patch.object(validation, "doctor", writing_doctor):
            self.assertEqual([".git/planted"], self.changed_paths(("doctor",)))

    @needs_real_scanner
    def test_the_guard_sees_a_network_git_command_planted_in_doctor(self) -> None:
        checked = validation.doctor

        def listing_doctor(root, policy):
            git.run_git(root, ("ls-remote", "--heads", "."))
            return checked(root, policy)

        with (
            patch.object(validation, "doctor", listing_doctor),
            suppress(AssertionError),
        ):
            self.run_command(("doctor",))
        self.assertEqual(["ls-remote"], self.network_git)


if __name__ == "__main__":
    unittest.main()
