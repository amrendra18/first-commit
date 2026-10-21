import subprocess
import unittest

from first_commit.gitleaks_blobs import MESSAGE_PATH
from first_commit.history_messages import TAG_MESSAGE_PATH
from first_commit.models import Severity
from first_commit.policy import PRIVATE_VALUES_PATH, parse_policy
from first_commit.private_values import PRIVATE_VALUE_MASK
from first_commit.validation import history
from tests.gitleaks_support import (
    SLACK_LINE,
    history_cli,
    needs_real_scanner,
    pushed_base_commit,
)
from tests.support import TemporaryRootTest, commit_message, run_git

HOME_LINE = "- Built in /Users/" + "someone/work.\n"
ON_THE_REMOTE = (
    " This text is already on a remote: revoke a secret with its provider; "
    "rewording it needs a history rewrite."
)
PUSHED_FIX = (
    "  fix: Revoke a secret, token, or key with its provider. Rewording a pushed "
    "message needs a history rewrite and a force push; a home path, email, "
    "fingerprint, or private value needs nothing else."
)
REMOTE_URL = "https://example.invalid/project.git"


class RemoteMessageTest(TemporaryRootTest):
    @needs_real_scanner
    def setUp(self) -> None:
        super().setUp()
        self.base = pushed_base_commit(self.root)
        run_git(self.root, "update-ref", "-d", "refs/remotes/origin/main")
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        path = self.root / ".git/test-message"
        path.write_text(commit_message("feat: add change") + HOME_LINE, "utf-8")
        (self.root / "change.txt").write_text("change\n", encoding="utf-8")
        run_git(self.root, "add", "--", "change.txt")
        run_git(self.root, "commit", "-q", "--no-verify", "-F", str(path))
        self.commit = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        line = commit_message("").count("\n") + 1
        self.finding = (
            f'privacy.user-home-path "{MESSAGE_PATH}":{line}: Commit '
            f"{self.commit[:12]}: Detected a literal user-home path."
        )

    def remote(self, name: str, target: str) -> None:
        run_git(self.root, "remote", "add", name, REMOTE_URL)
        run_git(self.root, "update-ref", f"refs/remotes/{name}/main", target)

    def check(self) -> tuple[int, str]:
        return history_cli(self.root, ("check",), {})

    def push(self, to_ref: str) -> tuple[int, str]:
        environment = {"PRE_COMMIT_TO_REF": to_ref, "PRE_COMMIT_REMOTE_NAME": "origin"}
        return history_cli(self.root, ("hook", "pre-push"), environment)

    def git_bytes(self, *arguments: bytes) -> None:
        subprocess.run([b"git", b"-C", bytes(self.root), *arguments], check=True)

    def test_a_nested_remote_with_any_name_is_not_a_tip_of_its_parent(self) -> None:
        self.remote("origin", self.base)
        token = self.root / "cfg.txt"
        token.write_text(SLACK_LINE, encoding="utf-8")
        run_git(self.root, "add", "--", "cfg.txt")
        run_git(self.root, "commit", "-q", "--no-verify", "-m", "feat: add cfg")
        head = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        nested = "origin/café".encode()
        self.git_bytes(b"config", b"remote." + nested + b".url", REMOTE_URL.encode())
        self.git_bytes(
            b"update-ref", b"refs/remotes/" + nested + b"/main", head.encode()
        )

        code, output = self.push(head)

        self.assertEqual(1, code)
        self.assertIn(self.finding + "\n", output)
        self.assertIn('secrets.gitleaks "cfg.txt"', output)

    def test_ref_names_that_are_not_utf8_give_findings_not_a_traceback(self) -> None:
        self.remote("origin", self.base)
        packed = self.root / ".git/packed-refs"
        with packed.open("ab") as refs:
            refs.write(self.base.encode() + b" refs/remotes/origin/\xff\n")
        self.assertEqual((1, True), self._pushed_finding())
        self.git_bytes(b"config", b"remote.origin/\xff.url", REMOTE_URL.encode())
        with packed.open("ab") as refs:
            refs.write(self.commit.encode() + b" refs/remotes/origin/\xff/main\n")
        self.assertEqual((1, True), self._pushed_finding())

    def _pushed_finding(self) -> tuple[int, bool]:
        code, output = self.push(self.commit)
        return code, self.finding + "\n" in output

    def test_check_only_warns_about_a_message_a_configured_remote_has(self) -> None:
        code, output = self.check()
        self.assertEqual(1, code)
        self.assertIn(self.finding + "\n", output)

        self.remote("upstream", self.commit)
        code, output = self.check()
        self.assertEqual(0, code)
        self.assertIn("WARN history", output)
        self.assertIn(self.finding + ON_THE_REMOTE + "\n" + PUSHED_FIX + "\n", output)

    def test_a_private_value_inside_the_remote_note_keeps_the_pushed_fix(self) -> None:
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        values = self.root / PRIVATE_VALUES_PATH
        values.parent.mkdir(parents=True)
        values.write_text("provider\n", encoding="utf-8")
        values.chmod(0o600)
        self.remote("upstream", self.commit)
        code, output = self.check()
        self.assertEqual(0, code)
        masked = ON_THE_REMOTE.replace("provider", PRIVATE_VALUE_MASK)
        self.assertIn(self.finding + masked + "\n" + PUSHED_FIX + "\n", output)

    def test_pre_push_without_a_push_range_blocks_what_another_remote_has(
        self,
    ) -> None:
        self.remote("backup", self.commit)
        self.assertEqual(0, self.check()[0])

        code, output = history_cli(
            self.root, ("hook", "pre-push"), {"PRE_COMMIT_REMOTE_NAME": "origin"}
        )
        self.assertEqual(1, code)
        self.assertIn(self.finding + "\n", output)

    def test_a_ref_of_no_configured_remote_is_not_trusted(self) -> None:
        run_git(self.root, "update-ref", "refs/remotes/nobody/x", self.commit)

        self.assertEqual(1, self.check()[0])

    def test_a_remote_name_with_glob_characters_or_spaces_is_not_trusted(
        self,
    ) -> None:
        run_git(self.root, "config", "remote.*.url", REMOTE_URL)
        run_git(self.root, "config", "remote.my nobody.url", REMOTE_URL)
        run_git(self.root, "update-ref", "refs/remotes/nobody/x", self.commit)

        self.assertEqual(1, self.check()[0])

    def test_a_remote_name_that_is_not_utf8_gives_findings_not_a_traceback(
        self,
    ) -> None:
        subprocess.run(
            [b"git", b"-C", bytes(self.root), b"config", b"remote.o\xff.url", b"x"],
            check=True,
        )
        for arguments, environment in (
            (("check",), {}),
            (
                ("hook", "pre-push"),
                {"PRE_COMMIT_TO_REF": self.commit, "PRE_COMMIT_REMOTE_NAME": "o"},
            ),
        ):
            with self.subTest(arguments=arguments):
                code, output = history_cli(self.root, arguments, environment)
                self.assertEqual(1, code)
                self.assertIn(self.finding + "\n", output)

    def test_a_tag_under_a_remote_ref_still_blocks_check(self) -> None:
        self.remote("origin", self.commit)
        run_git(self.root, "config", "tag.gpgSign", "false")
        path = self.root / ".git/test-tag-message"
        path.write_text("Release\n\n" + HOME_LINE, encoding="utf-8")
        run_git(self.root, "tag", "-a", "v1", "-F", str(path))
        tag = run_git(self.root, "rev-parse", "refs/tags/v1").stdout.decode().strip()
        run_git(self.root, "update-ref", "refs/remotes/origin/tags/v1", tag)

        found = history(self.root, self.policy, warn_on_remote=True).findings

        self.assertEqual(
            [(TAG_MESSAGE_PATH, Severity.ERROR)],
            [(item.path, item.severity) for item in found if item.path != MESSAGE_PATH],
        )
        self.assertIn(
            "git push --delete <remote> <tag>",
            history_cli(self.root, ("check",), {})[1],
        )


if __name__ == "__main__":
    unittest.main()
