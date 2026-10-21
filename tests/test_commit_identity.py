import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from first_commit.checks.identity import commit_identity_findings, ident_email
from first_commit.policy import POLICY_PATH, parse_policy
from first_commit.validation import message
from tests.gitleaks_support import needs_real_scanner
from tests.support import commit_message, initialize_repository, run_git
from tests.validation_support import IDENTITY, commit_identity

APPROVED = IDENTITY["user.email"]
PRIVATE_EMAIL = "alice@" + "corp-private.net"
IDENTITY_RULES = {"git.author-email", "git.committer-email"}
SOURCE = Path(__file__).resolve().parents[1] / "src"


class CommitIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        run_git(self.root, "config", "user.name", IDENTITY["user.name"])
        run_git(self.root, "config", "user.email", APPROVED)
        self.message_path = self.root / ".git/COMMIT_EDITMSG"
        self.message_path.write_text(commit_message("feat: add checks"), "utf-8")
        self.policy = replace(
            parse_policy(b'{"schema_version":1}', self.root),
            contributor_emails=(APPROVED,),
        )

    def identity_rules(self) -> set[str]:
        result = message(self.root, self.policy, self.message_path)
        return {item.rule_id for item in result.findings} & IDENTITY_RULES

    def test_ident_email_reads_only_well_formed_git_var_lines(self) -> None:
        self.assertEqual(
            "bob@example.net",
            ident_email(b"Bob B <bob@example.net> 1792345416 -0700\n"),
        )
        self.assertEqual("", ident_email(b"Nobody <> 1 +0000"))
        for raw in (
            b"Bob <bob@example.net>\n",
            b"Bob <bob@example.net> 1 +0000\nextra",
            b"Bob <a<b@example.net> 1 +0000",
            b"Bob <\xff@example.net> 1 +0000",
        ):
            with self.subTest(raw=raw):
                self.assertIsNone(ident_email(raw))

    def test_only_unapproved_emails_other_than_the_local_one_are_reported(self) -> None:
        settings = {"user.email": "local@example.net"}
        cases: tuple[tuple[dict[str, str | None], set[str]], ...] = (
            ({"GIT_AUTHOR_IDENT": APPROVED, "GIT_COMMITTER_IDENT": APPROVED}, set()),
            (
                {"GIT_AUTHOR_IDENT": PRIVATE_EMAIL, "GIT_COMMITTER_IDENT": APPROVED},
                {"git.author-email"},
            ),
            (
                {"GIT_AUTHOR_IDENT": APPROVED, "GIT_COMMITTER_IDENT": PRIVATE_EMAIL},
                {"git.committer-email"},
            ),
            ({"GIT_AUTHOR_IDENT": None, "GIT_COMMITTER_IDENT": None}, IDENTITY_RULES),
            (
                {
                    "GIT_AUTHOR_IDENT": "local@example.net",
                    "GIT_COMMITTER_IDENT": "local@example.net",
                },
                set(),
            ),
        )
        for emails, expected in cases:
            with self.subTest(emails=emails):
                findings = commit_identity_findings(emails, (APPROVED,), settings)
                self.assertEqual(expected, {item.rule_id for item in findings})

    def test_hook_environment_author_and_committer_are_checked(self) -> None:
        with commit_identity():
            self.assertEqual(set(), self.identity_rules())
        with commit_identity(author=PRIVATE_EMAIL):
            self.assertEqual({"git.author-email"}, self.identity_rules())
        with commit_identity(committer=PRIVATE_EMAIL):
            self.assertEqual({"git.committer-email"}, self.identity_rules())

    def test_a_global_or_system_file_named_by_variable_is_checked(self) -> None:
        other = self.root.parent / (self.root.name + " other.gitconfig")
        self.addCleanup(other.unlink, missing_ok=True)
        other.write_text(f"[committer]\n\temail = {PRIVATE_EMAIL}\n", "utf-8")
        for variables in (
            {"GIT_CONFIG_GLOBAL": str(other)},
            {"GIT_CONFIG_SYSTEM": str(other), "GIT_CONFIG_NOSYSTEM": "0"},
        ):
            with (
                self.subTest(variables=variables),
                mock.patch.dict(os.environ, variables),
            ):
                self.assertEqual({"git.committer-email"}, self.identity_rules())

    def test_git_c_settings_in_the_hook_environment_are_checked(self) -> None:
        cases = (
            (
                {"GIT_CONFIG_PARAMETERS": f"'user.email'='{PRIVATE_EMAIL}'"},
                IDENTITY_RULES,
            ),
            (
                {
                    "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "committer.email",
                    "GIT_CONFIG_VALUE_0": PRIVATE_EMAIL,
                },
                {"git.committer-email"},
            ),
        )
        for variables, expected in cases:
            with (
                self.subTest(variables=variables),
                mock.patch.dict(os.environ, variables),
            ):
                self.assertEqual(expected, self.identity_rules())

    def run_hooked_commit(
        self, git_options: tuple[str, ...] = (), commit_options: tuple[str, ...] = ()
    ) -> set[str]:
        (self.root / POLICY_PATH).write_text('{"schema_version":1}', "utf-8")
        hook = self.root / ".git/hooks/commit-msg"
        hook.write_text(
            "#!/bin/sh\n"
            f"'{sys.executable}' -m first_commit hook commit-msg --format json \"$1\" "
            '> "$(git rev-parse --git-dir)/hook-output.json"\n'
            "exit 0\n",
            "utf-8",
        )
        hook.chmod(0o755)
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        environment.update(
            PYTHONPATH=str(SOURCE),
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "-c",
                "commit.gpgsign=false",
                *git_options,
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                commit_message("feat: add checks"),
                *commit_options,
            ],
            env=environment,
            check=True,
            capture_output=True,
        )
        output = self.root / ".git/hook-output.json"
        report = json.loads(output.read_text("utf-8"))
        return {
            finding["rule_id"]
            for check in report["checks"]
            for finding in check["findings"]
        } & IDENTITY_RULES

    @needs_real_scanner
    def test_git_c_committer_email_reaches_the_commit_msg_hook(self) -> None:
        self.assertEqual(set(), self.run_hooked_commit())
        self.assertEqual(
            IDENTITY_RULES,
            self.run_hooked_commit(("-c", f"user.email={PRIVATE_EMAIL}")),
        )
        self.assertEqual(
            {"git.committer-email"},
            self.run_hooked_commit(("-c", f"committer.email={PRIVATE_EMAIL}")),
        )

    @needs_real_scanner
    def test_git_commit_author_option_reaches_the_commit_msg_hook(self) -> None:
        rules = {
            "own": self.run_hooked_commit(),
            "other": self.run_hooked_commit(
                commit_options=(f"--author=Alice <{PRIVATE_EMAIL}>",)
            ),
        }

        self.assertEqual({"own": set(), "other": {"git.author-email"}}, rules)


if __name__ == "__main__":
    unittest.main()
