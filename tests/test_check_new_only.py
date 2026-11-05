import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from first_commit import cli
from first_commit.gitleaks_blobs import MESSAGE_PATH
from first_commit.gitleaks_scanner import CALIBRATION_INPUT
from first_commit.help_text import CHECK_WRITES
from first_commit.pushed import MAX_REVISION_BYTES
from tests.gitleaks_support import history_cli, needs_real_scanner
from tests.support import (
    TemporaryRootTest,
    commit_message,
    initialize_repository,
    run_git,
)

HOME_LINE = "- Built in /Users/" + "someone/work.\n"
WHOLE_HISTORY = (
    'history.whole-history ".git/config": The remote list is too long to leave out '
    "the commits remotes hold, so --new-only checked the whole history."
)
WHOLE_HISTORY_FIX = (
    "Nothing was left out: this run checked every commit. To check only new "
    "commits, remove the remotes you no longer use with git remote remove <name>."
)
NEW_ONLY_HELP = (
    "Limit the history check to commits no configured remote holds, as its "
    "remote-tracking branches show (with no remote, the whole history)."
)


def _main(*arguments: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output), redirect_stderr(io.StringIO()):
        try:
            code = cli.main(arguments)
        except SystemExit as stop:
            code = int(stop.code or 0)
    return code, output.getvalue()


class NewOnlyTest(TemporaryRootTest):
    @needs_real_scanner
    def setUp(self) -> None:
        super().setUp()
        self.work = self.root / "work"
        self.work.mkdir()
        initialize_repository(self.work)
        (self.work / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
        self.old = self.commit("old.txt")

    def commit(self, name: str) -> str:
        (self.work / name).write_bytes(CALIBRATION_INPUT)
        message = self.root / "message.txt"
        message.write_text(commit_message(f"feat: add {name}") + HOME_LINE, "utf-8")
        run_git(self.work, "config", "user.email", "fixture@example.net")
        run_git(self.work, "config", "user.name", "Fixture Person")
        run_git(self.work, "config", "commit.gpgsign", "false")
        run_git(self.work, "add", "--", name)
        run_git(self.work, "commit", "-q", "--no-verify", "-F", str(message))
        return run_git(self.work, "rev-parse", "HEAD").stdout.decode().strip()

    def add_bare_remote(self) -> None:
        bare = self.root / "bare.git"
        run_git(self.root, "clone", "-q", "--bare", str(self.work), str(bare))
        run_git(self.work, "remote", "add", "origin", str(bare))
        run_git(self.work, "fetch", "-q", "origin")

    def check(self, *arguments: str) -> tuple[int, str]:
        return history_cli(self.work, ("check", *arguments), {})

    def message_finding(self, commit: str) -> str:
        line = commit_message("").count("\n") + 1
        return (
            f'privacy.user-home-path "{MESSAGE_PATH}":{line}: Commit {commit[:12]}: '
            "Detected a literal user-home path."
        )

    def test_new_only_reports_only_unpushed_commits(self) -> None:
        self.add_bare_remote()
        self.commit("new.txt")

        code, output = self.check("--new-only")

        self.assertEqual(1, code)
        self.assertIn('secrets.gitleaks "new.txt"', output)
        self.assertNotIn("old.txt", output)

        code, output = self.check()

        self.assertEqual(1, code)
        self.assertIn('secrets.gitleaks "new.txt"', output)
        self.assertIn('secrets.gitleaks "old.txt"', output)

    def test_new_only_leaves_out_messages_of_pushed_commits(self) -> None:
        self.add_bare_remote()
        new = self.commit("new.txt")

        output = self.check("--new-only")[1]

        self.assertIn(self.message_finding(new) + "\n", output)
        self.assertNotIn(self.message_finding(self.old), output)

        output = self.check()[1]

        self.assertIn(self.message_finding(new) + "\n", output)
        self.assertIn(self.message_finding(self.old) + " This text is already", output)

    def test_new_only_exits_0_with_nothing_new(self) -> None:
        self.add_bare_remote()
        self.commit("new.txt")
        run_git(self.work, "push", "-q", "--no-verify", "origin", "main")
        run_git(self.work, "fetch", "-q", "origin")

        code, output = self.check("--new-only")

        self.assertEqual(0, code)
        self.assertTrue(output.endswith("\nPASS history\n"), output)
        self.assertEqual(1, self.check()[0])

    def test_new_only_without_remote_checks_whole_history(self) -> None:
        code, output = self.check("--new-only")

        self.assertEqual(1, code)
        self.assertIn('secrets.gitleaks "old.txt"', output)
        self.assertIn(self.message_finding(self.old) + "\n", output)
        self.assertEqual((code, output), self.check())

    def test_new_only_checks_the_whole_history_past_the_remote_list_limit(
        self,
    ) -> None:
        self.add_bare_remote()
        self.commit("new.txt")
        names = [f"{number:03d}" + "r" * 250 for number in range(300)]
        with (self.work / ".git/config").open("a", encoding="utf-8") as config:
            for name in names:
                config.write(f'[remote "{name}"]\n\turl = {self.root / "bare.git"}\n')
        self.assertGreater(len(" --remotes=".join(names)), MAX_REVISION_BYTES)

        code, output = self.check("--new-only")

        self.assertEqual(1, code)
        self.assertIn('secrets.gitleaks "old.txt"', output)
        self.assertIn('secrets.gitleaks "new.txt"', output)
        self.assertEqual(
            1, output.count(WHOLE_HISTORY + "\n  fix: " + WHOLE_HISTORY_FIX + "\n")
        )
        self.assertNotIn("whole-history", self.check()[1])

        code, text = self.check("--new-only", "--format", "json")
        history = json.loads(text)["checks"][-1]

        self.assertEqual(1, code)
        self.assertIn(
            {
                "rule_id": "history.whole-history",
                "severity": "warning",
                "path": ".git/config",
                "summary": WHOLE_HISTORY.split(": ", 1)[1],
                "fix": WHOLE_HISTORY_FIX,
            },
            history["findings"],
        )

    def test_new_only_scans_commits_of_a_ref_no_configured_remote_has(self) -> None:
        run_git(self.work, "update-ref", "refs/remotes/nobody/main", self.old)

        output = self.check("--new-only")[1]

        self.assertIn('secrets.gitleaks "old.txt"', output)
        self.assertIn(self.message_finding(self.old) + "\n", output)

        run_git(self.work, "config", "remote.nobody.url", str(self.root / "none.git"))
        code, output = self.check("--new-only")

        self.assertEqual(0, code)
        self.assertNotIn("old.txt", output)

    def test_new_only_leaves_the_working_tree_and_staged_checks_whole(self) -> None:
        self.add_bare_remote()
        run_git(self.work, "push", "-q", "--no-verify", "origin", "main")
        run_git(self.work, "fetch", "-q", "origin")
        (self.work / "AGENTS.md").write_text("Rules.\n", "utf-8")
        (self.work / "README.md").write_text("A tool.\n", "utf-8")
        (self.work / "staged.txt").write_bytes(CALIBRATION_INPUT)
        run_git(self.work, "add", "--", "AGENTS.md", "README.md", "staged.txt")

        code, output = _main("check", "--new-only", "--root", str(self.work))
        everything = _main("check", "--root", str(self.work))

        self.assertEqual(1, code)
        self.assertIn("FAIL staged", output)
        self.assertIn('"staged.txt"', output)
        self.assertEqual(
            [line for line in output.splitlines() if "staged" in line],
            [line for line in everything[1].splitlines() if "staged" in line],
        )

    def test_hook_stages_do_not_accept_new_only(self) -> None:
        for stage in ("pre-push", "pre-commit"):
            with self.subTest(stage=stage):
                call = ("hook", stage, "--format", "json", "--root", str(self.work))

                code, text = _main(*call, "--new-only")

                self.assertEqual(2, code)
                self.assertEqual("invalid-arguments", json.loads(text)["error"]["code"])

                code, text = _main(*call)

                self.assertEqual(1, code)
                self.assertIn("checks", json.loads(text))


class NewOnlyHelpTest(unittest.TestCase):
    def test_check_help_names_new_only_and_keeps_its_effects(self) -> None:
        code, text = _main("check", "--help")

        self.assertEqual(0, code)
        self.assertIn(NEW_ONLY_HELP, " ".join(text.split()))
        self.assertIn("\nEffects: reads, writes own state\n", text)

        code, text = _main("help", "--format", "json")
        check = json.loads(text)["commands"]["check"]

        self.assertEqual(0, code)
        self.assertIn(
            {"argument": "--new-only", "help": NEW_ONLY_HELP}, check["options"]
        )
        self.assertEqual(["reads", "writes own state"], check["effects"])
        self.assertEqual(CHECK_WRITES, check["writes"])


if __name__ == "__main__":
    unittest.main()
