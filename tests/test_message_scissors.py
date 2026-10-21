import os
import subprocess
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import NamedTuple
from unittest import mock

from first_commit import git
from first_commit.gitleaks import scan_staged
from first_commit.gitleaks_blobs import MESSAGE_PATH
from first_commit.message_scissors import split_message
from first_commit.models import Finding, Result, Severity
from first_commit.policy import parse_policy
from first_commit.validation import message
from tests.gitleaks_support import (
    SLACK_LINE,
    SLACK_TOKEN,
    needs_real_scanner,
    stage_allowed_slack_token,
)
from tests.support import commit_message, initialize_repository, run_git

SCISSORS = "------------------------ >8 ------------------------\n"
EDITOR = '#!/bin/sh\ncp "$1" "$FIRST_COMMIT_TEST_CAPTURE"\nexit 1\n'
COMMIT_MSG_HOOK = (
    '#!/bin/sh\ncp "$1" "$FIRST_COMMIT_TEST_CAPTURE"\n'
    'env > "$FIRST_COMMIT_TEST_CAPTURE.env"\n'
)
# The variables that decide whether the hook treats comment lines as removed.
HOOK_VARIABLES = ("GIT_EDITOR", "GIT_CONFIG")
# The identity for fixture commits; `git -c` would set GIT_CONFIG_PARAMETERS.
IDENTITY = {
    "GIT_AUTHOR_NAME": "Example",
    "GIT_AUTHOR_EMAIL": "public@example.net",
    "GIT_COMMITTER_NAME": "Example",
    "GIT_COMMITTER_EMAIL": "public@example.net",
}
BELOW = (
    " The text below the scissors line is committed unless Git removes it, as git "
    "commit -v does; the pre-push hook blocks it if it is committed."
)
COMMENT = (
    " A comment line is committed unless Git removes it, as git commit does when it "
    "opens an editor; the pre-push hook blocks it if it is committed."
)
HOME_LINE = "/Users/" + "someone/work\n"
HOME_RULE = "privacy.user-home-path"


def _without_hook_variables(environment: Mapping[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in environment.items()
        if not key.startswith(HOOK_VARIABLES)
    }


def _hook_environment(
    variables: Mapping[str, str] | None = None,
) -> AbstractContextManager[object]:
    # tests/__init__.py exports GIT_CONFIG_GLOBAL and GIT_CONFIG_NOSYSTEM, and the
    # developer's shell may export GIT_EDITOR; the hook reads all three.
    return mock.patch.dict(
        os.environ,
        {**_without_hook_variables(os.environ), **(variables or {})},
        clear=True,
    )


def _reporting_version(version: bytes) -> AbstractContextManager[object]:
    def answer(
        root: Path, arguments: Sequence[str], input_bytes: bytes | None = None
    ) -> bytes:
        if tuple(arguments) == ("version",):
            return version
        return git.run_git(root, arguments, input_bytes)

    return mock.patch("first_commit.message_scissors.run_git", side_effect=answer)


def _git_version() -> tuple[int, int]:
    number = run_git(Path.cwd(), "version").stdout.decode().split()[2]
    major, minor = number.split(".")[:2]
    return int(major), int(minor)


def _secret_findings(result: Result) -> list[Finding]:
    return [
        item
        for item in result.findings
        if item.rule_id.startswith(("secrets.", "privacy."))
    ]


def _edited_message(root: Path, text: str, *options: str) -> Path:
    editor = root.parent / f"{root.name}-editor"
    editor.write_text(EDITOR, encoding="utf-8")
    editor.chmod(0o755)
    captured = root / ".git/captured-message"
    try:
        subprocess.run(
            ["git", "-C", str(root), "commit", *options, "-e", "-m", text],
            env={
                **os.environ,
                **IDENTITY,
                "GIT_EDITOR": str(editor),
                "FIRST_COMMIT_TEST_CAPTURE": str(captured),
            },
            capture_output=True,
            check=False,
        )
    finally:
        editor.unlink()
    return captured


class HookCapture(NamedTuple):
    message: Path
    # The hook's GIT_EDITOR and GIT_CONFIG* variables.
    environment: dict[str, str]
    recorded: str


def _hook_capture(
    root: Path,
    options: Sequence[str],
    config: Sequence[str] = (),
    variables: Mapping[str, str] | None = None,
) -> HookCapture:
    hook = root / ".git/hooks/commit-msg"
    hook.write_text(COMMIT_MSG_HOOK, encoding="utf-8")
    hook.chmod(0o755)
    captured = root / ".git/captured-message"
    # Without GIT_CONFIG_GLOBAL and GIT_CONFIG_NOSYSTEM, which the hook would see;
    # HOME is a scratch folder, so Git reads no global configuration.
    subprocess.run(
        ["git", "-C", str(root), *config, "commit", "-q", "--allow-empty", *options],
        env={
            **_without_hook_variables(os.environ),
            **IDENTITY,
            "FIRST_COMMIT_TEST_CAPTURE": str(captured),
            **(variables or {}),
        },
        capture_output=True,
        check=True,
    )
    recorded = run_git(root, "log", "-1", "--format=%B").stdout.decode()
    lines = Path(f"{captured}.env").read_text("utf-8").splitlines()
    environment = {
        key: value
        for key, _, value in (line.partition("=") for line in lines)
        if key.startswith(HOOK_VARIABLES)
    }
    return HookCapture(captured, environment, recorded)


class SplitMessageTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)

    def test_the_scissors_line_and_everything_below_it_are_dropped(self) -> None:
        above = b"feat: add\n\n# a comment\n"
        below = b"# " + SCISSORS.encode() + b"diff --git a/x b/x\n"
        self.assertEqual(above, split_message(self.root, above + below, {}).above)
        self.assertEqual(b"", split_message(self.root, below, {}).above)

    def test_only_the_configured_comment_string_marks_the_scissors_line(self) -> None:
        run_git(self.root, "config", "core.commentChar", ";")
        hidden = b"feat: add\n; " + SCISSORS.encode() + b"diff\n"
        self.assertEqual(b"feat: add\n", split_message(self.root, hidden, {}).above)
        kept = b"feat: add\n# " + SCISSORS.encode() + b"diff\n"
        self.assertEqual(kept, split_message(self.root, kept, {}).above)

    def test_lines_that_only_resemble_the_scissors_line_are_kept(self) -> None:
        for content in (
            b"feat: add\n#" + SCISSORS.encode() + b"x\n",
            b"feat: add\nx # " + SCISSORS.encode() + b"x\n",
            b"feat: add\n# " + SCISSORS.rstrip("\n").encode(),
        ):
            with self.subTest(content=content):
                self.assertEqual(content, split_message(self.root, content, {}).above)

    def test_an_automatic_comment_character_keeps_the_whole_message(self) -> None:
        run_git(self.root, "config", "core.commentChar", "auto")
        content = b"feat: add\n# " + SCISSORS.encode() + b"diff\n"
        self.assertEqual(content, split_message(self.root, content, {}).above)

    def test_the_commit_msg_check_reads_the_comment_string_once(self) -> None:
        policy = parse_policy(b'{"schema_version":1}', self.root)
        path = self.root / ".git/test-message"
        path.write_text(commit_message("feat: add") + "# " + SCISSORS + "x\n", "utf-8")
        with (
            mock.patch(
                "first_commit.message_scissors.run_git", wraps=git.run_git
            ) as run,
            mock.patch("first_commit.message_scissors.scan_message", return_value=()),
        ):
            message(self.root, policy, path)

        self.assertEqual(1, run.call_count)


class VerboseCommitMessageTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        stage_allowed_slack_token(self.root)

    def verbose_message_file(self, text: str) -> Path:
        captured = _edited_message(self.root, text, "-v")
        self.assertIn(SCISSORS, captured.read_text("utf-8"))
        self.assertIn(SLACK_TOKEN, captured.read_text("utf-8"))
        return captured

    @needs_real_scanner
    def test_a_staged_allowed_secret_below_the_scissors_line_only_warns(self) -> None:
        self.assertEqual((), scan_staged(self.root, max_findings=10))
        path = self.verbose_message_file(commit_message("feat: add config"))

        result = message(self.root, self.policy, path)

        found = _secret_findings(result)
        self.assertIn("secrets.gitleaks", [item.rule_id for item in found])
        self.assertEqual({Severity.WARNING}, {item.severity for item in found})

    @needs_real_scanner
    def test_a_secret_above_the_scissors_line_still_blocks(self) -> None:
        text = commit_message("feat: add config") + "- " + SLACK_LINE
        path = self.verbose_message_file(text)

        result = message(self.root, self.policy, path)

        self.assertIn(
            ("secrets.gitleaks", MESSAGE_PATH, Severity.ERROR),
            [(item.rule_id, item.path, item.severity) for item in result.findings],
        )


class CommentLinesTest(unittest.TestCase):
    @needs_real_scanner
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        self.above = commit_message("feat: add config")
        self.line = self.above.count("\n") + 1

    def check(
        self, text: str, variables: Mapping[str, str] | None = None
    ) -> list[tuple[str, int | None, Severity]]:
        path = self.root / ".git/test-message"
        path.write_text(text, encoding="utf-8")
        with _hook_environment(variables):
            found = _secret_findings(message(self.root, self.policy, path))
        return [(item.rule_id, item.line, item.severity) for item in found]

    def test_the_branch_name_git_adds_as_a_comment_only_warns(self) -> None:
        run_git(self.root, "checkout", "-q", "-b", "feature/" + "home/someone")
        (self.root / "notes.txt").write_text("notes\n", encoding="utf-8")
        run_git(self.root, "add", "--", "notes.txt")
        path = _edited_message(self.root, self.above)
        self.assertIn("# On branch feature/" + "home/someone", path.read_text("utf-8"))

        with _hook_environment():
            found = _secret_findings(message(self.root, self.policy, path))

        self.assertEqual(
            [
                (
                    HOME_RULE,
                    Severity.WARNING,
                    "Detected a literal user-home path." + COMMENT,
                )
            ],
            [(item.rule_id, item.severity, item.summary) for item in found],
        )

    def hook_check(
        self,
        options: Sequence[str],
        config: Sequence[str] = (),
        variables: Mapping[str, str] | None = None,
    ) -> tuple[HookCapture, list[tuple[str, int | None, Severity]]]:
        capture = _hook_capture(self.root, options, config, variables)
        with _hook_environment(capture.environment):
            found = _secret_findings(message(self.root, self.policy, capture.message))
        return capture, [(item.rule_id, item.line, item.severity) for item in found]

    def test_a_comment_line_in_a_message_without_an_editor_blocks(self) -> None:
        text = self.above + "# " + SLACK_LINE
        path = self.root.parent / f"{self.root.name}-message"
        path.write_text(text, encoding="utf-8")
        self.addCleanup(path.unlink)
        for options in (("-m", text), ("-F", str(path))):
            with self.subTest(options=options[0]):
                capture, found = self.hook_check(options)
                self.assertEqual(":", capture.environment["GIT_EDITOR"])
                self.assertIn(SLACK_TOKEN, capture.recorded)
                self.assertEqual(
                    [("secrets.gitleaks", self.line, Severity.ERROR)], found
                )

    def test_strip_cleanup_without_an_editor_still_blocks_comment_lines(self) -> None:
        # Git removes the line here; blocking it is the safe direction, since a
        # --cleanup option the hook cannot see may keep it.
        run_git(self.root, "config", "commit.cleanup", "strip")

        capture, found = self.hook_check(("-m", self.above + "# " + HOME_LINE))

        self.assertNotIn(HOME_LINE, capture.recorded)
        self.assertEqual([(HOME_RULE, self.line, Severity.ERROR)], found)

    def test_git_settings_the_hook_cannot_read_make_comment_lines_block(
        self,
    ) -> None:
        path = self.root.parent / f"{self.root.name}-message"
        path.write_text(self.above + "# " + HOME_LINE, encoding="utf-8")
        self.addCleanup(path.unlink)
        global_config = self.root.parent / f"{self.root.name}-global"
        global_config.write_text("[commit]\n\tcleanup = verbatim\n", "utf-8")
        self.addCleanup(global_config.unlink)
        for name, config, variables, kept in (
            ("editor", (), {}, False),
            ("git -c commit.cleanup", ("-c", "commit.cleanup=verbatim"), {}, True),
            ("git -c core.commentChar", ("-c", "core.commentChar=;"), {}, True),
            ("GIT_CONFIG_GLOBAL", (), {"GIT_CONFIG_GLOBAL": str(global_config)}, True),
        ):
            with self.subTest(name):
                capture, found = self.hook_check(
                    ("-e", "-F", str(path)),
                    config,
                    {"GIT_EDITOR": "true", **variables},
                )
                self.assertEqual(kept, HOME_LINE in capture.recorded)
                severity = Severity.ERROR if kept else Severity.WARNING
                self.assertEqual([(HOME_RULE, self.line, severity)], found)

    def test_any_configuration_override_makes_comment_lines_block(self) -> None:
        text = self.above + "# " + HOME_LINE
        self.assertEqual([(HOME_RULE, self.line, Severity.WARNING)], self.check(text))
        for name, value in (
            ("GIT_CONFIG_PARAMETERS", "'commit.cleanup'='verbatim'"),
            ("GIT_CONFIG_COUNT", "0"),
            ("GIT_CONFIG_GLOBAL", os.devnull),
            ("GIT_CONFIG_SYSTEM", os.devnull),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG", os.devnull),
        ):
            with self.subTest(name):
                self.assertEqual(
                    [(HOME_RULE, self.line, Severity.ERROR)],
                    self.check(text, {name: value}),
                )

    def test_findings_on_comment_lines_warn_with_their_own_line_numbers(self) -> None:
        start = self.above.count("\n")
        text = self.above + "# " + SLACK_LINE + "# " + HOME_LINE + "- " + HOME_LINE

        self.assertEqual(
            [
                ("secrets.gitleaks", start + 1, Severity.WARNING),
                (HOME_RULE, start + 2, Severity.WARNING),
                (HOME_RULE, start + 3, Severity.ERROR),
            ],
            self.check(text),
        )

    def test_a_cleanup_mode_that_keeps_comment_lines_blocks_them(self) -> None:
        for mode, severity in (
            ("verbatim", Severity.ERROR),
            ("whitespace", Severity.ERROR),
            ("scissors", Severity.ERROR),
            ("unknown", Severity.ERROR),
            ("strip", Severity.WARNING),
            ("default", Severity.WARNING),
        ):
            with self.subTest(mode=mode):
                run_git(self.root, "config", "commit.cleanup", mode)
                self.assertEqual(
                    [(HOME_RULE, self.line, severity)],
                    self.check(self.above + "# " + HOME_LINE),
                )

    def set_comment(self, key: str, value: str) -> None:
        for name in ("core.commentChar", "core.commentString"):
            subprocess.run(
                ["git", "-C", str(self.root), "config", "--unset", name],
                check=False,
            )
        run_git(self.root, "config", key, value)

    def test_the_configured_comment_string_marks_comment_lines(self) -> None:
        # Git reads core.commentString from 2.45 on and ignores it before.
        reads_string = _git_version() >= (2, 45)
        string_line, hash_line = (
            (Severity.WARNING, Severity.ERROR)
            if reads_string
            else (Severity.ERROR, Severity.WARNING)
        )
        for key, value, prefix, severity in (
            ("core.commentChar", ";", "; ", Severity.WARNING),
            ("core.commentChar", ";", "# ", Severity.ERROR),
            ("core.commentString", "//", "// ", string_line),
            ("core.commentString", "//", "# ", hash_line),
            ("core.commentChar", "auto", "# ", Severity.ERROR),
        ):
            with self.subTest(key=key, value=value, prefix=prefix):
                self.set_comment(key, value)
                self.assertEqual(
                    [(HOME_RULE, self.line, severity)],
                    self.check(self.above + prefix + HOME_LINE),
                )

    def test_the_comment_string_counts_only_for_a_git_that_reads_it(self) -> None:
        self.set_comment("core.commentString", "//")
        for version, string_line, hash_line in (
            (b"git version 2.39.5 (Apple Git-154)\n", Severity.ERROR, Severity.WARNING),
            (b"git version 2.45.0\n", Severity.WARNING, Severity.ERROR),
            (b"unexpected\n", Severity.ERROR, Severity.ERROR),
        ):
            with self.subTest(version=version), _reporting_version(version):
                self.assertEqual(
                    [(HOME_RULE, self.line, string_line)],
                    self.check(self.above + "// " + HOME_LINE),
                )
                self.assertEqual(
                    [(HOME_RULE, self.line, hash_line)],
                    self.check(self.above + "# " + HOME_LINE),
                )


class HandWrittenScissorsTest(unittest.TestCase):
    @needs_real_scanner
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        self.above = commit_message("feat: add config")

    def check(self, text: str) -> list[tuple[str, int | None, Severity, str]]:
        path = self.root / ".git/test-message"
        path.write_text(text, encoding="utf-8")
        found = _secret_findings(message(self.root, self.policy, path))
        return [
            (item.rule_id, item.line, item.severity, item.summary) for item in found
        ]

    def test_a_secret_below_the_line_only_warns(self) -> None:
        home = "- Built in /Users/" + "someone/work.\n"
        found = self.check(self.above + "# " + SCISSORS + SLACK_LINE + home)

        line = self.above.count("\n") + 2
        self.assertEqual(
            [
                (
                    "secrets.gitleaks",
                    line,
                    Severity.WARNING,
                    "Gitleaks reported a commit-message finding." + BELOW,
                ),
                (
                    "privacy.user-home-path",
                    line + 1,
                    Severity.WARNING,
                    "Detected a literal user-home path." + BELOW,
                ),
            ],
            found,
        )

    def test_the_same_secret_above_the_line_blocks(self) -> None:
        found = self.check(self.above + "- " + SLACK_LINE + "# " + SCISSORS + "x\n")

        self.assertEqual(
            [("secrets.gitleaks", self.above.count("\n") + 1, Severity.ERROR)],
            [row[:3] for row in found],
        )


if __name__ == "__main__":
    unittest.main()
