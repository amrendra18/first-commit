import importlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import yaml

from tests.setup_support import synthetic_key

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify"


def harness(name: str) -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module(f"verify_lib.{name}")


cli = harness("cli")
core = harness("core")
prepare = harness("prepare")
report = harness("report")


def _recording_runners(
    failing: str, started: list[str]
) -> dict[str, Callable[[object], list[str]]]:
    def runner(name: str) -> Callable[[object], list[str]]:
        def run(_run: object) -> list[str]:
            started.append(name)
            if name == failing:
                raise core.FeatureFailedError("synthetic failure")
            return ["ok"]

        return run

    return {name: runner(name) for name in cli.RUNNERS}


class VerifyScriptTest(unittest.TestCase):
    def main(self, *arguments: str) -> tuple[int, str, str]:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main(list(arguments))
        return code, output.getvalue(), error.getvalue()

    def test_help_and_usage_errors(self) -> None:
        code, output, _ = self.main("--help")
        self.assertEqual(0, code)
        self.assertTrue(output.startswith("Usage: scripts/verify"))
        for name in cli.FEATURES:
            self.assertIn(name, output)
        self.assertIn("Run `fast` before you open a pull request", output)
        for phrase in ("Agents", "handing off", "once the repository is public"):
            self.assertNotIn(phrase, output)
        for arguments in (("bogus",), ("--feature", "nope"), ("--plant", "nope")):
            with self.subTest(arguments=arguments):
                code, output, error = self.main(*arguments)
                self.assertEqual((2, ""), (code, output))
                self.assertIn("Usage:", error)

    def test_entry_point_prints_the_same_usage_and_exit_codes(self) -> None:
        shown = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual((0, cli.USAGE + "\n"), (shown.returncode, shown.stdout))
        wrong = subprocess.run(
            [sys.executable, str(SCRIPT), "bogus"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual((2, ""), (wrong.returncode, wrong.stdout))

    def test_levels_and_features_select_their_prerequisites_in_order(self) -> None:
        fast = cli.selected("fast", None)
        full = cli.selected("full", None)
        self.assertEqual(
            [
                "setup",
                "commit",
                "privacy",
                "message",
                "push",
                "clone-guided",
                "control-character",
                "preview-matches-apply",
                "fix-line-works",
                "first-run",
                "clone-trust",
                "commit-all",
            ],
            fast,
        )
        self.assertEqual(
            [*fast, "clone-saved", "clone-chosen-path", "remove", "github"], full
        )
        self.assertEqual(["setup", "commit", "remove"], cli.selected("fast", "remove"))
        self.assertEqual(["github"], cli.selected("fast", "github"))
        self.assertEqual(
            ["setup", "commit", "clone-guided", "clone-saved"],
            cli.selected("fast", "clone-saved"),
        )
        self.assertEqual(
            ["setup", "fix-line-works"], cli.selected("fast", "fix-line-works")
        )
        self.assertEqual(set(cli.FEATURES), set(cli.RUNNERS))

    def test_exit_checks_name_the_expected_code(self) -> None:
        self.assertEqual("setup exited 0", core.exited(0, 0, "setup"))
        self.assertEqual("a commit exited 1", core.blocked(1, "a commit"))
        with self.assertRaisesRegex(
            core.FeatureFailedError, "setup exited 1, expected 0"
        ):
            core.exited(1, 0, "setup")
        with self.assertRaisesRegex(
            core.FeatureFailedError, "a commit exited 0, expected non-zero"
        ):
            core.blocked(0, "a commit")

    def test_hook_proof_needs_the_exact_result_line_ending_in_passed(self) -> None:
        manifest = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text("utf-8"))
        names = {hook["name"] for hook in manifest}
        for name in (core.STAGED_HOOK, core.MESSAGE_HOOK, core.PUSH_HOOK):
            self.assertIn(name, names)
        name = core.MESSAGE_HOOK
        self.assertTrue(
            core.hook_passed(f"x\n{name}......Passed\n- hook id: y\n", name)
        )
        for output in (
            f"{name}......Failed\n",
            f"{name}......Failed\nother hook......Passed\n",
            "commit-message hygiene......Passed\n",
            f"before {name}......Passed\n",
            f"{name}......Passed (no files)\n",
            f"{name}\nPassed\n",
        ):
            with self.subTest(output=output):
                self.assertFalse(core.hook_passed(output, name))

    def test_a_skipped_github_feature_passes_unless_required(self) -> None:
        def skip(_run: object) -> list[str]:
            raise core.FeatureSkippedError("HEAD is not GitHub main")

        for flags, code, state in (
            ((), 0, "skipped"),
            (("--require-github",), 1, "failed"),
        ):
            with self.subTest(flags=flags):
                with (
                    patch.object(prepare, "check_prerequisites", return_value=[]),
                    patch.object(cli, "start_agent"),
                    patch.object(cli, "snapshot"),
                    patch.object(report, "write_evidence"),
                    patch.dict(cli.RUNNERS, {"github": skip}),
                ):
                    result, output, _ = self.main("--feature", "github", *flags)
                self.assertEqual(code, result)
                self.assertIn(f"github: {state}", output)
                self.assertIn("HEAD is not GitHub main", output)

    def test_a_failed_setup_or_commit_skips_the_later_features(self) -> None:
        fast = cli.selected("fast", None)
        for arguments, failing, ran, skipped in (
            (("--feature", "remove"), "setup", ["setup"], ["commit", "remove"]),
            (("--feature", "remove"), "commit", ["setup", "commit"], ["remove"]),
            (("--feature", "remove"), "remove", ["setup", "commit", "remove"], []),
            (("fast",), "privacy", fast, []),
        ):
            started: list[str] = []
            with (
                self.subTest(arguments=arguments, failing=failing),
                patch.object(prepare, "check_prerequisites", return_value=[]),
                patch.object(cli, "start_agent"),
                patch.object(cli, "snapshot"),
                patch.object(report, "write_evidence"),
                patch.dict(cli.RUNNERS, _recording_runners(failing, started)),
            ):
                code, output, _ = self.main(*arguments)
                self.assertEqual((1, ran), (code, started))
                self.assertEqual(
                    [
                        f"{name}: skipped - not reached: {failing} failed"
                        for name in skipped
                    ],
                    [line for line in output.splitlines() if "not reached" in line],
                )

    def test_an_unexpected_error_fails_only_its_feature(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            work.mkdir()
            run = core.Run(work=work, python=sys.executable, environment={})

            def broken(_run: object) -> list[str]:
                raise ValueError(f"no such file {work}/project/README.md")

            options = cli.parse_options(["fast"])
            with (
                patch.object(cli, "start_agent"),
                patch.object(cli, "snapshot"),
                patch.dict(
                    cli.RUNNERS, {"first-run": broken, "github": lambda _: ["ok"]}
                ),
                redirect_stdout(io.StringIO()) as output,
            ):
                results = cli.run_features(run, ["first-run", "github"], options)
        expected = "ValueError: no such file <work>/project/README.md"
        self.assertEqual(
            ("failed", expected),
            (results["first-run"].state, results["first-run"].reason),
        )
        self.assertEqual("proven", results["github"].state)
        self.assertIn("first-run: failed", output.getvalue())
        self.assertIn(expected, output.getvalue())
        self.assertNotIn(str(work), output.getvalue())

    def test_prerequisite_problem_exits_3_before_any_work(self) -> None:
        missing = [("Python with pre-commit and PyYAML", False, "create .venv")]
        with (
            patch.object(prepare, "check_prerequisites", return_value=missing),
            patch.object(cli, "start_agent") as agent,
        ):
            code, output, _ = self.main("fast")
        self.assertEqual(3, code)
        self.assertIn(
            "prerequisite: Python with pre-commit and PyYAML: missing - create .venv",
            output,
        )
        self.assertNotIn("doctor:", output)
        agent.assert_not_called()

    def test_a_path_folder_with_first_commit_and_git_stops_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            shared = Path(directory) / "shared"
            shared.mkdir()
            for tool in ("first-commit", "git", "ssh", "ssh-keygen"):
                (shared / tool).write_text("#!/bin/sh\nexit 0\n", "utf-8")
                (shared / tool).chmod(0o755)
            with (
                patch.dict(os.environ, {"PATH": f"{shared}:/usr/bin:/bin"}),
                patch.object(prepare, "check_prerequisites", return_value=[]),
                patch.object(cli, "start_agent") as agent,
                patch.object(cli, "snapshot"),
                patch.object(report, "write_evidence"),
            ):
                code, _, error = self.main("fast")
        self.assertEqual(3, code)
        self.assertIn(
            f"error: PATH folder {shared} holds first-commit and git, ssh, ssh-keygen;",
            error,
        )
        agent.assert_not_called()

    def test_fix_line_command_is_read_from_the_printed_fix_line(self) -> None:
        fix_line = harness("fix_line")
        printed = (
            'git.explicit-identity ".git/config": Explicit repository identity is not '
            "required.\n  fix: Run first-commit setup in this checkout; it sets the "
            "local identity, signing, contributor record, hooks, and commit template.\n"
        )
        match = fix_line.FIX_COMMAND.search(printed)
        self.assertIsNotNone(match)
        self.assertEqual("first-commit setup", match.group(1))

    def test_fix_line_feature_runs_only_the_tool_it_installed(self) -> None:
        fix_line = harness("fix_line")
        with tempfile.TemporaryDirectory() as directory:
            elsewhere = Path(directory) / "elsewhere"
            elsewhere.mkdir()
            (elsewhere / "first-commit").write_text("#!/bin/sh\nexit 0\n", "utf-8")
            (elsewhere / "first-commit").chmod(0o755)
            path = f"{elsewhere}:{elsewhere}:/usr/bin:/bin"
            with patch.dict(os.environ, {"PATH": path}):
                search_path = prepare.harness_path()
            run = self.enterContext(prepare.private_run(sys.executable, search_path))
            self.assertEqual([str(elsewhere)], run.removed_path_folders)
            with (
                patch.object(core.Run, "command", return_value=(0, "")),
                self.assertRaisesRegex(core.FeatureFailedError, "bin/first-commit"),
            ):
                fix_line.install_tool(run, "tool", "first-commit[setup]")
            env = fix_line.with_tool(run, run.work / "tool/bin")
            self.assertIsNone(shutil.which("first-commit", path=env["PATH"]))

    def test_setup_driver_runs_setup_by_path_from_the_named_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key.pub"
            key.write_text(synthetic_key() + "\n", encoding="ascii")
            project = Path(directory) / "project"
            project.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(harness("journeys").SETUP_DRIVER),
                    str(ROOT / "src"),
                    str(project),
                    "1" * 40,
                    "Example Person",
                    "public@" + "example.net",
                    str(key),
                    "skip",
                    "https",
                    "dry-run",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual([], list(project.iterdir()))
        self.assertEqual((0, ""), (result.returncode, result.stderr))
        self.assertIn("Git repository: would initialize", result.stdout.splitlines())

    def test_remove_runs_the_readme_remove_block_as_printed(self) -> None:
        block = harness("remove_journey").readme_remove_block()
        self.assertTrue(block.startswith("pre-commit uninstall\n"), block)
        self.assertIn('  git config --local --unset-all "$key"\n', block)
        self.assertTrue(
            block.endswith("rm -rf .local/first-commit .local/bin/gitleaks\n"), block
        )

    def test_the_clone_download_proof_reads_only_the_successful_setup(self) -> None:
        clones = harness("clones")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            scanner = target / ".local/bin/gitleaks"
            scanner.parent.mkdir(parents=True)
            scanner.write_text("#!/bin/sh\n", "utf-8")
            scanner.chmod(0o755)
            run = core.Run(work=target, python=sys.executable, environment={})
            run.log.append("Gitleaks: downloaded and installed 8.30.0\n")
            with (
                patch.object(clones, "clone", return_value=target),
                patch.object(clones, "guided", return_value=([], "Gitleaks: ready\n")),
                patch.object(clones, "checks_without_tool", return_value=[]),
                self.assertRaisesRegex(
                    core.FeatureFailedError, "Gitleaks: downloaded and installed"
                ),
            ):
                clones.feature_clone_guided(run)

    def test_each_feature_has_a_map_file_listed_in_the_index(self) -> None:
        features = ROOT / "verify" / "features"
        index = (features / "README.md").read_text("utf-8")
        for name in cli.FEATURES:
            with self.subTest(feature=name):
                text = (features / f"{name}.md").read_text("utf-8")
                for heading in (
                    "## What it is",
                    "## How to get to it",
                    "## Driving it",
                    "## Proof",
                ):
                    self.assertIn(heading, text)
                self.assertIn(f"]({name}.md)", index)
                self.assertRegex(text, r"\nProves: \[[^\]]+\]\(\.\./\.\./[A-Z]+\.md#")

    def test_the_map_table_equals_the_harness_features(self) -> None:
        features = ROOT / "verify" / "features"
        index = (features / "README.md").read_text("utf-8")
        rows = re.findall(
            r"^\| \d+ \| (.+?) \| \[(\S+)\.md\]\(\S+\) \| (\w+) \| (.+?) \|$",
            index,
            re.MULTILINE,
        )
        table = {
            name: (title, level, () if needs == "none" else tuple(needs.split(", ")))
            for title, name, level, needs in rows
        }
        pages = {path.stem for path in features.glob("*.md")} - {"README"}
        self.assertEqual(set(cli.FEATURES), pages)
        self.assertEqual(set(cli.FEATURES), set(table))
        for name, feature in cli.FEATURES.items():
            with self.subTest(feature=name):
                heading = (features / f"{name}.md").read_text("utf-8").split("\n", 1)[0]
                self.assertEqual(
                    (heading.removeprefix("# "), feature.level, feature.needs),
                    table[name],
                )


if __name__ == "__main__":
    unittest.main()
