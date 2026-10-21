import importlib
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType

import yaml

ROOT = Path(__file__).resolve().parents[1]


def rehearsal() -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module("verify_lib.rehearsal")


ci_local = rehearsal()


class CiLocalTest(unittest.TestCase):
    def test_the_real_workflow_loads_with_stand_ins_for_its_actions(self) -> None:
        jobs = ci_local.load_jobs(ci_local.WORKFLOW)
        self.assertEqual(["test"], list(jobs))
        steps = jobs["test"].steps
        uses = [step["uses"].split("@")[0] for step in steps if "uses" in step]
        self.assertEqual(["actions/checkout", "actions/setup-python"], uses)
        self.assertEqual(30, jobs["test"].minutes)
        runs = "\n".join(step.get("run", "") for step in steps)
        for command in (
            "first-commit setup",
            "scripts/check full",
            "scripts/verify fast",
        ):
            self.assertIn(command, runs)

    # CI installs Gitleaks through setup, so the rehearsal offers no Go.
    def test_steps_get_no_go_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = ci_local.base_environment(Path(temporary))
        self.assertEqual([], [key for key in environment if key.startswith("GO")])
        self.assertNotIn("Go ", ci_local.USAGE)

    def test_refuses_steps_it_cannot_run_locally(self) -> None:
        for step in (
            {"uses": "actions/cache@0123456789012345678901234567890123456789"},
            {"run": "echo ${{ matrix.os }}"},
            {"run": "true", "if": "success()"},
            {"run": "true", "env": {"NAME": "${{ secrets.TOKEN }}"}},
            {"run": "true", "env": ["NAME=value"]},
            {"name": "no command"},
        ):
            with self.subTest(step=step), self.assertRaises(ci_local.WorkflowError):
                ci_local.check_step(step, 1)
        self.assertEqual(
            {"run": "true", "if": "always()"},
            ci_local.check_step({"run": "true", "if": "always()"}, 1),
        )

    def test_refuses_workflow_job_and_step_keys_it_does_not_implement(self) -> None:
        step = {"name": "one", "run": "true"}
        job = {"runs-on": "ubuntu-latest", "steps": [step]}
        refused: tuple[tuple[dict[str, object], ...], ...] = (
            ({"env": {"A": "1"}}, {}, {}),
            ({"defaults": {"run": {"shell": "sh"}}}, {}, {}),
            ({}, {"env": {"A": "1"}}, {}),
            ({}, {"defaults": {"run": {"working-directory": "src"}}}, {}),
            ({}, {"timeout-minutes": 0}, {}),
            ({}, {"timeout-minutes": "${{ inputs.minutes }}"}, {}),
            ({}, {"timeout-minutes": True}, {}),
            ({}, {"continue-on-error": True}, {}),
            ({}, {"needs": "other"}, {}),
            ({}, {}, {"shell": "sh"}),
            ({}, {}, {"working-directory": "src"}),
            ({}, {}, {"continue-on-error": True}),
            ({}, {}, {"timeout-minutes": 5}),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ci.yml"
            for top, extra_job, extra_step in refused:
                workflow = {
                    "name": "CI",
                    "on": {"push": None},
                    "permissions": {"contents": "read"},
                    **top,
                    "jobs": {
                        "test": {**job, **extra_job, "steps": [{**step, **extra_step}]}
                    },
                }
                path.write_text(yaml.safe_dump(workflow), "utf-8")
                key = next(iter({**top, **extra_job, **extra_step}))
                with (
                    self.subTest(key=key, where=(top, extra_job, extra_step)),
                    self.assertRaisesRegex(ci_local.WorkflowError, key),
                ):
                    ci_local.load_jobs(path)
            accepted = {
                "on": None,
                "concurrency": {
                    "group": "${{ github.ref }}",
                    "cancel-in-progress": True,
                },
                "jobs": {"test": {**job, "steps": [{**step, "shell": "bash"}]}},
            }
            path.write_text(yaml.safe_dump(accepted), "utf-8")
            loaded = ci_local.load_jobs(path)["test"]
            self.assertEqual("bash", loaded.steps[0]["shell"])
            self.assertEqual(ci_local.ACTIONS_TIMEOUT_MINUTES, loaded.minutes)

    def test_a_step_past_the_job_time_limit_stops_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            state = ci_local.JobState(
                work=work, environment=ci_local.base_environment(work), checkout=work
            )
            log = work / "step.log"
            step = {"run": "echo started\nsleep 30\necho unreachable\n"}
            code = ci_local.run_step(state, step, log, timeout=0.5)
            self.assertEqual(ci_local.TIMED_OUT, code)
            self.assertEqual(
                "started\nstopped: the job reached its timeout-minutes\n",
                log.read_text("utf-8"),
            )

    def test_steps_run_with_bash_e_unless_the_step_names_bash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            state = ci_local.JobState(
                work=work, environment=ci_local.base_environment(work), checkout=work
            )
            log = work / "step.log"
            pipe = {"run": "false | true\necho reached\nfalse\necho unreachable\n"}
            self.assertEqual(1, ci_local.run_step(state, pipe, log, 60))
            self.assertEqual("reached\n", log.read_text("utf-8"))
            named = {**pipe, "shell": "bash"}
            self.assertEqual(1, ci_local.run_step(state, named, log, 60))
            self.assertEqual("", log.read_text("utf-8"))

    def test_reads_github_env_in_both_formats(self) -> None:
        self.assertEqual(
            {"ONE": "1", "TWO": "a=b", "MANY": "first\nsecond"},
            ci_local.parse_github_env(
                "ONE=1\nTWO=a=b\nMANY<<END\nfirst\nsecond\nEND\n"
            ),
        )
        for text in ("OPEN<<END\nno end\n", "no equals sign\n"):
            with self.subTest(text=text), self.assertRaises(ci_local.WorkflowError):
                ci_local.parse_github_env(text)

    def test_later_steps_see_exported_variables_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            tools = work / "tools"
            tools.mkdir()
            (tools / "hello").write_text("#!/bin/sh\necho hello from tools\n", "utf-8")
            (tools / "hello").chmod(0o755)
            state = ci_local.JobState(
                work=work, environment=ci_local.base_environment(work), checkout=work
            )
            first = work / "first.log"
            second = work / "second.log"
            code = ci_local.run_step(
                state,
                {
                    "run": f'echo "GREETING=hi" >> "$GITHUB_ENV"\n'
                    f'echo "{tools}" >> "$GITHUB_PATH"\n'
                },
                first,
                60,
            )
            self.assertEqual(0, code)
            code = ci_local.run_step(
                state,
                {
                    "run": 'echo "$GREETING $STEP"\nhello\nfalse\necho unreachable\n',
                    "env": {"STEP": "two"},
                },
                second,
                60,
            )
            self.assertEqual(1, code)
            self.assertEqual("hi two\nhello from tools\n", second.read_text("utf-8"))
            self.assertEqual(str(work / "home"), state.environment["HOME"])

    def test_usage(self) -> None:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(0, ci_local.main(["--help"]))
            self.assertEqual(2, ci_local.main(["--bogus"]))
        self.assertTrue(output.getvalue().startswith("Usage: scripts/ci-local"))
        self.assertIn("error: invalid arguments", error.getvalue())
        launcher = ROOT / "scripts" / "ci-local"
        self.assertTrue(launcher.stat().st_mode & 0o111)
        shown = subprocess.run(
            [sys.executable, str(launcher), "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual((0, ci_local.USAGE + "\n"), (shown.returncode, shown.stdout))


if __name__ == "__main__":
    unittest.main()
