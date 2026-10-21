import importlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SYSTEM_PYTHON = Path("/usr/bin/python3")


def harness_python() -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module("verify_lib.interpreter")


interpreter = harness_python()


def _older(python: Path) -> bool:
    if not os.access(python, os.X_OK):
        return False
    result = subprocess.run(
        [str(python), "-c", "import sys; sys.exit(sys.version_info >= (3, 11))"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    return result.returncode == 0


class HarnessPythonTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        self.old = self.project / "old-python"
        self.old.write_text("#!/bin/sh\nexit 1\n", "utf-8")
        self.old.chmod(0o755)
        self.enterContext(patch.object(interpreter, "PROJECT", self.project))
        self.enterContext(patch.object(interpreter, "_running", return_value=(3, 9, 6)))
        self.rerun = self.enterContext(
            patch.object(interpreter, "run_under", return_value=0)
        )

    def require(self, environment: dict[str, str]) -> int | None:
        with patch.dict(os.environ, environment, clear=True):
            try:
                interpreter.require_supported(Path("scripts/verify"), ["full"])
            except SystemExit as stopped:
                return int(stopped.code or 0)
        return None

    def test_a_supported_python_runs_the_harness_itself(self) -> None:
        with patch.object(interpreter, "_running", return_value=(3, 11, 0)):
            self.assertIsNone(self.require({}))
        self.rerun.assert_not_called()

    def test_an_older_python_re_runs_under_the_named_python_first(self) -> None:
        venv = self.project / ".venv/bin/python"
        venv.parent.mkdir(parents=True)
        venv.symlink_to(sys.executable)
        self.rerun.return_value = 1
        self.assertEqual(
            1, self.require({"FIRST_COMMIT_VERIFY_PYTHON": sys.executable})
        )
        self.rerun.assert_called_once_with(
            sys.executable, Path("scripts/verify"), ["full"]
        )

    def test_an_older_named_python_exits_3_without_falling_back(self) -> None:
        venv = self.project / ".venv/bin/python"
        venv.parent.mkdir(parents=True)
        venv.symlink_to(sys.executable)
        error = io.StringIO()
        with redirect_stderr(error):
            code = self.require({"FIRST_COMMIT_VERIFY_PYTHON": str(self.old)})
        self.assertEqual(3, code)
        self.rerun.assert_not_called()
        text = error.getvalue()
        self.assertIn(f"FIRST_COMMIT_VERIFY_PYTHON names {self.old}", text)
        self.assertIn("\nwhy: ", text)
        self.assertIn("\nfix: ", text)

    def test_without_a_named_python_the_project_environment_is_used(self) -> None:
        venv = self.project / ".venv/bin/python"
        venv.parent.mkdir(parents=True)
        venv.symlink_to(sys.executable)
        self.assertEqual(0, self.require({}))
        self.rerun.assert_called_once_with(str(venv), Path("scripts/verify"), ["full"])

    def test_no_supported_python_exits_3_with_what_why_and_fix(self) -> None:
        error = io.StringIO()
        with redirect_stderr(error):
            code = self.require({})
        self.assertEqual(3, code)
        self.rerun.assert_not_called()
        text = error.getvalue()
        self.assertTrue(text.startswith("error: scripts/verify needs Python 3.11"))
        self.assertIn("3.9.6", text)
        self.assertIn("\nwhy: ", text)
        self.assertIn(str(self.project / ".venv/bin/python"), text)
        self.assertIn("\nfix: ", text)


class HandlingSignalsTest(unittest.TestCase):
    def test_the_previous_handler_returns_even_after_an_error(self) -> None:
        before = signal.getsignal(signal.SIGHUP)
        inside = None
        with (
            self.assertRaises(ValueError),
            interpreter.handling_signals((signal.SIGHUP,), signal.SIG_IGN),
        ):
            inside = signal.getsignal(signal.SIGHUP)
            raise ValueError
        self.assertEqual(
            (signal.SIG_IGN, before), (inside, signal.getsignal(signal.SIGHUP))
        )


CHILD = """
import signal, sys, time


def stop(number, _frame):
    open("{folder}/received", "w").write(str(number))
    sys.exit(128 + number)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGHUP, stop)
print("ready", flush=True)
time.sleep(30)
"""
WRAPPER = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(ROOT / "scripts")!r})
from verify_lib import interpreter
raise SystemExit(interpreter.run_under(sys.executable, Path("{{folder}}/child.py"), []))
"""


class RunUnderTest(unittest.TestCase):
    def test_a_child_killed_by_a_signal_exits_128_plus_the_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "killed.py"
            script.write_text(
                "import os, signal\nos.kill(os.getpid(), signal.SIGTERM)\n", "utf-8"
            )
            code = interpreter.run_under(sys.executable, script, [])
        self.assertEqual(128 + signal.SIGTERM, code)

    def test_sigterm_and_sighup_to_the_wrapper_reach_the_child(self) -> None:
        for number in (signal.SIGTERM, signal.SIGHUP):
            with (
                self.subTest(signal=number.name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                folder = Path(temporary)
                (folder / "child.py").write_text(CHILD.format(folder=folder), "utf-8")
                wrapper = self.enterContext(
                    subprocess.Popen(
                        [sys.executable, "-c", WRAPPER.format(folder=folder)],
                        stdout=subprocess.PIPE,
                        text=True,
                    )
                )
                self.addCleanup(wrapper.kill)
                self.assertEqual(
                    "ready\n", wrapper.stdout.readline() if wrapper.stdout else ""
                )
                wrapper.send_signal(number)
                self.assertEqual(128 + number, wrapper.wait(timeout=30))
                self.assertEqual(
                    str(int(number)), (folder / "received").read_text("utf-8")
                )

    def test_a_second_ctrl_c_sends_sigterm_to_the_child(self) -> None:
        child = MagicMock()
        child.__enter__.return_value = child
        child.wait.side_effect = [KeyboardInterrupt, KeyboardInterrupt, -signal.SIGTERM]
        with patch.object(interpreter.subprocess, "Popen", return_value=child):
            code = interpreter.run_under("python", Path("scripts/verify"), ["full"])
        self.assertEqual(128 + signal.SIGTERM, code)
        child.send_signal.assert_called_once_with(signal.SIGTERM)

    def test_one_ctrl_c_lets_the_child_finish_its_cleanup(self) -> None:
        child = MagicMock()
        child.__enter__.return_value = child
        child.wait.side_effect = [KeyboardInterrupt, 1]
        with patch.object(interpreter.subprocess, "Popen", return_value=child):
            code = interpreter.run_under("python", Path("scripts/verify"), [])
        self.assertEqual(1, code)
        child.send_signal.assert_not_called()

    @unittest.skipUnless(_older(SYSTEM_PYTHON), "no python3 older than 3.11 here")
    def test_the_entry_points_re_run_from_an_older_system_python(self) -> None:
        environment = dict(os.environ, FIRST_COMMIT_VERIFY_PYTHON=sys.executable)
        for script in ("verify", "ci-local"):
            with self.subTest(script=script):
                shown = subprocess.run(
                    [str(SYSTEM_PYTHON), str(ROOT / "scripts" / script), "--help"],
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(0, shown.returncode, shown.stderr)
                self.assertTrue(shown.stdout.startswith(f"Usage: scripts/{script}"))


if __name__ == "__main__":
    unittest.main()
