import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import patch

from tests.test_verify_script import ROOT, harness

cli = harness("cli")
core = harness("core")
first_run = harness("first_run")
prepare = harness("prepare")
CHILD = f"""
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, {str(ROOT / "scripts")!r})
from verify_lib import cli, prepare, report


def wait(run):
    print("work", run.work, flush=True)
    print("agent", run.environment["SSH_AGENT_PID"], flush=True)
    script = 'sleep 60 & echo $! > "$1"; wait'
    run.command(["/bin/sh", "-c", script, "sh", sys.argv[1]], run.work)
    return []


with (
    patch.object(prepare, "check_prerequisites", return_value=[]),
    patch.object(cli, "snapshot"),
    patch.dict(cli.RUNNERS, {{"setup": wait}}),
    patch.object(report, "PROJECT", Path(sys.argv[2])),
):
    raise SystemExit(cli.main(["--feature", "setup"]))
"""
STOP_SECONDS = 30
# Git and ssh-agent stay reachable; no folder here holds first-commit.
SEARCH_PATH: tuple[str, list[str]] = ("/usr/bin:/bin", [])


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class StoppedRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gone: set[int] = set()

    # A process id proven gone may already name another process.
    def stop_later(self, pid: int) -> None:
        def stop() -> None:
            if pid not in self.gone and _alive(pid):
                os.kill(pid, signal.SIGTERM)

        self.addCleanup(stop)

    def gone_within(self, pid: int, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while _alive(pid):
            if time.monotonic() > deadline:
                return False
            time.sleep(0.1)
        self.gone.add(pid)
        return True

    def stopped_run(self, number: signal.Signals) -> tuple[int, str, Path, int, int]:
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        started = folder / "started"
        evidence = folder / "project"
        child = subprocess.Popen(
            [sys.executable, "-c", CHILD, started, evidence],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(child.kill)
        lines = {}
        for line in child.stdout or ():
            name, _, value = line.rstrip("\n").partition(" ")
            lines[name] = value
            if name == "agent":
                break
        work, agent = Path(lines["work"]), int(lines["agent"])
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        self.stop_later(agent)
        deadline = time.monotonic() + STOP_SECONDS
        while not (started.exists() and started.read_text("utf-8").strip()):
            self.assertLess(time.monotonic(), deadline, "the command never started")
            time.sleep(0.1)
        sleeper = int(started.read_text("utf-8"))
        self.stop_later(sleeper)
        child.send_signal(number)
        _, error = child.communicate(timeout=STOP_SECONDS)
        return child.returncode, error, work, agent, sleeper

    def test_a_signal_removes_the_work_folder_and_stops_every_process(self) -> None:
        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number.name):
                code, error, work, agent, sleeper = self.stopped_run(number)
                self.assertFalse(work.exists(), f"{work} was left")
                self.assertTrue(
                    self.gone_within(agent, 5), f"ssh-agent {agent} still runs"
                )
                self.assertTrue(
                    self.gone_within(sleeper, 5), f"command child {sleeper} runs"
                )
                self.assertEqual(128 + number, code, error)
                self.assertIn(
                    f"harness: stopped by {number.name}; the temporary folder was "
                    "removed and its SSH agent stopped",
                    error,
                )

    def test_a_signal_during_cleanup_does_not_stop_the_cleanup(self) -> None:
        def signal_self(_environment: object) -> None:
            os.kill(os.getpid(), signal.SIGTERM)

        with (
            patch.object(prepare, "stop_agent", side_effect=signal_self) as stop,
            cli.stop_on_signals(),
            prepare.private_run(sys.executable, SEARCH_PATH) as run,
        ):
            work = run.work
        stop.assert_called_once()
        self.assertFalse(work.exists(), f"{work} was left")

    def test_an_agent_started_just_before_a_signal_is_stopped(self) -> None:
        real = core.Run.command
        agents: list[int] = []

        def signal_after_agent(
            run: object, args: Sequence[str | Path], *rest: object, **named: object
        ) -> tuple[int, str]:
            code, output = real(run, args, *rest, **named)
            if not any("ssh-agent" in str(item) for item in args):
                return code, output
            printed = [output] + [
                Path(item).read_text("utf-8")
                for item in args
                if isinstance(item, Path) and item.is_file()
            ]
            for pid in re.findall(r"SSH_AGENT_PID=(\d+);", "".join(printed)):
                agents.append(int(pid))
                self.stop_later(int(pid))
            raise cli.StoppedError(signal.SIGTERM)

        with (
            patch.object(core.Run, "command", signal_after_agent),
            self.assertRaises(cli.StoppedError),
            cli.stop_on_signals(),
            prepare.private_run(sys.executable, SEARCH_PATH) as run,
        ):
            work = run.work
            prepare.start_agent(run)
        self.assertEqual(1, len(agents))
        self.assertTrue(self.gone_within(agents[0], 5), "ssh-agent still runs")
        self.assertFalse(work.exists(), f"{work} was left")

    def test_a_stopped_terminal_journey_kills_its_command(self) -> None:
        started: list[subprocess.Popen[bytes]] = []

        def stop(_primary, process, _pending):
            started.append(process)
            raise KeyboardInterrupt

        run = core.Run(work=ROOT, python=sys.executable, environment={})
        with (
            patch.object(first_run, "_read_until_exit", side_effect=stop),
            self.assertRaises(KeyboardInterrupt),
        ):
            first_run.terminal(
                run, ["sleep", "30"], ROOT, {"PATH": "/usr/bin:/bin"}, ()
            )
        self.assertIsNotNone(started[0].poll())


if __name__ == "__main__":
    unittest.main()
