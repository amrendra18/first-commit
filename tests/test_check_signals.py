import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from tests.support import TemporaryRootTest, initialize_repository, run_git

SOURCE = Path(__file__).resolve().parents[1] / "src"
SLOW_SCANNER = """#!/bin/sh
for argument; do
  case $argument in --report-path=*) report=${argument#--report-path=} ;; esac
done
printf '[]' > "$report"
printf '%s\\n%s\\n' "${report%/*}" "$$" > "$0.started.tmp"
mv "$0.started.tmp" "$0.started"
exec sleep SECONDS
"""
CHILD = f"""
import signal
import sys
from unittest.mock import patch
sys.path.insert(0, {str(SOURCE)!r})
if sys.argv[3:] == ["ignore-hangup"]:
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
from first_commit import cli, gitleaks


def validated(_root, scanner):
    return gitleaks.Scanner(sys.argv[2], scanner.environment)


with patch.object(gitleaks, "_validated", validated):
    raise SystemExit(cli.main(["hook", "pre-commit", "--root", sys.argv[1]]))
"""
WAIT_SECONDS = 30


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class StoppedCheckTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        initialize_repository(self.repository)
        policy = self.repository / ".repo-policy.json"
        policy.write_text('{"schema_version":1}\n', encoding="utf-8")
        run_git(self.repository, "add", "--", ".repo-policy.json")
        self.scanner = self.root / "gitleaks"
        self.slow_scanner(20)
        temporary = self.root / "tmp"
        temporary.mkdir()
        self.environment = {**os.environ, "TMPDIR": str(temporary)}

    def slow_scanner(self, seconds: int) -> None:
        self.scanner.write_text(
            SLOW_SCANNER.replace("SECONDS", str(seconds)), encoding="utf-8"
        )
        self.scanner.chmod(0o700)

    def run_child(self, *options: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [sys.executable, "-c", CHILD, self.repository, self.scanner, *options],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
        )

    def started(self) -> tuple[Path, int]:
        marker = Path(f"{self.scanner}.started")
        deadline = time.monotonic() + WAIT_SECONDS
        while not marker.exists():
            if time.monotonic() > deadline:
                self.fail("The fake scanner did not start.")
            time.sleep(0.05)
        folder, pid = marker.read_text(encoding="utf-8").split()
        marker.unlink()
        return Path(folder), int(pid)

    def test_a_terminating_signal_removes_the_report_and_stops_gitleaks(self) -> None:
        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number.name):
                child = self.run_child()
                folder, pid = self.started()
                self.assertTrue((folder / "report.json").exists())
                child.send_signal(number)
                _, error = child.communicate(timeout=WAIT_SECONDS)
                self.assertEqual(1, child.returncode)
                self.assertEqual(
                    f"error: first-commit stopped on {number.name}.\n",
                    error.decode("utf-8"),
                )
                self.assertFalse(folder.exists())
                self.assertFalse(_alive(pid))

    def test_a_hangup_the_run_started_with_ignored_stays_ignored(self) -> None:
        self.slow_scanner(2)
        child = self.run_child("ignore-hangup")
        self.started()
        child.send_signal(signal.SIGHUP)
        output, error = child.communicate(timeout=WAIT_SECONDS)
        self.assertEqual("", error.decode("utf-8"))
        self.assertIn("policy finding(s)", output.decode("utf-8"))
