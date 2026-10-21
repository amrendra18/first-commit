import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _file(lines: tuple[int, int], branches: tuple[int, int]) -> dict[str, object]:
    return {
        "summary": {
            "covered_lines": lines[0],
            "num_statements": lines[1],
            "covered_branches": branches[0],
            "num_branches": branches[1],
        }
    }


SKIPPED_CHECK = (
    "first-commit check skipped (PRE_COMMIT=1); the first-commit-push hook runs it"
)


class CheckScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.script = Path(__file__).resolve().parents[1] / "scripts" / "check"
        self.package_script = (
            Path(__file__).resolve().parents[1] / "scripts" / "check-package"
        )
        self.coverage_script = (
            Path(__file__).resolve().parents[1] / "scripts" / "check-coverage"
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.report = Path(temporary.name) / "coverage.json"

    def run_coverage_gate(self, report: object) -> subprocess.CompletedProcess[str]:
        if isinstance(report, bytes):
            self.report.write_bytes(report)
        else:
            self.report.write_text(json.dumps(report), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(self.coverage_script), str(self.report)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_check_scripts_are_executable(self) -> None:
        self.assertTrue(self.script.stat().st_mode & 0o111)
        self.assertTrue(self.package_script.stat().st_mode & 0o111)
        self.assertTrue(self.coverage_script.stat().st_mode & 0o111)

    def test_check_runs_project_owned_per_file_coverage_gate(self) -> None:
        lines = self.script.read_text("utf-8").splitlines()
        run = lines.index("python3 -m coverage run -m unittest discover -s tests -q")
        export = lines.index(
            "python3 -m coverage json -q -o .local/coverage/coverage.json"
        )
        gate = lines.index(
            "python3 scripts/check-coverage .local/coverage/coverage.json"
        )
        report = lines.index("python3 -m coverage report")
        self.assertLess(run, export)
        self.assertLess(export, gate)
        self.assertLess(run, report)
        self.assertNotIn("lcov", self.script.read_text("utf-8"))

    def test_coverage_gate_passes_files_at_or_above_threshold(self) -> None:
        result = self.run_coverage_gate(
            {
                "files": {
                    "src/first_commit/exact.py": _file((9, 10), (9, 10)),
                    "src/first_commit/full.py": _file((5, 5), (2, 2)),
                    "src/first_commit/empty.py": _file((0, 0), (0, 0)),
                    "tests/helper.py": _file((0, 10), (0, 10)),
                }
            }
        )
        self.assertEqual((0, ""), (result.returncode, result.stderr))

    def test_coverage_gate_names_each_file_below_threshold(self) -> None:
        result = self.run_coverage_gate(
            {
                "files": {
                    "src/first_commit/lines.py": _file((899, 1000), (10, 10)),
                    "src/first_commit/branches.py": _file((10, 10), (8, 9)),
                    "src/first_commit/fine.py": _file((10, 10), (10, 10)),
                }
            }
        )
        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual(
            [
                "error: src/first_commit/branches.py branch coverage is below 90%",
                "error: src/first_commit/lines.py line coverage is below 90%",
            ],
            result.stderr.splitlines(),
        )

    def test_coverage_gate_rejects_unusable_reports_without_echoing_them(
        self,
    ) -> None:
        canary = "private-coverage-canary"
        bad_summary = {"covered_lines": canary, "num_statements": 1}
        cases: tuple[object, ...] = (
            b"\xff" + canary.encode(),
            b"{" + canary.encode(),
            [canary],
            {"files": []},
            {"files": {}},
            {"files": {"tests/" + canary + ".py": _file((1, 1), (1, 1))}},
            {"files": {"src/first_commit/a.py": {"summary": bad_summary}}},
            {"files": {"src/first_commit/a.py": _file((2, 1), (0, 0))}},
            {"files": {"src/first_commit/a.py": _file((-1, 1), (0, 0))}},
            {"files": {"src/first_commit/a.py": _file((True, 1), (0, 0))}},
            {"files": {"src/first_commit/a.py": canary}},
        )
        for report in cases:
            with self.subTest(report=report):
                result = self.run_coverage_gate(report)
                self.assertEqual(2, result.returncode)
                self.assertEqual(
                    "error: coverage report is missing or invalid\n", result.stderr
                )
                self.assertNotIn(canary, result.stdout + result.stderr)
        result = subprocess.run(
            [sys.executable, str(self.coverage_script)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("usage", result.stderr)
        missing = self.report.with_name("absent.json")
        result = subprocess.run(
            [sys.executable, str(self.coverage_script), str(missing)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertNotIn(str(missing), result.stderr)

    def test_help_documents_modes(self) -> None:
        result = subprocess.run(
            [str(self.script), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode)
        self.assertIn("scripts/check [fast|full|matrix]", result.stdout)
        self.assertIn("Run it before every commit.", result.stdout)
        self.assertNotIn("Agents", result.stdout)

    def test_a_pre_commit_hook_run_leaves_first_commit_check_to_its_push_hook(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            calls = project / "first-commit-calls"
            stub = "#!/bin/sh\nexit 0\n"
            files = {
                "scripts/check": self.script.read_text("utf-8"),
                "scripts/lint": stub,
                "scripts/check-package": stub,
                "scripts/release": stub,
                "tools/python3": stub,
                "bin/first-commit": f'#!/bin/sh\necho "$*" >> "{calls}"\n',
            }
            for name, content in files.items():
                path = project / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                path.chmod(0o755)
            runs = {}
            for marker in ("1", None):
                environment = {
                    key: value
                    for key, value in os.environ.items()
                    if key != "PRE_COMMIT"
                }
                environment.update(
                    VIRTUAL_ENV=directory,
                    PATH=f"{project / 'tools'}{os.pathsep}/usr/bin:/bin",
                )
                if marker is not None:
                    environment["PRE_COMMIT"] = marker
                result = subprocess.run(
                    [str(project / "scripts/check"), "fast"],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                runs[marker] = (
                    result.returncode,
                    calls.read_text("utf-8") if calls.exists() else "",
                    SKIPPED_CHECK in result.stdout.splitlines(),
                )
                calls.unlink(missing_ok=True)

        self.assertEqual({"1": (0, "", True), None: (0, "check\n", False)}, runs)

    def test_invalid_mode_fails(self) -> None:
        result = subprocess.run(
            [str(self.script), "unsupported"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)


if __name__ == "__main__":
    unittest.main()
