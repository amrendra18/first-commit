import os
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text("utf-8"))[
    "jobs"
]["test"]["strategy"]["matrix"]["python"]
SETUP_PINS = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"][
    "optional-dependencies"
]["setup"]
STUB = "#!/bin/sh\nexit 0\n"
INTERPRETER = """#!/bin/bash
printf '%s\\n' "$*" >> "{log}"
case "$1 $2 $3" in
  '-m venv '*)
    mkdir -p "$3/bin"
    ln -s "{self}" "$3/bin/python"
    ln -s "{self}" "$3/bin/python3"
    exit 0
    ;;
  '-m pip check') exit {pip_check} ;;
  '-m pip install')
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == -r ]]; then
        cat "$2" >> "{log}.pins"
      fi
      shift
    done
    exit 0
    ;;
esac
if [[ "$1" == -c ]]; then
  exec "{real}" "$@"
fi
exit 0
"""


class CheckMatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.project = self.folder / "project"
        self.pythons = self.folder / "pythons"
        self.pythons.mkdir()
        self.log = self.folder / "calls.log"
        files = {
            "scripts/check": (ROOT / "scripts/check").read_text("utf-8"),
            "pyproject.toml": (ROOT / "pyproject.toml").read_text("utf-8"),
            "scripts/lint": STUB,
            "scripts/check-package": STUB,
            "bin/first-commit": STUB,
        }
        for name, content in files.items():
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            path.chmod(0o755)

    def add_interpreters(self, pip_check: int, folder: Path | None = None) -> None:
        for version in VERSIONS:
            path = (folder or self.pythons / f"cpython-{version}.0-test/bin") / (
                f"python{version}"
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                INTERPRETER.format(
                    log=self.log, self=path, pip_check=pip_check, real=sys.executable
                ),
                encoding="utf-8",
            )
            path.chmod(0o755)

    def sealed_path(self) -> Path:
        tools = self.folder / "tools"
        tools.mkdir()
        for name in ("cat", "date", "dirname", "ln", "mkdir", "mktemp", "rm", "uname"):
            found = shutil.which(name)
            if found is None:
                self.fail(f"{name} is not on PATH")
            (tools / name).symlink_to(found)
        return tools

    def matrix(
        self, path: Path | None = None
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in {"VIRTUAL_ENV", "PRE_COMMIT", "FIRST_COMMIT_PYTHONS"}
        }
        if path is None:
            environment.update(
                FIRST_COMMIT_PYTHONS=str(self.pythons), PATH="/usr/bin:/bin"
            )
        else:
            environment.update(PATH=str(path))
        result = subprocess.run(
            [str(self.project / "scripts/check"), "matrix"],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        summaries = list(self.project.glob(".local/check-matrix/*/summary.md"))
        self.assertEqual(1, len(summaries), result.stdout + result.stderr)
        evidence = summaries[0].parent.relative_to(self.project)
        self.assertEqual(f"evidence: {evidence}/", result.stdout.splitlines()[-2])
        return result, summaries[0].read_text("utf-8").splitlines()

    def test_matrix_versions_match_ci(self) -> None:
        self.assertIn(
            f"matrix_versions='{' '.join(VERSIONS)}'",
            (ROOT / "scripts/check").read_text("utf-8").splitlines(),
        )

    def test_missing_pythons_fail_and_are_recorded(self) -> None:
        result, summary = self.matrix()
        missing = [
            f"matrix: Python {version}: missing (no {self.pythons}/cpython-{version}.*)"
            for version in VERSIONS
        ]
        self.assertEqual((1, ""), (result.returncode, result.stderr))
        self.assertEqual(missing, result.stdout.splitlines()[:-2])
        self.assertEqual("matrix: exit 1", result.stdout.splitlines()[-1])
        self.assertEqual("# scripts/check matrix", summary[0])
        self.assertIn("- HEAD: unknown (not a Git work tree) (dirty: unknown)", summary)
        self.assertIn("- exit: 1", summary)
        self.assertTrue(any(line.startswith("- platform: ") for line in summary))
        self.assertEqual([f"- {line}" for line in missing], summary[-len(missing) :])

    def test_each_python_checks_the_hook_pins_without_dependencies(self) -> None:
        self.add_interpreters(pip_check=0)
        result, summary = self.matrix()
        self.assertEqual((0, ""), (result.returncode, result.stderr))
        calls = self.log.read_text("utf-8").splitlines()
        installs = [call for call in calls if "--no-deps" in call]
        self.assertEqual(len(VERSIONS), len(installs))
        self.assertEqual(len(VERSIONS), calls.count("-m pip check"))
        for install in installs:
            self.assertTrue(install.startswith("-m pip install"))
        pins = self.log.with_name("calls.log.pins").read_text("utf-8").splitlines()
        self.assertEqual(SETUP_PINS * len(VERSIONS), pins)
        self.assertIn("- exit: 0", summary)
        for version in VERSIONS:
            interpreter = self.pythons / f"cpython-{version}.0-test/bin/python{version}"
            for line in (
                f"matrix: Python {version}: {interpreter} ({platform.python_version()})",
                f"matrix: Python {version}: pinned hook dependencies (pip check): exit 0",
                f"matrix: Python {version}: scripts/check full: exit 0",
            ):
                self.assertIn(line, result.stdout.splitlines())
                self.assertIn(f"- {line}", summary)

    def test_without_the_variable_a_missing_python_names_path_and_the_variable(
        self,
    ) -> None:
        result, summary = self.matrix(self.sealed_path())
        missing = [
            f"matrix: Python {version}: missing (no python{version} on PATH; install "
            "it, or set FIRST_COMMIT_PYTHONS to a folder of cpython-<version>.* builds)"
            for version in VERSIONS
        ]
        self.assertEqual((1, ""), (result.returncode, result.stderr))
        self.assertEqual(missing, result.stdout.splitlines()[:-2])
        self.assertEqual([f"- {line}" for line in missing], summary[-len(missing) :])

    def test_without_the_variable_each_python_comes_from_path(self) -> None:
        tools = self.sealed_path()
        self.add_interpreters(pip_check=0, folder=tools)
        result, summary = self.matrix(tools)
        self.assertEqual((0, ""), (result.returncode, result.stderr))
        self.assertIn("- exit: 0", summary)
        for version in VERSIONS:
            for line in (
                (
                    f"matrix: Python {version}: {tools / f'python{version}'} "
                    f"({platform.python_version()})"
                ),
                f"matrix: Python {version}: scripts/check full: exit 0",
            ):
                self.assertIn(line, result.stdout.splitlines())

    def test_help_names_path_and_the_variable_without_a_private_folder(self) -> None:
        output = subprocess.run(
            [str(self.project / "scripts/check"), "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout
        self.assertIn("python3.11 to python3.14 on PATH", " ".join(output.split()))
        self.assertNotIn(".local/uv-python", output)

    def test_an_incomplete_pin_list_fails_the_matrix(self) -> None:
        self.add_interpreters(pip_check=1)
        result, summary = self.matrix()
        self.assertEqual(1, result.returncode)
        line = f"matrix: Python {VERSIONS[0]}: pinned hook dependencies (pip check): exit 1"
        self.assertIn(line, result.stdout.splitlines())
        self.assertIn(f"- {line}", summary)
        self.assertIn("- exit: 1", summary)


if __name__ == "__main__":
    unittest.main()
