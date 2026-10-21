import io
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import __version__
from tests.cli_support import PROJECT


class CliLauncherTest(unittest.TestCase):
    def test_module_entry_points_execute_main(self) -> None:
        for module in ("first_commit",):
            with self.subTest(module=module):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    patch.object(sys, "argv", [module, "version"]),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                    self.assertRaises(SystemExit) as error,
                ):
                    runpy.run_module(module, run_name="__main__", alter_sys=True)
                self.assertEqual(0, error.exception.code)
                self.assertEqual(__version__, stdout.getvalue().strip())
                self.assertEqual("", stderr.getvalue())

    def checkout_launcher(self, root: Path) -> Path:
        (root / "bin").mkdir()
        launcher = root / "bin" / "first-commit"
        launcher.write_bytes((PROJECT / "bin" / "first-commit").read_bytes())
        launcher.chmod(0o755)
        return launcher

    def stub_python(self, path: Path, version: str, name: str) -> None:
        old = tuple(map(int, version.split("."))) < (3, 11)
        path.parent.mkdir(parents=True)
        path.write_text(
            "#!/bin/bash\n"
            f'if [[ "$1" == -c ]]; then echo {version}; exit {int(old)}; fi\n'
            f'printf \'%s\\n\' "$PYTHONPATH" "$PATH" "$*" \'{name}\'\n',
            encoding="utf-8",
        )
        path.chmod(0o755)

    def test_checkout_launcher_runs_and_selects_environment(self) -> None:
        result = subprocess.run(
            [str(PROJECT / "bin" / "first-commit"), "version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual((0, __version__), (result.returncode, result.stdout.strip()))
        for active in (False, True):
            with (
                self.subTest(active=active),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                launcher = self.checkout_launcher(root)
                for name in (".venv", "active"):
                    self.stub_python(root / name / "bin" / "python", "3.13.0", name)
                environment = os.environ.copy()
                environment.pop("VIRTUAL_ENV", None)
                environment["PATH"] = "/usr/bin:/bin"
                if active:
                    environment["VIRTUAL_ENV"] = str(root / "active")
                result = subprocess.run(
                    [str(launcher), "version"],
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                lines = result.stdout.splitlines()
                self.assertEqual(str(root / "src"), lines[0])
                self.assertTrue(
                    lines[1].startswith(str(root / ".local" / "bin") + os.pathsep)
                )
                self.assertEqual("-m first_commit.cli version", lines[2])
                self.assertEqual("active" if active else ".venv", lines[3])

    def test_checkout_launcher_refuses_python_older_than_3_11(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = self.checkout_launcher(root)
            self.stub_python(root / "tools" / "python3", "3.9.6", "python3")
            environment = os.environ.copy()
            environment.pop("VIRTUAL_ENV", None)
            environment["PATH"] = f"{root / 'tools'}{os.pathsep}/usr/bin:/bin"
            result = subprocess.run(
                [str(launcher), "version"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual((3, ""), (result.returncode, result.stdout))
        self.assertEqual(
            [
                (
                    "error: bin/first-commit needs Python 3.11 or newer; "
                    "this is Python 3.9.6 (python3)."
                ),
                (
                    "why: it runs $VIRTUAL_ENV/bin/python, else .venv/bin/python, "
                    "else python3 from PATH."
                ),
                (
                    "fix: create the project environment with "
                    "`python3.13 -m venv .venv` and "
                    "`.venv/bin/python -m pip install -e '.[test]'`, "
                    "or activate a virtual environment with Python 3.11 or newer."
                ),
            ],
            result.stderr.splitlines(),
        )


if __name__ == "__main__":
    unittest.main()
