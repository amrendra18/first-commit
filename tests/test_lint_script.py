import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOGGING_TOOL = '#!/bin/bash\nprintf \'%s %s\\n\' "${0##*/}" "$*" >> "$LINT_LOG"\n'
PYTHON_PATHS = "src tests scripts/verify_lib"


def _scripts() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"python": [], "shell": []}
    for path in sorted([*(ROOT / "bin").iterdir(), *(ROOT / "scripts").iterdir()]):
        if path.is_file():
            first = path.read_text("utf-8").splitlines()[0]
            kind = "python" if first == "#!/usr/bin/env python3" else "shell"
            found[kind].append(path.relative_to(ROOT).as_posix())
    return found


class LintScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name)
        self.log = self.project / "lint.log"
        for name in ("bin", "scripts", "src", "tests", "scripts/verify_lib", "tools"):
            (self.project / name).mkdir(exist_ok=True)
        for path in [*(ROOT / "bin").iterdir(), *(ROOT / "scripts").iterdir()]:
            if path.is_file():
                self.write(path.relative_to(ROOT).as_posix(), path.read_text("utf-8"))
        for tool in ("python3", "shellcheck"):
            self.write(f"tools/{tool}", LOGGING_TOOL)

    def write(self, name: str, content: str) -> None:
        path = self.project / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def lint(self, *arguments: str) -> tuple[int, str, list[str]]:
        result = subprocess.run(
            [str(self.project / "scripts" / "lint"), *arguments],
            env={
                **os.environ,
                "LINT_LOG": str(self.log),
                "VIRTUAL_ENV": str(self.project),
                "PATH": f"{self.project / 'tools'}{os.pathsep}/usr/bin:/bin",
            },
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        calls = self.log.read_text("utf-8").splitlines() if self.log.exists() else []
        self.log.unlink(missing_ok=True)
        return result.returncode, result.stderr, calls

    def test_every_script_with_a_python_shebang_is_linted_and_type_checked(
        self,
    ) -> None:
        self.write("scripts/probe", "#!/usr/bin/env python3\nprint('probe')\n")
        found = _scripts()
        python = " ".join(sorted([*found["python"], "scripts/probe"]))
        shell = " ".join(found["shell"])
        self.assertEqual(
            {"scripts/check-coverage", "scripts/ci-local", "scripts/verify"},
            set(found["python"]),
        )
        self.assertEqual(
            (
                0,
                "",
                [
                    f"python3 -m ruff check {PYTHON_PATHS} {python}",
                    f"python3 -m ruff format --check {PYTHON_PATHS} {python}",
                    f"shellcheck -o check-extra-masked-returns {shell}",
                ],
            ),
            self.lint(),
        )
        self.assertEqual(
            (
                0,
                "",
                [
                    f"python3 -m mypy {PYTHON_PATHS}",
                    *(f"python3 -m mypy {script}" for script in python.split()),
                    f"python3 -m pylint src/first_commit tests scripts/verify_lib {python}",
                ],
            ),
            self.lint("types"),
        )

    def test_a_script_with_another_shebang_stops_lint(self) -> None:
        self.write("scripts/probe", "#!/bin/sh\necho probe\n")
        code, error, calls = self.lint()
        self.assertEqual((1, []), (code, calls))
        self.assertEqual(
            "error: scripts/probe has no #!/bin/bash or #!/usr/bin/env python3 line; "
            "scripts/lint checks only those.\n",
            error,
        )

    def test_a_syntax_error_in_any_shell_script_stops_lint(self) -> None:
        self.assertNotEqual("scripts/zz-broken", _scripts()["shell"][0])
        self.write("scripts/zz-broken", "#!/bin/bash\nif then\n")
        code, error, calls = self.lint()
        self.assertEqual((2, []), (code, calls))
        self.assertIn("scripts/zz-broken", error)

    def test_unknown_mode_fails(self) -> None:
        code, error, calls = self.lint("everything")
        self.assertEqual((2, []), (code, calls))
        self.assertTrue(
            error.startswith("error: unknown lint mode\nUsage: scripts/lint")
        )

    def test_pre_commit_hook_runs_lint_and_the_gate_adds_types(self) -> None:
        declared = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text("utf-8"))
        hooks = {
            hook["id"]: hook for repo in declared["repos"] for hook in repo["hooks"]
        }
        self.assertEqual("scripts/lint", hooks["project-lint"]["entry"])
        self.assertEqual(["pre-commit"], hooks["project-lint"]["stages"])
        self.assertEqual(["pre-push"], hooks["project-quality"]["stages"])
        self.assertEqual(
            ["first-commit-push", "project-quality", "project-journeys"],
            [name for name, hook in hooks.items() if "pre-push" in hook["stages"]],
        )
        lines = (ROOT / "scripts" / "check").read_text("utf-8").splitlines()
        self.assertEqual(1, lines.count("  bin/first-commit check"))
        lint = lines.index("scripts/lint")
        self.assertEqual("scripts/lint types", lines[lint + 1])
        project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
        mypy = project["tool"]["mypy"]
        self.assertTrue(mypy["strict"])
        self.assertNotIn("files", mypy)
        # Tests may leave helpers unannotated, but their bodies stay checked.
        tests = [entry for entry in mypy["overrides"] if "tests.*" in entry["module"]]
        self.assertEqual(1, len(tests))
        self.assertNotIn("check_untyped_defs", tests[0])

    def test_pre_push_runs_the_fast_journeys_after_the_gate(self) -> None:
        declared = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text("utf-8"))
        hooks = {
            hook["id"]: hook for repo in declared["repos"] for hook in repo["hooks"]
        }
        self.assertEqual(
            {
                "id": "project-journeys",
                "name": "first-commit journeys (scripts/verify fast) on the pushed commit",
                "entry": "scripts/check-pushed scripts/verify fast",
                "language": "system",
                "always_run": True,
                "pass_filenames": False,
                "stages": ["pre-push"],
            },
            hooks["project-journeys"],
        )
        shipped = (ROOT / ".pre-commit-hooks.yaml").read_text("utf-8")
        self.assertNotIn("scripts/verify", shipped)


if __name__ == "__main__":
    unittest.main()
