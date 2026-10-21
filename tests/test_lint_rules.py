import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "pyproject.toml"
BRANCHES = "".join(
    f"    if value == {number}:\n        return {number}\n" for number in range(1, 11)
)
RUFF_FIXTURE = f'''from typing import Any


def six_arguments(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    return a + b + c + d + e + f


def evaluate(text: str) -> Any:
    return eval(text)


LONG = "{"x" * 93}"


def eleven_paths(value: int) -> int:
{BRANCHES}    return 0


class Box:
    _hidden = 1


def peek(box: Box) -> int:
    return box._hidden
'''
RUFF_CODES = {
    "ANN401": "select names ANN401",
    "C901": "mccabe max-complexity 10",
    "E501": "pycodestyle max-line-length 100",
    "PLR0913": "pylint max-args 5",
    "S307": "select names S",
    "SLF001": "select names SLF001",
}
MYPY_FIXTURE = """def untyped(value):
    return value


def narrowed(value: int) -> int:
    if isinstance(value, int):
        return value
    return 0
"""
MYPY_CODES = {"no-untyped-def": "strict", "unreachable": "warn_unreachable"}
REPEATED = "".join(f"total_{n} = {n} * 3 + 1\n" for n in range(8))
PYLINT_FIXTURES = {
    "__init__.py": "",
    "first.py": "from fixture import second\n\nVALUE = 1\n",
    "second.py": "from fixture import first\n\nOTHER = 2\n",
    "copy_one.py": REPEATED,
    "copy_two.py": REPEATED,
    "long.py": "".join(f"line_{n} = {n}\n" for n in range(501)),
    "shadow.py": "def name() -> int:\n    return 1\n\n\ndef use() -> int:\n"
    "    name = 2\n    return name\n",
}
PYLINT_SYMBOLS = {
    "cyclic-import",
    "duplicate-code",
    "redefined-outer-name",
    "too-many-lines",
}
# The fixtures sample the rules; these copies catch any other rule or limit removed.
RUFF_SETTINGS = {
    "target-version": "py311",
    "line-length": 88,
    "lint": {
        "preview": True,
        "explicit-preview-rules": True,
        "select": [
            *("A", "ANN401", "ARG", "ASYNC", "B", "BLE", "C4", "C90", "DTZ", "E"),
            *("ERA", "EXE", "F", "FBT", "FLY", "FURB", "G", "I", "INP", "ISC003"),
            *("ISC004", "LOG", "N", "PERF", "PGH", "PIE", "PL", "PTH", "PYI", "RET"),
            *("RSE", "RUF", "S", "SIM", "SLF001", "SLOT", "T10", "TID", "TRY300"),
            *("TRY301", "UP", "W", "YTT"),
            *("B909", "PLR0914", "PLR0916", "PLW0717", "RUF031"),
        ],
        "ignore": ["PLC0415", "S603", "S607", "SIM117"],
        "pycodestyle": {"max-line-length": 100},
        "mccabe": {"max-complexity": 10},
        "pylint": {"max-args": 5, "max-bool-expr": 7, "max-statements": 40},
    },
}
MYPY_SETTINGS = {
    "python_version": "3.11",
    "mypy_path": "scripts",
    "strict": True,
    "warn_unreachable": True,
    "enable_error_code": ["ignore-without-code", "redundant-expr", "truthy-bool"],
    "overrides": [
        {
            "module": ["tests", "tests.*"],
            "disallow_untyped_defs": False,
            "disallow_incomplete_defs": False,
            "disallow_untyped_calls": False,
        }
    ],
}
PYLINT_SETTINGS = {
    "main": {"disable": ["all"], "enable": sorted(PYLINT_SYMBOLS)},
    "format": {"max-module-lines": 500},
    "similarities": {"min-similarity-lines": 6},
}

LINT_SCRIPT = ROOT / "scripts/lint"
# SC2155 is on by default; SC2312 only with the check-extra-masked-returns option.
SHELL_FIXTURE = """#!/bin/bash
show() {
  local value=$(false)
  echo "$value $(false)"
}
show
"""
SHELL_CODES = {2155: "local x=$(...) masks the exit code", 2312: "the -o option"}
UNFORMATTED = "values = [1,2,  3]\n"
FORMATTED = "values = [1, 2, 3]\n"


class LintRulesTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def tool(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", *arguments],
            cwd=self.folder,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    def test_the_configured_rules_and_limits_are_exactly_these(self) -> None:
        with CONFIG.open("rb") as file:
            tools = tomllib.load(file)["tool"]
        for name, expected in (
            ("ruff", RUFF_SETTINGS),
            ("mypy", MYPY_SETTINGS),
            ("pylint", PYLINT_SETTINGS),
        ):
            with self.subTest(tool=name):
                self.assertEqual(expected, tools[name])

    def test_ruff_reports_each_configured_rule_and_limit(self) -> None:
        (self.folder / "rules.py").write_text(RUFF_FIXTURE, "utf-8")
        result = self.tool(
            "ruff",
            "check",
            "--config",
            str(CONFIG),
            "--no-cache",
            "--output-format",
            "json",
            "rules.py",
        )
        self.assertEqual(1, result.returncode, result.stderr)
        reported = {finding["code"] for finding in json.loads(result.stdout)}
        missing = sorted(set(RUFF_CODES) - reported)
        self.assertEqual([], [RUFF_CODES[code] for code in missing])

    def test_mypy_reports_strict_and_unreachable_code(self) -> None:
        (self.folder / "typed.py").write_text(MYPY_FIXTURE, "utf-8")
        result = self.tool(
            "mypy",
            "--config-file",
            str(CONFIG),
            "--cache-dir",
            str(self.folder / "cache"),
            "typed.py",
        )
        self.assertEqual(1, result.returncode, result.stderr)
        reported = {
            line.rsplit("[", 1)[1].rstrip("]")
            for line in result.stdout.splitlines()
            if ": error: " in line
        }
        missing = sorted(set(MYPY_CODES) - reported)
        self.assertEqual([], [MYPY_CODES[code] for code in missing])

    def test_pylint_reports_cycles_copies_shadows_and_long_modules(self) -> None:
        package = self.folder / "fixture"
        package.mkdir()
        for name, text in PYLINT_FIXTURES.items():
            (package / name).write_text(text, "utf-8")
        result = self.tool(
            "pylint",
            "--rcfile",
            str(CONFIG),
            "--persistent=n",
            "--output-format=json",
            "fixture",
        )
        self.assertNotEqual(0, result.returncode, result.stderr)
        reported = {message["symbol"] for message in json.loads(result.stdout)}
        self.assertEqual([], sorted(PYLINT_SYMBOLS - reported))

    def lint_command(self, start: str) -> list[str]:
        lines = LINT_SCRIPT.read_text("utf-8").splitlines()
        found = [line for line in lines if line.strip().startswith(start)]
        self.assertEqual(1, len(found), f"scripts/lint lines starting {start!r}")
        words = shlex.split(found[0])
        return words[: next(n for n, word in enumerate(words) if "${" in word)]

    def test_shellcheck_runs_as_scripts_lint_runs_it_and_reports_masked_exits(
        self,
    ) -> None:
        command = self.lint_command("shellcheck ")
        found = shutil.which(
            "shellcheck",
            path=f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        )
        self.assertIsNotNone(found, "install the test extra: it has shellcheck-py")
        (self.folder / "masked.sh").write_text(SHELL_FIXTURE, "utf-8")
        result = subprocess.run(
            [str(found), *command[1:], "--format", "json", "masked.sh"],
            cwd=self.folder,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        self.assertEqual(1, result.returncode, result.stderr)
        reported = {finding["code"] for finding in json.loads(result.stdout)}
        missing = sorted(set(SHELL_CODES) - reported)
        self.assertEqual([], [SHELL_CODES[code] for code in missing])

    def test_ruff_format_runs_as_scripts_lint_runs_it_and_fails_on_a_change(
        self,
    ) -> None:
        command = self.lint_command("python3 -m ruff format ")
        self.assertEqual(["python3", "-m", "ruff", "format", "--check"], command)
        for name, text, code in (
            ("unformatted.py", UNFORMATTED, 1),
            ("formatted.py", FORMATTED, 0),
        ):
            with self.subTest(file=name):
                (self.folder / name).write_text(text, "utf-8")
                result = self.tool(*command[2:], "--config", str(CONFIG), name)
                self.assertEqual(code, result.returncode, result.stdout)
                self.assertEqual(text, (self.folder / name).read_text("utf-8"))


if __name__ == "__main__":
    unittest.main()
