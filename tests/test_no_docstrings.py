import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = ("src", "scripts", "tests")
DOCUMENTED = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
PYTHON_SHEBANG = re.compile(rb"#!.*\bpython[0-9.]*(?:\s|$)")


def runs_python(first_line: bytes) -> bool:
    return PYTHON_SHEBANG.match(first_line) is not None


def python_files() -> list[Path]:
    found = []
    for folder in FOLDERS:
        for path in sorted((ROOT / folder).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix == ".py" or (
                not path.suffix and runs_python(path.read_bytes().split(b"\n", 1)[0])
            ):
                found.append(path)
    return found


def _starts_with_text(node: ast.AST) -> bool:
    body = getattr(node, "body", [])
    return (
        bool(body)
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    )


def docstring_lines(source: str) -> list[int]:
    return [
        node.body[0].lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, DOCUMENTED) and _starts_with_text(node)
    ]


class NoDocstringTest(unittest.TestCase):
    def test_no_python_file_has_a_docstring(self) -> None:
        files = python_files()
        self.assertGreater(len(files), 100)
        self.assertIn(ROOT / "scripts" / "verify", files)
        found = [
            f"{path.relative_to(ROOT)}:{line}"
            for path in files
            for line in docstring_lines(path.read_text("utf-8"))
        ]
        self.assertEqual([], found)

    def test_a_docstring_is_found_in_a_module_class_and_function(self) -> None:
        for source, lines in (
            ('"""Module."""\n', [1]),
            ('class A:\n    """Class."""\n', [2]),
            ('def f():\n    """Function."""\n', [2]),
            ('async def f():\n    """Coroutine."""\n', [2]),
            ("def f():\n    # A comment.\n    return 1\n", []),
            ("def f():\n    return 'text'\n", []),
            ('""""""\n', [1]),
            ("def f():\n    ''\n", [2]),
            ("def f():\n    b'bytes'\n", []),
        ):
            with self.subTest(source=source):
                self.assertEqual(lines, docstring_lines(source))

    def test_a_script_counts_as_python_by_any_shebang_that_runs_python(self) -> None:
        for first_line, expected in (
            (b"#!/usr/bin/env python3\n", True),
            (b"#!/usr/bin/env python\n", True),
            (b"#!/usr/bin/python3\n", True),
            (b"#!/usr/bin/python3.13 -I\n", True),
            (b"#!/usr/bin/env -S python3 -I\n", True),
            (b"#! /opt/venv/bin/python\n", True),
            (b"#!/bin/sh\n", False),
            (b"#!/usr/bin/env bash\n", False),
            (b"#!/usr/bin/env pythonic-tool\n", False),
            (b"import os\n", False),
        ):
            with self.subTest(first_line=first_line):
                self.assertEqual(expected, runs_python(first_line))


if __name__ == "__main__":
    unittest.main()
