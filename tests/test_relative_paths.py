import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from first_commit.gitleaks_ignore_format import IgnoreFileError, parse_ignore
from first_commit.gitleaks_report import report_entries
from first_commit.paths import PathError, confined_path, relative_path_problem
from first_commit.policy import parse_policy
from first_commit.policy_fields import PolicyError

# The union of the values that at least one reader refused at a683a4e.
REFUSED = (
    "",
    ".",
    "..",
    "/absolute",
    "//absolute",
    "../outside",
    "nested/../outside",
    "~",
    "~/home-file",
    "~tilde-file",
    "back\\slash",
    "\\leading-backslash",
    "line\nbreak",
    "control\x01character",
    "delete\x7fcharacter",
    "double//slash",
    "dot/./part",
    "./leading-dot",
    "trailing/",
    "trailing/.",
)
ACCEPTED = ("value.txt", "nested/value.txt", ".hidden", "space name/value.txt")
OUTSIDE = ("", ".", "..", "/absolute", "//absolute", "../outside", "nested/../outside")
FILE_NAMES = ("~tilde-file", "back\\slash", "line\nbreak", "control\x01character")


def _ignore_content(path: str) -> bytes:
    digest = hashlib.sha256(b"synthetic\n").hexdigest()
    return (
        f"# reason: Synthetic fixture.\n# file-sha256: {digest}\n{path}:rule-id:1\n"
    ).encode()


class RelativePathRulesTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def _confined(self, value: str) -> bool:
        try:
            confined_path(self.root, value)
        except PathError:
            return False
        return True

    def _policy(self, value: str) -> bool:
        policy = {
            "schema_version": 1,
            "public_environment_files": [{"path": value, "reason": "Synthetic."}],
        }
        try:
            parse_policy(json.dumps(policy).encode(), self.root)
        except PolicyError:
            return False
        return True

    @staticmethod
    def _ignore_entry(value: str) -> bool:
        try:
            parse_ignore(_ignore_content(value))
        except IgnoreFileError:
            return False
        return True

    def _report(self, value: str) -> bool:
        report = self.root.parent / f"{self.root.name}-report.json"
        self.addCleanup(report.unlink, missing_ok=True)
        entry = {"RuleID": "rule-id", "File": value, "StartLine": 1}
        report.write_text(json.dumps([entry]), encoding="utf-8")
        return report_entries(self.root, report)[0].path == value

    def _readers(self) -> dict[str, Callable[[str], bool]]:
        return {
            "policy": self._policy,
            "gitleaksignore": self._ignore_entry,
            "report": self._report,
        }

    def test_problem_names_the_first_broken_rule(self) -> None:
        cases = {
            "": "names no file",
            ".": "names no file",
            "/absolute": "is absolute",
            "~tilde-file": "starts with '~'",
            "back\\slash": "holds a backslash",
            "control\x01character": "holds a control character",
            "double//slash": "is not in normal form",
            "nested/../outside": "has a '..' part",
        }
        for value, problem in cases.items():
            with self.subTest(value=value):
                self.assertEqual(problem, relative_path_problem(value))
        for value in REFUSED:
            with self.subTest(value=value):
                self.assertIsNotNone(relative_path_problem(value))
        for value in ACCEPTED:
            with self.subTest(value=value):
                self.assertIsNone(relative_path_problem(value))

    def test_every_reader_refuses_each_refused_value(self) -> None:
        for reader, accepts in self._readers().items():
            for value in REFUSED:
                with self.subTest(reader=reader, value=value):
                    self.assertFalse(accepts(value))

    def test_every_reader_accepts_each_normal_relative_value(self) -> None:
        for reader, accepts in self._readers().items():
            for value in ACCEPTED:
                with self.subTest(reader=reader, value=value):
                    self.assertTrue(accepts(value))

    def test_confined_path_refuses_only_values_outside_the_repository(self) -> None:
        for value in OUTSIDE:
            with self.subTest(value=value):
                self.assertFalse(self._confined(value))
        for value in (*ACCEPTED, *FILE_NAMES):
            with self.subTest(value=value):
                self.assertTrue(self._confined(value))


if __name__ == "__main__":
    unittest.main()
