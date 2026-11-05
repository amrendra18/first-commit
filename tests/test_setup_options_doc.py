import re
import unittest
from pathlib import Path

from first_commit.arguments import ArgumentError, parse

ARCHITECTURE = Path(__file__).resolve().parents[1] / "ARCHITECTURE.md"
ACCEPTS = re.compile(r"it accepts (?P<flags>[^.]+)\.")
ROW = re.compile(r"^\| `(?P<option>--[a-z-]+)", re.MULTILINE)
# The Commands section documents these for setup, check, and doctor together.
SHARED = {"-h", "--help", "--root", "--format"}


def documented_setup_options() -> set[str]:
    text = ARCHITECTURE.read_text("utf-8")
    table = text.split("### Setup options", 1)[1].split("\n### ", 1)[0]
    return set(ROW.findall(table))


class SetupOptionsDocumentTest(unittest.TestCase):
    def test_the_setup_options_table_lists_every_setup_option(self) -> None:
        with self.assertRaises(ArgumentError) as raised:
            parse(["setup", "--no-such-option"])
        match = ACCEPTS.search(str(raised.exception)) or self.fail("no flag list")
        accepted = set(match["flags"].split(", "))
        self.assertIn("--hooks", accepted)
        self.assertEqual(accepted - SHARED, documented_setup_options())
