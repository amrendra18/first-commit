import unittest

from first_commit.checks.text import no_commit_findings, text_findings
from tests.test_checks import candidate


class TextRuleInputTest(unittest.TestCase):
    def test_an_indented_no_commit_marker_is_still_found(self) -> None:
        for text in ("  <!-- @no-commit -->\n", "\t# @no-commit\n"):
            with self.subTest(text=repr(text)):
                findings = no_commit_findings(
                    candidate("README.md", text.encode()), max_findings=1000
                )
                self.assertEqual([1], [item.line for item in findings])

    def test_a_line_that_ends_in_a_tab_has_trailing_whitespace(self) -> None:
        findings = text_findings(
            candidate("notes.txt", b"value\t\nnext\n"), max_findings=1000
        )
        self.assertEqual(
            [("text.trailing-whitespace", 1)],
            [(item.rule_id, item.line) for item in findings],
        )


if __name__ == "__main__":
    unittest.main()
