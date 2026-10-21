import json
import unicodedata
import unittest
from unittest.mock import patch

from first_commit.checks.privacy import PrivacyPolicy, privacy_findings
from first_commit.models import Candidate, Finding, Origin, Result
from first_commit.policy import REQUIRED_DOCUMENTS
from first_commit.private_values import PRIVATE_VALUE_MASK as MASK
from first_commit.private_values import masked_path, masked_result
from tests.cli_support import CliFixture
from tests.support import run_git

RULE = "privacy.private-path"
VALUE = "synthetic-path-canary"


def path_findings(path: str, value: str, origin: Origin = Origin.INDEX) -> list[str]:
    candidate = Candidate(path=path, content=b"public text\n", origin=origin)
    findings = privacy_findings(
        candidate, PrivacyPolicy(private_values=(value,)), max_findings=10
    )
    return [item.rule_id for item in findings]


class PrivatePathTest(unittest.TestCase):
    def test_a_private_value_in_a_file_name_is_reported_at_that_path(self) -> None:
        candidate = Candidate(f"{VALUE}.txt", b"public text\n", Origin.INDEX)

        findings = privacy_findings(
            candidate, PrivacyPolicy(private_values=(VALUE,)), max_findings=10
        )

        self.assertEqual(
            [(RULE, f"{VALUE}.txt", None)],
            [(item.rule_id, item.path, item.line) for item in findings],
        )
        self.assertNotIn(VALUE, findings[0].summary)

    def test_the_path_is_compared_in_nfc_and_casefold(self) -> None:
        decomposed = unicodedata.normalize("NFD", "Café")
        for path, value in (
            ("docs/AuditLens-notes.md", "auditlens"),
            (f"{decomposed}/plan.md", "café"),
            ("STRASSE.txt", "straße".casefold()),
        ):
            with self.subTest(path=path):
                self.assertEqual([RULE], path_findings(path, value))

    def test_a_path_without_the_value_and_a_message_label_report_nothing(
        self,
    ) -> None:
        self.assertEqual([], path_findings("docs/notes.md", VALUE))
        self.assertEqual([], path_findings(VALUE, VALUE, Origin.MESSAGE))


class MaskedPathTest(unittest.TestCase):
    def test_each_private_value_in_a_path_is_replaced_with_the_mask(self) -> None:
        decomposed = unicodedata.normalize("NFD", "Café")
        for path, values, expected in (
            (f"{VALUE}.txt", (VALUE,), f"{MASK}.txt"),
            ("docs/AuditLens-notes.md", ("auditlens",), f"docs/{MASK}-notes.md"),
            (f"{decomposed}/plan.md", ("café",), f"{MASK}/plan.md"),
            ("a/STRASSE/b.txt", ("straße".casefold(),), f"a/{MASK}/b.txt"),
            ("one-two.txt", ("one", "two"), f"{MASK}-{MASK}.txt"),
            ("onetwo.txt", ("one", "netw"), f"{MASK}o.txt"),
            ("docs/notes.md", (VALUE,), "docs/notes.md"),
        ):
            with self.subTest(path=path):
                self.assertEqual(expected, masked_path(path, values))

    def test_a_result_masks_the_value_in_each_finding_path_and_summary(self) -> None:
        finding = Finding(
            rule_id=RULE,
            path=f"{VALUE}.txt",
            summary=f"{VALUE}/notes.md is unreadable.",
        )

        masked = masked_result(Result("staged", (finding,)), (VALUE,))

        self.assertEqual(
            [(f"{MASK}.txt", f"{MASK}/notes.md is unreadable.")],
            [(item.path, item.summary) for item in masked.findings],
        )


class PrivatePathHookTest(CliFixture):
    def stage_named_file(self) -> None:
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        for name in REQUIRED_DOCUMENTS:
            (self.root / name).write_text("# Reviewed\n", encoding="utf-8")
        private = self.root / ".local/first-commit/private-values.txt"
        private.parent.mkdir(parents=True)
        private.write_text(VALUE + "\n", encoding="utf-8")
        private.chmod(0o600)
        # The trailing space adds a second finding at the same path.
        (self.root / f"{VALUE}.txt").write_text("public text \n", "utf-8")
        run_git(
            self.root, "add", "--", ".gitignore", *REQUIRED_DOCUMENTS, f"{VALUE}.txt"
        )

    def run_hook(self, *arguments: str) -> tuple[int, str, str]:
        passed = Result("test", ())
        with (
            patch("first_commit.validation.doctor", return_value=passed),
            patch("first_commit.validation.scan_staged", return_value=[]),
        ):
            return self.run_cli("hook", "pre-commit", *arguments)

    def test_the_pre_commit_hook_blocks_a_staged_file_named_with_the_value(
        self,
    ) -> None:
        self.stage_named_file()

        code, output, error = self.run_hook()

        self.assertEqual((1, ""), (code, error))
        self.assertIn(f'{RULE} "{MASK}.txt": ', output)
        self.assertIn(f'text.trailing-whitespace "{MASK}.txt":1: ', output)
        self.assertNotIn(VALUE, output)

    def test_the_json_output_masks_the_value_in_every_finding_path(self) -> None:
        self.stage_named_file()

        code, output, error = self.run_hook("--format", "json")

        self.assertEqual((1, ""), (code, error))
        findings = json.loads(output)["checks"][0]["findings"]
        self.assertEqual(
            {(RULE, f"{MASK}.txt"), ("text.trailing-whitespace", f"{MASK}.txt")},
            {(item["rule_id"], item["path"]) for item in findings},
        )
        self.assertNotIn(VALUE, output)


if __name__ == "__main__":
    unittest.main()
