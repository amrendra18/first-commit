import unittest

from first_commit.checks.messages import message_findings
from first_commit.models import Candidate, Origin


class MessagesTest(unittest.TestCase):
    def findings(self, text: str, maximum: int = 100):
        return message_findings(
            Candidate("<commit-message>", text.encode("utf-8"), Origin.MESSAGE),
            max_findings=maximum,
        )

    @staticmethod
    def message(subject: str, line_ending: str = "\n") -> str:
        return line_ending.join(
            (
                subject,
                "",
                "Why:",
                "- Explain the reason.",
                "",
                "Changes:",
                "- Describe the change.",
                "",
                "Test Plan:",
                "- Run the focused tests.",
                "",
                "Risks:",
                "- Low: isolated policy change.",
                "",
            )
        )

    def test_accepts_supported_types_scopes_and_breaking_markers(self) -> None:
        for kind in (
            "feat",
            "fix",
            "docs",
            "style",
            "refactor",
            "test",
            "build",
            "chore",
            "perf",
            "ci",
            "deps",
            "revert",
            "security",
            "infra",
            "release",
        ):
            for suffix in ("", "(api)", "(infra-db)", "!", "(v2-api)!"):
                with self.subTest(kind=kind, suffix=suffix):
                    self.assertEqual(
                        [], self.findings(self.message(kind + suffix + ": add checks"))
                    )

    def test_rejects_invalid_headers_without_echoing_content(self) -> None:
        for header in (
            "",
            "\n# comment\n",
            "add checks",
            "unknown: add checks",
            "Feat: add checks",
            "feat(): add checks",
            "feat(API): add checks",
            "feat(-api): add checks",
            "feat(api-): add checks",
            "feat(api--db): add checks",
            "feat(api/db): add checks",
            "feat: ",
            "feat:  add checks",
            "feat:\tadd checks",
            "feat: \u2003add checks",
            "feat: add\tchecks",
            "feat: add\rchecks",
            "feat: add\x1bchecks",
            "feat: add\x7fchecks",
        ):
            with self.subTest(header=header):
                findings = self.findings(header)
                self.assertEqual(
                    ["message.header"], [item.rule_id for item in findings]
                )
                self.assertEqual("error", findings[0].severity)
                self.assertEqual("<commit-message>", findings[0].path)
                self.assertNotIn("add checks", findings[0].summary)

    def test_length_thresholds_count_subject_characters_not_header_bytes(self) -> None:
        for length, severity, rule in (
            (72, None, None),
            (73, "warning", "message.subject-length"),
            (100, "warning", "message.subject-length"),
            (101, "error", "message.subject-length"),
        ):
            with self.subTest(length=length):
                findings = self.findings(
                    self.message("feat(long-scope): " + "界" * length)
                )
                if severity is None:
                    self.assertEqual([], findings)
                else:
                    self.assertEqual(
                        [(severity, rule)],
                        [(item.severity, item.rule_id) for item in findings],
                    )

    def test_requires_each_review_section_once_and_in_order(self) -> None:
        valid = self.message("docs: describe policy")
        self.assertEqual([], self.findings(valid))
        for changed in (
            "docs: describe policy\n",
            valid.replace("Why:\n- Explain the reason.\n\n", ""),
            valid.replace("Risks:\n- Low: isolated policy change.\n", ""),
            valid.replace("Why:", "Changes:", 1),
            valid.replace(
                "Why:\n- Explain the reason.\n\nChanges:\n- Describe the change.",
                "Changes:\n- Describe the change.\n\nWhy:\n- Explain the reason.",
            ),
        ):
            with self.subTest(changed=changed):
                findings = self.findings(changed)
                self.assertEqual(
                    [("message.sections", "error")],
                    [(item.rule_id, item.severity) for item in findings],
                )

    def test_rejects_empty_comment_only_and_template_placeholder_sections(self) -> None:
        valid = self.message("docs: describe policy")
        for changed in (
            valid.replace("- Explain the reason.", ""),
            valid.replace("- Describe the change.", "# added by Git"),
            valid.replace("- Run the focused tests.", "- <commands and results>"),
            valid.replace("- Low: isolated policy change.", "- <risks>"),
        ):
            with self.subTest(changed=changed):
                self.assertEqual(
                    ["message.sections"],
                    [item.rule_id for item in self.findings(changed)],
                )

    def test_accepts_generated_git_subjects(self) -> None:
        for prefix in ("Merge ", "Revert ", "fixup! ", "squash! ", "amend! "):
            with self.subTest(prefix=prefix):
                self.assertEqual([], self.findings(prefix + "generated subject" * 12))
                self.assertEqual("message.header", self.findings(prefix)[0].rule_id)

    def test_comments_blank_lines_and_crlf_preserve_subject_location(self) -> None:
        self.assertEqual(
            [],
            self.findings(
                "# Template comment\r\n\r\n" + self.message("feat: add checks", "\r\n")
            ),
        )
        findings = self.findings("# Template\n\ninvalid private-canary\n")
        self.assertEqual(3, findings[0].line)
        self.assertNotIn("private-canary", repr(findings))

    def test_trailing_punctuation_warns_and_finding_budget_is_respected(self) -> None:
        findings = self.findings(self.message("fix: correct checks."))
        self.assertEqual(
            [("message.subject-punctuation", "warning")],
            [(item.rule_id, item.severity) for item in findings],
        )
        self.assertEqual(2, len(self.findings(self.message("fix: " + "a" * 73 + "."))))
        self.assertEqual(
            1, len(self.findings(self.message("fix: " + "a" * 73 + "."), 1))
        )
        self.assertEqual(
            ["message.sections"],
            [item.rule_id for item in self.findings("fix: " + "a" * 73, 1)],
        )
        self.assertEqual([], self.findings("invalid", 0))

    def test_optional_sections_keep_only_conventional_subject_rules(self) -> None:
        def findings(text: str, maximum: int = 100) -> list[tuple[str, str]]:
            candidate = Candidate(
                "<commit-message>", text.encode("utf-8"), Origin.MESSAGE
            )
            return [
                (item.rule_id, item.severity)
                for item in message_findings(
                    candidate, max_findings=maximum, require_sections=False
                )
            ]

        valid = self.message("docs: describe policy")
        for text in (
            "docs: describe policy\n",
            "docs: describe policy",
            "docs: describe policy\n\nFree-form body.\n",
            valid,
            valid.replace("Why:", "Changes:", 1),
            valid.replace("- Explain the reason.", ""),
            "# Template\n\nfeat(api)!: add checks\r\n",
            "Merge generated subject\n",
        ):
            with self.subTest(text=text[:30]):
                self.assertEqual([], findings(text))
        self.assertEqual([("message.header", "error")], findings("plain subject\n"))
        self.assertEqual([("message.header", "error")], findings(""))
        self.assertEqual(
            [("message.subject-length", "error")], findings("fix: " + "a" * 101)
        )
        self.assertEqual(
            [("message.subject-length", "warning")], findings("fix: " + "a" * 73)
        )
        self.assertEqual(
            [("message.subject-punctuation", "warning")], findings("fix: correct it.")
        )
        self.assertEqual(
            [("message.subject-length", "warning")],
            findings("fix: " + "a" * 73 + ".", 1),
        )
        self.assertEqual([], findings("invalid", 0))
        self.assertEqual(
            [("message.sections", "error")],
            [
                (item.rule_id, item.severity)
                for item in message_findings(
                    Candidate("<commit-message>", b"docs: x\n", Origin.MESSAGE),
                    max_findings=100,
                    require_sections=True,
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
