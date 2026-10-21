import json
import re
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit.checks.identity import SIGNATURE_TRUST_SUMMARY
from first_commit.checks.templates import template_findings
from first_commit.contributor import contributor_findings
from first_commit.fixes import (
    HOOK_FIXES,
    MESSAGE_FIXES,
    PUSHED_MESSAGE_FIX,
    SETUP_RULES,
    TAG_MESSAGE_FIX,
    TOOL_FIXES,
    fix_for,
)
from first_commit.gitleaks_blobs import MESSAGE_PATH, MESSAGE_SUMMARY
from first_commit.history_messages import ON_THE_REMOTE
from first_commit.models import Finding, Result, Severity
from first_commit.private_values import masked_result
from first_commit.reporting import render_human
from first_commit.setup_command import SETUP_HOOK_COMMAND, TOOL_SETUP_COMMAND
from tests.validation_support import render_json

SOURCE = Path(__file__).resolve().parents[1] / "src/first_commit"
RULE = re.compile(
    r'"((?:documents|environment|files|git|hooks|message|privacy|scaffold|secrets|'
    r'template|text)\.[a-z0-9-]+)"'
)
NOT_RULES: set[str] = set()
APPROVAL_FIELDS = (
    "public_environment_files",
    "private_literal_exceptions",
    "privacy_detector_exceptions",
    "public_emails",
)
APPROVAL_RULES = (
    "environment.not-ignored",
    "privacy.private-literal",
    "privacy.ssh-fingerprint",
    "privacy.unapproved-email",
    "privacy.user-home-path",
)


def source_rules() -> set[str]:
    found = set()
    for path in SOURCE.rglob("*.py"):
        if path.name == "fixes.py":
            continue
        found.update(RULE.findall(path.read_text("utf-8")))
    return found - NOT_RULES


class FixesTest(unittest.TestCase):
    def test_every_rule_in_the_source_has_a_fix_and_no_fix_is_unused(self) -> None:
        rules = source_rules()
        self.assertGreaterEqual(len(rules), 40)
        self.assertEqual(set(), rules - set(HOOK_FIXES), "rules without a fix")
        self.assertEqual(set(), set(HOOK_FIXES) - rules, "fixes for no rule")

    def test_fix_lines_are_single_sentences_of_plain_text(self) -> None:
        for rule, fix in (
            *HOOK_FIXES.items(),
            *TOOL_FIXES.items(),
            *MESSAGE_FIXES.items(),
            ("pushed message", PUSHED_MESSAGE_FIX),
            ("tag message", TAG_MESSAGE_FIX),
        ):
            with self.subTest(rule=rule):
                self.assertNotIn("\n", fix)
                self.assertTrue(fix.endswith("."), fix)
                self.assertLessEqual(len(fix), 200)

    def test_a_fix_that_adds_a_policy_approval_says_to_stage_the_policy(
        self,
    ) -> None:
        approvals = {
            (form, rule): fix
            for form, fixes in (
                ("hook", HOOK_FIXES),
                ("tool", TOOL_FIXES),
                ("message", MESSAGE_FIXES),
            )
            for rule, fix in fixes.items()
            if any(field in fix for field in APPROVAL_FIELDS)
        }
        self.assertEqual(
            {
                *((form, rule) for form in ("hook", "tool") for rule in APPROVAL_RULES),
                ("message", "privacy.unapproved-email"),
            },
            set(approvals),
        )
        for (form, rule), fix in approvals.items():
            with self.subTest(form=form, rule=rule):
                self.assertIn(", then stage .repo-policy.json", fix)
        for rule in APPROVAL_RULES:
            self.assertEqual(HOOK_FIXES[rule], TOOL_FIXES[rule])

    def test_fix_lines_name_only_commands_a_clone_has(self) -> None:
        for rule, fix in HOOK_FIXES.items():
            with self.subTest(rule=rule):
                self.assertNotIn("first-commit setup", fix)
                self.assertNotIn("--trust-self", fix)
        self.assertEqual(
            "Run FIRST_COMMIT_TRUST_SELF=1 pre-commit run first-commit-setup "
            "--hook-stage manual in this checkout to trust your own signing key.",
            HOOK_FIXES["git.signature-verification-trust"],
        )
        self.assertIn(SETUP_HOOK_COMMAND, HOOK_FIXES["template.missing"])
        self.assertIn(SETUP_HOOK_COMMAND, HOOK_FIXES["git.contributor-record"])

    def test_tool_fix_lines_name_setup_where_no_setup_hook_exists(self) -> None:
        self.assertEqual(set(HOOK_FIXES), set(TOOL_FIXES))
        self.assertEqual(
            "Run first-commit setup --trust-self in this checkout to trust your own "
            "signing key.",
            TOOL_FIXES["git.signature-verification-trust"],
        )
        for rule, fix in TOOL_FIXES.items():
            with self.subTest(rule=rule):
                self.assertNotIn("first-commit-setup", fix)
                if HOOK_FIXES[rule] == fix:
                    self.assertNotIn(SETUP_HOOK_COMMAND, fix)
                else:
                    self.assertIn(TOOL_SETUP_COMMAND, fix)
        for rule in SETUP_RULES:
            self.assertIn(TOOL_SETUP_COMMAND, TOOL_FIXES[rule])

    def test_remote_and_revision_fix_lines_keep_their_text(self) -> None:
        self.assertEqual(
            "Rename one of the remotes so no two names differ only in letter case.",
            TOOL_FIXES["hooks.remote-case"],
        )
        self.assertEqual(
            "Set rev in .pre-commit-config.yaml to the installed first-commit's commit "
            "(first-commit setup names it), or install first-commit at the pinned rev.",
            TOOL_FIXES["hooks.push-revision"],
        )
        self.assertEqual(
            "Set rev in .pre-commit-config.yaml to the installed first-commit's commit, "
            "or install first-commit at the pinned rev.",
            HOOK_FIXES["hooks.push-revision"],
        )

    def test_the_scanner_fix_line_names_setup_or_a_gitleaks_install(self) -> None:
        action = (
            "in this checkout (first delete .local/bin/gitleaks if the summary says "
            "to), or install Gitleaks 8.30.0 on PATH."
        )
        self.assertEqual(
            f"Run {SETUP_HOOK_COMMAND} {action}",
            HOOK_FIXES["secrets.scanner-unavailable"],
        )
        self.assertEqual(
            f"Run {TOOL_SETUP_COMMAND} {action}",
            TOOL_FIXES["secrets.scanner-unavailable"],
        )

    def test_finding_summaries_leave_commands_to_the_fix_line(self) -> None:
        with patch(
            "first_commit.checks.templates.effective_git_settings", return_value={}
        ):
            template = template_findings(Path())
        summaries = {
            "template.missing": template[0].summary,
            "git.contributor-record": contributor_findings(None, {})[0].summary,
            "git.signature-verification-trust": SIGNATURE_TRUST_SUMMARY,
        }
        for rule, summary in summaries.items():
            with self.subTest(rule=rule):
                self.assertNotIn("run ", summary.lower())
                self.assertNotIn("setup", summary)
                self.assertNotIn("pre-commit", summary)

    def test_human_and_json_output_carry_the_fix(self) -> None:
        finding = Finding(
            rule_id="text.final-newline",
            severity=Severity.ERROR,
            path="a.txt",
            summary="Text file has no final newline.",
        )
        result = Result("staged", (finding,))
        self.assertEqual(
            [
                'text.final-newline "a.txt": Text file has no final newline.',
                "  fix: End the file with a newline.",
                "1 policy finding(s)",
            ],
            render_human(result).splitlines(),
        )
        value = json.loads(render_json(result))
        self.assertEqual("End the file with a newline.", value["findings"][0]["fix"])

    def test_a_gitleaks_finding_in_the_message_says_to_edit_the_message(self) -> None:
        finding = Finding(
            rule_id="secrets.gitleaks",
            severity=Severity.ERROR,
            path=MESSAGE_PATH,
            summary=MESSAGE_SUMMARY,
            line=4,
        )
        fix = (
            "Revoke the secret and delete it from the commit message; .gitleaksignore "
            "does not apply to it. Commit again, or reword a commit: git commit "
            "--amend (last) or git rebase -i (earlier)."
        )
        for setup_hook in (True, False):
            with self.subTest(setup_hook=setup_hook):
                result = Result("message", (finding,))
                self.assertIn(
                    "  fix: " + fix,
                    render_human(result, setup_hook=setup_hook).splitlines(),
                )
                value = json.loads(render_json(result, setup_hook=setup_hook))
                self.assertEqual(fix, value["findings"][0]["fix"])
        in_a_file = Result("staged", (replace(finding, path="a.txt"),))
        value = json.loads(render_json(in_a_file))
        self.assertIn(".gitleaksignore", value["findings"][0]["fix"])

    def test_a_privacy_finding_in_the_message_says_to_reword_it(self) -> None:
        rules = [
            rule
            for rule in HOOK_FIXES
            if rule.startswith("privacy.")
            and rule not in {"privacy.forbidden-path", "privacy.private-path"}
        ]
        self.assertEqual(7, len(rules))
        for rule in rules:
            with self.subTest(rule=rule):
                finding = Finding(
                    rule_id=rule,
                    severity=Severity.ERROR,
                    path=MESSAGE_PATH,
                    summary="Detected.",
                    line=4,
                )
                fix = json.loads(render_json(Result("message", (finding,))))[
                    "findings"
                ][0]["fix"]
                self.assertIn("message", fix)
                self.assertIn("git commit --amend", fix)
                self.assertIn("git rebase -i", fix)
                self.assertNotIn("exceptions", fix)

    def test_a_masked_remote_finding_keeps_the_pushed_message_fix(self) -> None:
        pushed = Finding(
            rule_id="privacy.user-home-path",
            severity=Severity.WARNING,
            path=MESSAGE_PATH,
            summary="Commit 0123456789ab: Detected a literal user-home path."
            + ON_THE_REMOTE,
            line=4,
            on_remote=True,
        )
        masked = masked_result(Result("history", (pushed,)), ("provider",))
        self.assertNotIn("provider", masked.findings[0].summary)
        self.assertEqual(PUSHED_MESSAGE_FIX, fix_for(masked.findings[0]))
        local = replace(pushed, on_remote=False)
        self.assertEqual(MESSAGE_FIXES["privacy.user-home-path"], fix_for(local))

    def test_the_empty_index_fix_does_not_assume_a_commit_was_tried(self) -> None:
        expected = (
            "Stage the files to commit with git add, including README.md and AGENTS.md."
        )
        for fixes in (HOOK_FIXES, TOOL_FIXES):
            with self.subTest(setup_hook=fixes is HOOK_FIXES):
                self.assertEqual(expected, fixes["git.empty-index"])

    def test_an_unknown_rule_prints_no_fix_line(self) -> None:
        finding = Finding(
            rule_id="other.rule",
            severity=Severity.ERROR,
            path="a.txt",
            summary="Something.",
        )
        self.assertNotIn("fix:", render_human(Result("staged", (finding,))))
        value = json.loads(render_json(Result("staged", (finding,))))
        self.assertNotIn("fix", value["findings"][0])


if __name__ == "__main__":
    unittest.main()
