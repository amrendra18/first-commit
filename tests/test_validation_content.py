import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit.candidates import CandidateError
from first_commit.contributor import Contributor
from first_commit.models import Candidate, Origin
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from first_commit.validation import (
    doctor,
    message,
    staged,
    working,
)
from tests.gitleaks_support import SLACK_TOKEN
from tests.support import commit_message, initialize_repository, run_git
from tests.validation_support import (
    IDENTITY,
    PUBLIC_EMAIL,
    TOKEN,
    ValidationFixture,
    commit_identity,
    evaluate_candidates,
)


class ContentValidationTest(ValidationFixture):
    def stage_policy(self, fields: dict[str, object]) -> None:
        content = json.dumps({"schema_version": 1, **fields}) + "\n"
        (self.root / ".repo-policy.json").write_text(content, encoding="utf-8")
        run_git(self.root, "add", "--", ".repo-policy.json")

    def test_public_emails_pass_working_index_and_message_content(self) -> None:
        message_path, person = self.public_email_repository()
        message_path.write_text(
            commit_message("docs: add contact") + "- Contact " + PUBLIC_EMAIL + "\n",
            encoding="utf-8",
        )
        policy = replace(
            self.policy,
            contributor_emails=(person.email,),
            public_emails=(PUBLIC_EMAIL,),
        )
        with (
            patch("first_commit.validation.scan_staged", return_value=()),
            patch("first_commit.validation.local_git_settings", return_value=IDENTITY),
            patch("first_commit.validation.load_contributor", return_value=person),
            commit_identity(),
        ):
            self.stage_policy({"public_emails": [PUBLIC_EMAIL]})
            listed = (
                working(self.root, policy),
                staged(self.root, policy),
                message(self.root, policy, message_path),
            )
            self.stage_policy({})
            unlisted = (
                working(self.root, self.policy),
                staged(self.root, self.policy),
                message(self.root, self.policy, message_path),
            )
        for result in listed:
            with self.subTest(scope=result.scope):
                self.assertEqual((), result.findings)
        for result in unlisted:
            with self.subTest(scope=result.scope):
                self.assertIn(
                    "privacy.unapproved-email",
                    {item.rule_id for item in result.findings},
                )
                self.assertNotIn(PUBLIC_EMAIL, repr(result))

    def test_public_emails_are_never_the_local_author_email(self) -> None:
        message_path, person = self.public_email_repository()
        message_path.write_text(commit_message("docs: add contact"), encoding="utf-8")
        policy = replace(
            self.policy,
            contributor_emails=(person.email,),
            public_emails=(PUBLIC_EMAIL,),
        )
        settings = {**IDENTITY, "user.email": PUBLIC_EMAIL}
        with (
            patch("first_commit.validation.local_git_settings", return_value=settings),
            patch("first_commit.validation.load_contributor", return_value=person),
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.validation.hook_findings", return_value=[]),
            patch("first_commit.validation.template_findings", return_value=[]),
        ):
            results = (
                message(self.root, policy, message_path),
                doctor(self.root, policy),
            )
            no_contributor = message(
                self.root, replace(policy, contributor_emails=()), message_path
            )
        for result in (*results, no_contributor):
            with self.subTest(scope=result.scope):
                rules = {item.rule_id for item in result.findings}
                self.assertIn("git.allowed-email", rules)
                self.assertNotIn("privacy.unapproved-email", rules)
        self.assertIn(
            "git.contributor-email", {item.rule_id for item in results[0].findings}
        )

    def test_public_emails_match_exact_addresses_only(self) -> None:
        message_path, person = self.public_email_repository()
        policy = replace(
            self.policy,
            contributor_emails=(person.email,),
            public_emails=(PUBLIC_EMAIL,),
        )
        local, _, domain = PUBLIC_EMAIL.partition("@")
        lookalikes = (
            "x" + PUBLIC_EMAIL,
            local + "s@" + domain,
            PUBLIC_EMAIL + ".evil",
            PUBLIC_EMAIL + "s",
            local + "@sub." + domain,
            local[1:] + "@" + domain,
            local + "@" + domain[1:],
            PUBLIC_EMAIL.upper(),
        )
        for address in lookalikes:
            with self.subTest(address=address):
                candidate = Candidate(
                    "contact.txt", (address + "\n").encode(), Origin.WORKTREE
                )
                result = evaluate_candidates("working", (candidate,), policy, {})
                self.assertIn(
                    "privacy.unapproved-email",
                    {item.rule_id for item in result.findings},
                )
                message_path.write_text(
                    commit_message("docs: add contact") + "- " + address + "\n",
                    encoding="utf-8",
                )
                with (
                    patch(
                        "first_commit.validation.local_git_settings",
                        return_value=IDENTITY,
                    ),
                    patch(
                        "first_commit.validation.load_contributor",
                        return_value=person,
                    ),
                    commit_identity(),
                ):
                    result = message(self.root, policy, message_path)
                self.assertEqual(
                    ["privacy.unapproved-email"],
                    [item.rule_id for item in result.findings],
                )
                self.assertNotIn(address, repr(result))

    def test_public_emails_keep_the_finding_budget(self) -> None:
        policy = replace(self.policy, public_emails=(PUBLIC_EMAIL,), max_findings=2)
        content = (
            "\n".join(
                [PUBLIC_EMAIL]
                + [f"user{number}@" + "unlisted.dev" for number in range(5)]
            )
            + "\n"
        )
        candidate = Candidate("contacts.txt", content.encode(), Origin.WORKTREE)
        documents = {
            name: Candidate(name, b"# Reviewed\n", Origin.WORKTREE)
            for name in REQUIRED_DOCUMENTS
        }
        result = evaluate_candidates("working", (candidate,), policy, documents)
        self.assertEqual(
            [("privacy.unapproved-email", 2), ("privacy.unapproved-email", 3)],
            [(item.rule_id, item.line) for item in result.findings],
        )

    def test_commit_body_sections_setting_controls_only_message_sections(
        self,
    ) -> None:
        canary = "synthetic-sections-private-canary"
        values = self.private_repository(canary)
        message_path = self.root / ".local/message"
        person = Contributor("Example", IDENTITY["user.email"], "key.pub")
        required = replace(self.policy, contributor_emails=(person.email,))
        optional = replace(required, commit_body_sections=False)
        self.assertIsInstance(required.commit_body_sections, bool)
        self.assertTrue(required.commit_body_sections)
        unlisted = "private@" + "nonexample.dev"
        cases: tuple[tuple[str, list[str], list[str]], ...] = (
            ("feat: add checks\n", [], ["message.sections"]),
            (commit_message("feat: add checks"), [], []),
            ("feat: add checks\n\nFree-form body.\n", [], ["message.sections"]),
            ("plain subject\n", ["message.header"], ["message.header"]),
            (
                "feat: " + "a" * 101 + "\n",
                ["message.subject-length"],
                ["message.subject-length"],
            ),
            (
                "feat: add checks\n\nCredit " + canary + "\n",
                ["privacy.private-literal"],
                ["message.sections", "privacy.private-literal"],
            ),
            (
                "feat: add checks\n\nContact " + unlisted + "\n",
                ["privacy.unapproved-email"],
                ["message.sections", "privacy.unapproved-email"],
            ),
            (
                "feat: add checks\n\n<!-- @no-commit -->\n",
                ["scaffold.no-commit"],
                ["message.sections", "scaffold.no-commit"],
            ),
        )
        for text, without_sections, with_sections in cases:
            with self.subTest(text=text[:24]):
                message_path.write_text(text, encoding="utf-8")
                with (
                    patch(
                        "first_commit.validation.local_git_settings",
                        return_value=IDENTITY,
                    ),
                    patch(
                        "first_commit.validation.load_contributor",
                        return_value=person,
                    ),
                    commit_identity(),
                ):
                    relaxed = message(self.root, optional, message_path, values)
                    strict = message(self.root, required, message_path, values)
                self.assertEqual(
                    sorted(without_sections),
                    sorted(item.rule_id for item in relaxed.findings),
                )
                self.assertEqual(
                    sorted(with_sections),
                    sorted(item.rule_id for item in strict.findings),
                )
                self.assertNotIn(canary, repr(relaxed))
                self.assertNotIn(unlisted, repr(relaxed))
        message_path.write_text("feat: add checks\n", encoding="utf-8")
        with (
            patch("first_commit.validation.local_git_settings", return_value={}),
            patch("first_commit.validation.load_contributor", return_value=None),
        ):
            result = message(self.root, optional, message_path, values)
        rules = {item.rule_id for item in result.findings}
        self.assertTrue({"git.allowed-email", "git.contributor-record"} <= rules)
        self.assertNotIn("message.sections", rules)

    def test_staged_selects_index_bytes_not_worktree_bytes(self) -> None:
        initialize_repository(self.root)
        self.write_documents()
        readme = self.root / "README.md"
        readme.write_text("# Project\n<!-- @no-commit -->\n", encoding="utf-8")
        draft = self.root / "draft.md"
        draft.write_text(TOKEN + "\n", encoding="utf-8")
        run_git(self.root, "add", "--", *REQUIRED_DOCUMENTS, "draft.md")
        readme.write_text("# Project\n", encoding="utf-8")
        draft.write_text("# Safe draft\n", encoding="utf-8")
        proposal = "AGENTS.md.first-commit-proposal.md"
        (self.root / proposal).write_text(
            "# Proposal\n<!-- @no-commit -->\n", encoding="utf-8"
        )
        (self.root / "notes.md").write_text(
            "# Notes\n<!-- @no-commit -->\n", encoding="utf-8"
        )

        with patch("first_commit.validation.scan_staged", return_value=()):
            result = staged(self.root, self.policy)
        working_result = working(self.root, self.policy)

        found = {(item.path, item.rule_id, item.line) for item in result.findings}
        self.assertIn(("README.md", "scaffold.no-commit", 2), found)
        self.assertIn(("draft.md", "privacy.github-token", 1), found)
        self.assertIn((proposal, "scaffold.no-commit", 2), found)
        self.assertNotIn(("notes.md", "scaffold.no-commit", 2), found)
        self.assertNotIn(TOKEN, repr(result))
        working_found = {(item.path, item.rule_id) for item in working_result.findings}
        self.assertNotIn(("README.md", "scaffold.no-commit"), working_found)
        self.assertNotIn(("draft.md", "privacy.github-token"), working_found)

        run_git(self.root, "add", "--", "README.md", "draft.md")
        with patch("first_commit.validation.scan_staged", return_value=()):
            result = staged(self.root, self.policy)
        self.assertEqual(
            [(proposal, "scaffold.no-commit")],
            [(item.path, item.rule_id) for item in result.findings],
        )

    def test_private_values_apply_to_every_content_scope_without_disclosure(
        self,
    ) -> None:
        canary = "Private Person Canary"
        values = self.private_repository(canary)
        (self.root / "document.md").write_text(
            "Mentions " + canary.upper() + "\n", encoding="utf-8"
        )
        run_git(self.root, "add", "--", "document.md")
        message_path = self.root / ".local/message"
        message_path.write_text("Reference " + canary + "\n", encoding="utf-8")

        with patch("first_commit.validation.scan_staged", return_value=()):
            results = (
                working(self.root, self.policy, values),
                staged(self.root, self.policy, values),
                message(self.root, self.policy, message_path, values),
            )

        for result in results:
            with self.subTest(scope=result.scope):
                self.assertIn(
                    "privacy.private-literal",
                    {item.rule_id for item in result.findings},
                )
                self.assertNotIn(canary.casefold(), repr(result).casefold())

    def test_generated_subjects_never_bypass_privacy_or_identity(self) -> None:
        canary = "synthetic-message-private-canary"
        values = self.private_repository(canary)
        message_path = self.root / ".local/message"
        for prefix in ("Merge ", "Revert ", "fixup! ", "squash! ", "amend! ", "bad "):
            with self.subTest(prefix=prefix):
                message_path.write_text(prefix + canary + "\n", encoding="utf-8")
                result = message(self.root, self.policy, message_path, values)
                self.assertIn(
                    "privacy.private-literal",
                    {item.rule_id for item in result.findings},
                )
                self.assertNotIn(canary, repr(result))
        limited = replace(self.policy, max_findings=1)
        message_path.write_text("Merge safe branch\n", encoding="utf-8")
        result = message(self.root, limited, message_path)
        self.assertEqual(1, len(result.findings))
        self.assertTrue(result.findings[0].rule_id.startswith("git."))
        message_path.write_text(commit_message("feat: " + "a" * 73), encoding="utf-8")
        result = message(self.root, limited, message_path)
        self.assertEqual("error", result.findings[0].severity)
        message_path.write_text("Merge " + canary + "\n", encoding="utf-8")
        result = message(self.root, limited, message_path, values)
        self.assertEqual(
            ["privacy.private-literal"], [item.rule_id for item in result.findings]
        )

    def test_message_ignores_git_author_fields_for_private_literals(self) -> None:
        values = self.private_repository("Example Maintainer")
        for key, value in {
            **IDENTITY,
            "user.name": "Example Maintainer",
            "user.email": "maintainer@example.com",
        }.items():
            run_git(self.root, "config", "--local", key, value)
        policy = replace(self.policy, contributor_emails=("maintainer@example.com",))
        message_path = self.root / ".local/message"
        message_path.write_text(
            commit_message("chore: validate checks"), encoding="utf-8"
        )
        with patch(
            "first_commit.validation.load_contributor",
            return_value=Contributor(
                "Example Maintainer", "maintainer@example.com", "key.pub"
            ),
        ):
            clean = message(self.root, policy, message_path, values)
            message_path.write_text(
                commit_message("chore: credit Example Maintainer"), encoding="utf-8"
            )
            unsafe = message(self.root, policy, message_path, values)

        self.assertEqual((), clean.findings)
        self.assertEqual(
            ["privacy.private-literal"], [item.rule_id for item in unsafe.findings]
        )
        self.assertNotIn("Example Maintainer", repr(unsafe))

    def test_message_marker_and_contributor_findings_do_not_disclose_message(
        self,
    ) -> None:
        initialize_repository(self.root)
        message_path = self.root / "message.txt"
        message_path.write_text(
            commit_message("feat: add feature") + "# @no-commit\nprivate-canary\n",
            encoding="utf-8",
        )
        result = message(self.root, self.policy, message_path)
        rules = [item.rule_id for item in result.findings]
        self.assertIn("scaffold.no-commit", rules)
        self.assertIn("git.contributor-record", rules)
        locations = [
            (item.path, item.line or 0, item.rule_id) for item in result.findings
        ]
        self.assertEqual(sorted(locations), locations)
        self.assertNotIn("private-canary", repr(result))

    def test_message_secret_is_a_gitleaks_finding_without_disclosure(self) -> None:
        initialize_repository(self.root)
        message_path = self.root / "message.txt"
        message_path.write_text(
            commit_message("feat: add feature") + f'- slack = "{SLACK_TOKEN}"\n',
            encoding="utf-8",
        )
        result = message(self.root, self.policy, message_path)
        self.assertIn(
            ("secrets.gitleaks", "<commit-message>", 14),
            {(item.rule_id, item.path, item.line) for item in result.findings},
        )
        self.assertNotIn(SLACK_TOKEN, repr(result))

    def test_message_rejects_binary_invalid_and_external_paths_without_disclosure(
        self,
    ) -> None:
        initialize_repository(self.root)
        message_path = self.root / "message"
        for content in (b"private-message-canary\0", b"private-message-canary\xff"):
            with self.subTest(content=content):
                message_path.write_bytes(content)
                with self.assertRaises(CandidateError) as context:
                    message(self.root, self.policy, message_path)
                self.assertNotIn("private-message-canary", str(context.exception))
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "message"
            external.write_text("private-message-canary\n", encoding="utf-8")
            with self.assertRaises(CandidateError) as context:
                message(self.root, self.policy, external)
        self.assertNotIn("private-message-canary", str(context.exception))

    def test_message_accepts_exact_linked_worktree_git_path(self) -> None:
        initialize_repository(self.root)
        with tempfile.TemporaryDirectory() as directory:
            linked = Path(directory) / "main.git/worktrees/linked/COMMIT_EDITMSG"
            linked.parent.mkdir(parents=True)
            linked.write_text(commit_message("feat: add checks"), encoding="utf-8")
            with (
                patch(
                    "first_commit.validation.run_git",
                    return_value=str(linked).encode("utf-8") + b"\n",
                ),
                patch("first_commit.validation.local_git_settings", return_value={}),
                patch("first_commit.validation.load_contributor", return_value=None),
            ):
                result = message(self.root, self.policy, linked)
        self.assertEqual("message", result.scope)
        self.assertFalse(
            any(item.rule_id.startswith("privacy.") for item in result.findings)
        )

    def test_environment_policy_applies_to_working_and_staged_scopes(self) -> None:
        initialize_repository(self.root)
        self.write_documents()
        (self.root / ".env").write_text("VALUE=private\n", encoding="utf-8")
        result = working(self.root, self.policy)
        self.assertIn(
            (".env", "environment.not-ignored"),
            {(item.path, item.rule_id) for item in result.findings},
        )
        run_git(self.root, "add", "--", ".env")
        with patch("first_commit.validation.scan_staged", return_value=()):
            result = staged(self.root, self.policy)
        self.assertIn(
            (".env", "environment.tracked-private-file"),
            {(item.path, item.rule_id) for item in result.findings},
        )

    def test_ignored_environment_content_is_not_read_and_exceptions_keep_privacy(
        self,
    ) -> None:
        initialize_repository(self.root)
        self.write_documents()
        (self.root / ".gitignore").write_text("/.env\n", encoding="utf-8")
        ignored = "ghp_" + "ignoredenvironmentcontent1234567890"
        (self.root / ".env").write_text(ignored, encoding="utf-8")
        result = working(self.root, self.policy)
        self.assertEqual((), result.findings)
        self.assertNotIn(ignored, repr(result))

        value = {
            "schema_version": 1,
            "public_environment_files": [
                {"path": "fixtures/.env", "reason": "Synthetic parser fixture."}
            ],
        }
        policy = parse_policy(json.dumps(value).encode(), self.root)
        fixtures = self.root / "fixtures"
        fixtures.mkdir()
        (fixtures / ".env").write_text(TOKEN + "\n", encoding="utf-8")
        run_git(self.root, "add", "--", "fixtures/.env")
        rules = {item.rule_id for item in working(self.root, policy).findings}
        self.assertIn("privacy.github-token", rules)
        self.assertNotIn("environment.tracked-private-file", rules)


if __name__ == "__main__":
    unittest.main()
