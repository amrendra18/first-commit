import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.candidates import staged_candidate_paths
from first_commit.policy import POLICY_PATH, REQUIRED_DOCUMENTS, parse_policy
from tests.gitleaks_support import commit_fixture
from tests.support import commit_message, initialize_repository, run_git

PRIVATE_EMAIL = "alice@" + "corp-private.net"
HOME_TARGET = "/Users/" + "alice/private-notes"
OWNER = "alicecanary"
OWNER_URL = f"https://github.com/{OWNER}/project"
PRIVATE_KEY_BLOCK = (
    b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----\nsynthetic\n"
    b"-----END OPENSSH PRIVATE KEY-----\n"
)
LITERAL_LINE = f"Written by {OWNER}."


class StagedChangesTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        for path in REQUIRED_DOCUMENTS:
            (self.root / path).write_text("# Reviewed\n", encoding="utf-8")
        run_git(self.root, "add", "--", *REQUIRED_DOCUMENTS)

    def staged_rules(
        self,
        config_bytes: bytes = b'{"schema_version":1}',
        private_values: tuple[str, ...] = (),
    ) -> set[tuple[str, str]]:
        policy = parse_policy(config_bytes, self.root)
        with (
            patch("first_commit.validation.scan_staged", return_value=()),
            patch("first_commit.validation.scan_hidden_staged", return_value=()),
        ):
            result = validation.staged(self.root, policy, private_values)
        return {(item.rule_id, item.path) for item in result.findings}

    def write_policy(self, policy: dict[str, object]) -> bytes:
        content = json.dumps({"schema_version": 1, **policy}).encode("utf-8")
        (self.root / POLICY_PATH).write_bytes(content)
        return content

    def test_symlink_replaced_by_a_file_is_checked(self) -> None:
        (self.root / "link").symlink_to("README.md")
        commit_fixture(self.root, "link", *REQUIRED_DOCUMENTS)
        (self.root / "link").unlink()
        (self.root / "link").write_text(f"Contact {PRIVATE_EMAIL}\n", encoding="utf-8")
        run_git(self.root, "add", "--", "link")

        self.assertEqual(("link",), staged_candidate_paths(self.root, 10))
        self.assertIn(("privacy.unapproved-email", "link"), self.staged_rules())

    def test_file_replaced_by_a_symlink_is_checked(self) -> None:
        (self.root / "notes").write_text("# Notes\n", encoding="utf-8")
        commit_fixture(self.root, "notes", *REQUIRED_DOCUMENTS)
        (self.root / "notes").unlink()
        (self.root / "notes").symlink_to(HOME_TARGET)
        run_git(self.root, "add", "--", "notes")

        self.assertEqual(("notes",), staged_candidate_paths(self.root, 10))
        self.assertIn(("privacy.user-home-path", "notes"), self.staged_rules())

    def test_unstaged_public_emails_edit_does_not_approve_staged_bytes(self) -> None:
        self.write_policy({})
        (self.root / "CONTACT.txt").write_text(f"{PRIVATE_EMAIL}\n", encoding="utf-8")
        run_git(self.root, "add", "--", POLICY_PATH, "CONTACT.txt")
        worktree = self.write_policy({"public_emails": [PRIVATE_EMAIL]})

        rules = self.staged_rules(worktree)

        self.assertIn(("privacy.unapproved-email", "CONTACT.txt"), rules)

    def test_unstaged_forbidden_paths_edit_does_not_allow_staged_paths(self) -> None:
        self.write_policy(
            {
                "forbidden_paths": [
                    {"match": "prefix", "value": "private/", "reason": "Local notes."}
                ]
            }
        )
        (self.root / "private").mkdir()
        (self.root / "private/notes.txt").write_text("notes\n", encoding="utf-8")
        run_git(self.root, "add", "--", POLICY_PATH, "private/notes.txt")
        worktree = self.write_policy({})

        rules = self.staged_rules(worktree)

        self.assertIn(("privacy.forbidden-path", "private/notes.txt"), rules)

    def test_staged_policy_edit_applies_before_the_worktree_copy(self) -> None:
        self.write_policy({"public_emails": [PRIVATE_EMAIL]})
        (self.root / "CONTACT.txt").write_text(f"{PRIVATE_EMAIL}\n", encoding="utf-8")
        run_git(self.root, "add", "--", POLICY_PATH, "CONTACT.txt")
        worktree = self.write_policy({})

        rules = self.staged_rules(worktree)

        self.assertNotIn(("privacy.unapproved-email", "CONTACT.txt"), rules)

    def exempted_private_bytes(self) -> bytes:
        key = self.root / "key.txt"
        key.write_bytes(PRIVATE_KEY_BLOCK)
        (self.root / "CONTACT.txt").write_text(f"{PRIVATE_EMAIL}\n", encoding="utf-8")
        (self.root / "SOURCE.txt").write_text(OWNER_URL + "\n", encoding="utf-8")
        (self.root / "CREDITS.txt").write_text(LITERAL_LINE + "\n", encoding="utf-8")
        (self.root / ".env").write_text("MODE=demo\n", encoding="utf-8")
        run_git(
            self.root,
            "add",
            "--",
            *("key.txt", "CONTACT.txt", "SOURCE.txt", "CREDITS.txt", ".env"),
        )
        detector = {
            "path": "key.txt",
            "line": 1,
            "rule": "privacy.private-key",
            "sha256": hashlib.sha256(PRIVATE_KEY_BLOCK).hexdigest(),
            "reason": "Synthetic test key.",
        }
        literal = {
            "path": "CREDITS.txt",
            "line": 1,
            "sha256": hashlib.sha256(LITERAL_LINE.encode("utf-8")).hexdigest(),
            "reason": "Public credit line.",
        }
        return self.write_policy(
            {
                "public_emails": [PRIVATE_EMAIL],
                "privacy_detector_exceptions": [detector],
                "private_literal_exceptions": [literal],
                "public_environment_files": [
                    {"path": ".env", "reason": "Public demo settings."}
                ],
                "public_github_owner_urls": True,
            }
        )

    def environment_rules(self, rules: set[tuple[str, str]]) -> set[str]:
        return {rule for rule, path in rules if path == ".env"}

    def test_an_untracked_policy_cannot_approve_staged_bytes(self) -> None:
        rules = self.staged_rules(self.exempted_private_bytes(), (OWNER,))

        self.assertIn(("privacy.private-key", "key.txt"), rules)
        self.assertIn(("privacy.unapproved-email", "CONTACT.txt"), rules)
        self.assertIn(("privacy.private-literal", "SOURCE.txt"), rules)
        self.assertIn(("privacy.private-literal", "CREDITS.txt"), rules)
        self.assertEqual(
            {"environment.tracked-private-file"}, self.environment_rules(rules)
        )

    def test_a_staged_policy_with_the_same_exemptions_approves(self) -> None:
        worktree = self.exempted_private_bytes()
        run_git(self.root, "add", "--", POLICY_PATH)

        rules = self.staged_rules(worktree, (OWNER,))

        self.assertNotIn(("privacy.private-key", "key.txt"), rules)
        self.assertNotIn(("privacy.unapproved-email", "CONTACT.txt"), rules)
        self.assertNotIn(("privacy.private-literal", "SOURCE.txt"), rules)
        self.assertNotIn(("privacy.private-literal", "CREDITS.txt"), rules)
        self.assertEqual(set(), self.environment_rules(rules))

    def test_a_policy_staged_for_deletion_applies_from_head(self) -> None:
        self.write_policy({})
        commit_fixture(self.root, POLICY_PATH, *REQUIRED_DOCUMENTS)
        run_git(self.root, "rm", "-q", "--cached", "--", POLICY_PATH)
        worktree = self.write_policy({"public_emails": [PRIVATE_EMAIL]})
        (self.root / "CONTACT.txt").write_text(f"{PRIVATE_EMAIL}\n", encoding="utf-8")
        run_git(self.root, "add", "--", "CONTACT.txt")

        rules = self.staged_rules(worktree)

        self.assertIn(("privacy.unapproved-email", "CONTACT.txt"), rules)

    def test_unstaged_policy_edit_does_not_approve_the_commit_message(self) -> None:
        self.write_policy({})
        run_git(self.root, "add", "--", POLICY_PATH)
        worktree = self.write_policy({"public_emails": [PRIVATE_EMAIL]})
        message_path = self.root / ".git/COMMIT_EDITMSG"
        message_path.write_text(
            commit_message(f"feat: credit {PRIVATE_EMAIL}"), encoding="utf-8"
        )

        result = validation.message(
            self.root, parse_policy(worktree, self.root), message_path
        )

        self.assertIn(
            "privacy.unapproved-email", {item.rule_id for item in result.findings}
        )


if __name__ == "__main__":
    unittest.main()
