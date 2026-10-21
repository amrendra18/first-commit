import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    MAX_CONTRIBUTOR_BYTES,
    MAX_EMAIL_CHARS,
    Contributor,
    ContributorError,
    contributor_findings,
    create_contributor,
    load_contributor,
    parse_contributor,
    record_bytes,
)
from first_commit.git import GitError
from first_commit.paths import PathError
from first_commit.policy import load_policy
from tests.support import initialize_repository, run_git


class ContributorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        self.person = Contributor(
            name="Example Contributor",
            email="contributor@example.com",
            signing_key="~/.ssh/id_ed25519.pub",
        )

    def test_missing_record_is_read_only(self) -> None:
        self.assertIsNone(load_contributor(self.root))
        self.assertFalse((self.root / ".local").exists())

    def test_exclusive_creation_and_load_require_repository_ignore(self) -> None:
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        create_contributor(self.root, self.person)
        target = self.root / CONTRIBUTOR_PATH
        self.assertEqual(self.person, load_contributor(self.root))
        self.assertEqual(0, target.stat().st_mode & 0o077)
        before = target.read_bytes()
        with self.assertRaisesRegex(ContributorError, "already exists"):
            create_contributor(self.root, self.person)
        self.assertEqual(before, target.read_bytes())

    def test_unignored_and_broad_permissions_are_rejected(self) -> None:
        target = self.root / CONTRIBUTOR_PATH
        target.parent.mkdir(parents=True)
        target.write_text(
            '{"schema_version":1,"name":"Example","email":"contributor@example.com","signing_key":"key.pub"}\n',
            encoding="utf-8",
        )
        target.chmod(0o600)
        with self.assertRaisesRegex(ContributorError, "repository .gitignore"):
            load_contributor(self.root)
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        target.chmod(0o644)
        with self.assertRaisesRegex(ContributorError, "permissions"):
            load_contributor(self.root)

    def test_policy_load_keeps_the_record_cause_and_names_its_fix(self) -> None:
        (self.root / ".repo-policy.json").write_text('{"schema_version": 1}\n', "utf-8")
        target = self.root / CONTRIBUTOR_PATH
        target.parent.mkdir(parents=True)
        target.write_bytes(record_bytes(self.person))
        target.chmod(0o600)
        unignored = (
            "Contributor record must be protected by repository .gitignore.\n"
            "fix: make .gitignore ignore .local/first-commit/contributor.json: add "
            "the line .local/ and delete any later rule that re-includes it, such as "
            "!.local/ (git check-ignore -v .local/first-commit/contributor.json names "
            "it); if Git tracks the file, run git rm --cached "
            ".local/first-commit/contributor.json; then rerun setup."
        )
        broad = (
            "Contributor record permissions are too broad.\n"
            "fix: run `chmod 600 .local/first-commit/contributor.json`."
        )
        for ignore, mode, expected in (
            ("", 0o600, unignored),
            (".local/\n", 0o644, broad),
        ):
            with self.subTest(expected=expected.split("\n")[0]):
                (self.root / ".gitignore").write_text(ignore, encoding="utf-8")
                target.chmod(mode)
                with self.assertRaises(ContributorError) as refused:
                    load_policy(self.root / ".repo-policy.json", self.root)
                self.assertEqual(expected, str(refused.exception))

    def test_tracked_and_symlinked_records_are_rejected_without_disclosure(
        self,
    ) -> None:
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        create_contributor(self.root, self.person)
        target = self.root / CONTRIBUTOR_PATH
        run_git(self.root, "add", "-f", "--", CONTRIBUTOR_PATH)
        with self.assertRaisesRegex(ContributorError, "tracked"):
            load_contributor(self.root)
        run_git(self.root, "rm", "--cached", "--", CONTRIBUTOR_PATH)
        target.unlink()
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "outside-contributor-canary"
            outside.write_text("private-canary\n", encoding="utf-8")
            target.symlink_to(outside)
            with self.assertRaises(ContributorError) as error:
                load_contributor(self.root)
            self.assertNotIn("private-canary", str(error.exception))

    def test_parser_rejects_ambiguous_or_private_material(self) -> None:
        for raw in (
            b"{not-json}",
            b'{"schema_version":1,"schema_version":1}',
            (
                b'{"schema_version":true,"name":"N","email":"n@example.com",'
                b'"signing_key":"key.pub"}'
            ),
            b'{"schema_version":1,"name":"N","email":"bad","signing_key":"key.pub"}',
            b'{"schema_version":1,"name":"N","email":"n@example.com",'
            b'"signing_key":"-----BEGIN PRIVATE ' + b'KEY-----"}',
        ):
            with self.subTest(raw=raw[:24]):
                with self.assertRaises(ContributorError) as error:
                    parse_contributor(raw)
                self.assertNotIn("PRIVATE KEY", str(error.exception))

    def test_creation_without_ignore_rolls_back_record(self) -> None:
        with self.assertRaisesRegex(ContributorError, "repository .gitignore"):
            create_contributor(self.root, self.person)
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())

    def test_email_shares_the_policy_length_limit_and_names_it(self) -> None:
        def record(email: str) -> bytes:
            return (
                '{"schema_version":1,"name":"N","email":"' + email + '",'
                '"signing_key":"key.pub"}'
            ).encode()

        longest = "a" * (MAX_EMAIL_CHARS - len("@example.org")) + "@example.org"
        self.assertEqual(longest, parse_contributor(record(longest)).email)
        with self.assertRaises(ContributorError) as error:
            parse_contributor(record("a" + longest))
        self.assertEqual(
            "Contributor email is longer than 254 characters.", str(error.exception)
        )
        with self.assertRaises(ContributorError) as error:
            parse_contributor(record("not-an-address"))
        self.assertEqual("Contributor email is invalid.", str(error.exception))

    def test_parser_rejects_bounds_and_invalid_fields(self) -> None:
        for raw in (
            b"x" * (MAX_CONTRIBUTOR_BYTES + 1),
            b'{"schema_version":1,"name":"N","email":"n@example.com"}',
            b'{"schema_version":1,"name":"","email":"n@example.com","signing_key":"key.pub"}',
            b'{"schema_version":2,"name":"N","email":"n@example.com","signing_key":"key.pub"}',
        ):
            with self.subTest(raw=raw[:24]):
                with self.assertRaises(ContributorError):
                    parse_contributor(raw)

    def test_record_too_deep_to_decode_is_invalid_json(self) -> None:
        with (
            patch("first_commit.contributor.json.loads", side_effect=RecursionError),
            self.assertRaisesRegex(ContributorError, "not valid UTF-8 JSON"),
        ):
            parse_contributor(b"[[]]")

    def test_git_and_path_read_failures_are_redacted(self) -> None:
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        create_contributor(self.root, self.person)
        with patch(
            "first_commit.git.is_tracked",
            side_effect=GitError("private-canary"),
        ):
            with self.assertRaises(ContributorError) as error:
                load_contributor(self.root)
        self.assertNotIn("private-canary", str(error.exception))
        with patch(
            "first_commit.contributor.read_regular_bytes",
            side_effect=PathError("private-canary"),
        ):
            with self.assertRaises(ContributorError) as error:
                load_contributor(self.root)
        self.assertNotIn("private-canary", str(error.exception))
        with patch(
            "first_commit.contributor.confined_path",
            side_effect=PathError("private-canary"),
        ):
            with self.assertRaises(ContributorError):
                load_contributor(self.root)
            with self.assertRaises(ContributorError):
                create_contributor(self.root, self.person)

    def test_creation_rejects_unsafe_parent_and_preserves_raced_file(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / ".local").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ContributorError, "unsafe"):
            create_contributor(self.root, self.person)
        self.assertEqual([], list(outside.iterdir()))
        (self.root / ".local").unlink()
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")

        def concurrent_change(root: Path):
            target = root / CONTRIBUTOR_PATH
            target.write_text("concurrent\n", encoding="utf-8")
            raise ContributorError("synthetic failure")

        with patch(
            "first_commit.contributor.load_contributor", side_effect=concurrent_change
        ):
            with self.assertRaises(ContributorError):
                create_contributor(self.root, self.person)
        self.assertEqual(
            "concurrent\n", (self.root / CONTRIBUTOR_PATH).read_text("utf-8")
        )

    def test_local_identity_must_match_ignored_contributor_record(self) -> None:
        missing = contributor_findings(None, {})
        self.assertEqual("git.contributor-record", missing[0].rule_id)
        values = {
            "user.name": self.person.name,
            "user.email": self.person.email,
            "user.signingkey": self.person.signing_key,
        }
        self.assertEqual([], contributor_findings(self.person, values))
        values["user.email"] = "different@" + "personal.test"
        findings = contributor_findings(self.person, values)
        self.assertEqual("git.contributor-email", findings[0].rule_id)
        self.assertNotIn(values["user.email"], str(findings))
