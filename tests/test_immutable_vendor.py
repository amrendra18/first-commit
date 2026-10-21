import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.candidates import index_candidate
from first_commit.gitleaks_scanner import CALIBRATION_INPUT
from first_commit.models import Candidate, Finding, Origin, Severity
from first_commit.policy import parse_policy
from first_commit.policy_fields import DEFAULT_LIMITS, PolicyError
from tests.gitleaks_support import needs_real_scanner
from tests.support import initialize_repository, run_git
from tests.validation_support import evaluate_candidates


class ImmutableVendorTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.public = (
            "upstream" + "@public-source.dev " + "/" + "home/author/file "
        ).encode()
        self.path = "vendor/upstream.txt"
        self.documents = {
            path: Candidate(path, b"# Reviewed\n", Origin.WORKTREE)
            for path in ("README.md", "AGENTS.md")
        }

    def entry(self, path=None, content=None):
        return {
            "path": self.path if path is None else path,
            "sha256": hashlib.sha256(
                self.public if content is None else content
            ).hexdigest(),
            "reason": "Reviewed unchanged upstream source.",
        }

    def policy(self, entries=None, **facts):
        return parse_policy(
            json.dumps(
                {
                    "schema_version": 1,
                    "immutable_vendor_files": [self.entry()]
                    if entries is None
                    else entries,
                    **facts,
                }
            ).encode(),
            self.root,
        )

    def rules(
        self, content=None, path=None, origin=Origin.WORKTREE, policy=None, private=()
    ):
        candidate = Candidate(
            path or self.path, self.public if content is None else content, origin
        )
        result = evaluate_candidates(
            "working", (candidate,), policy or self.policy(), self.documents, private
        )
        self.assertNotIn(self.public.decode(), repr(result))
        return {finding.rule_id for finding in result.findings}

    def test_unchanged_vendor_has_only_four_exemptions(self) -> None:
        self.assertEqual(
            (), parse_policy(b'{"schema_version":1}', self.root).immutable_vendor_files
        )
        for origin in (Origin.WORKTREE, Origin.INDEX):
            self.assertEqual(set(), self.rules(origin=origin))
        expected = {
            "privacy.unapproved-email",
            "privacy.user-home-path",
            "text.trailing-whitespace",
            "text.final-newline",
        }
        self.assertEqual(expected, self.rules(policy=self.policy(entries=[])))
        self.assertEqual(expected, self.rules(origin=Origin.MESSAGE))
        self.assertEqual(expected, self.rules(path="source.txt"))
        self.assertEqual(expected, self.rules(content=self.public + b"edited "))

    def test_schema_rejects_invalid_or_duplicate_declarations(self) -> None:
        entries: list[object] = [None, {}, [None], ["canary"]]
        entries += [
            [{**self.entry(), key: value}]
            for key, value in (
                ("path", "../outside"),
                ("path", "src/authored.py"),
                ("path", "vendor/*.txt"),
                ("path", "vendor//x"),
                ("path", "/outside"),
                ("path", "vendor\\x"),
                ("sha256", "A" * 64),
                ("sha256", None),
                ("sha256", "z" * 64),
                ("reason", ""),
                ("reason", " "),
                ("reason", True),
                ("reason", "canary\n"),
                ("reason", "a" * 501),
                ("extra", "canary"),
            )
        ]
        entries += [[self.entry(), self.entry(content=b"other")]]
        entries += [
            [
                self.entry(path=f"vendor/{i}")
                for i in range(DEFAULT_LIMITS["max_files"] + 1)
            ]
        ]
        for value in entries:
            with self.subTest(value=str(value)[:60]):
                with self.assertRaises(PolicyError) as context:
                    self.policy(immutable_vendor_files=value)
                self.assertNotIn("canary", str(context.exception))

    def test_large_vendor_manifest_retains_existing_bounds(self) -> None:
        entries = [self.entry(path=f"vendor/{i}") for i in range(2032)]
        self.assertEqual(2032, len(self.policy(entries).immutable_vendor_files))
        self.assertEqual(DEFAULT_LIMITS["max_files"], self.policy(entries).max_files)

    def test_declared_secrets_and_other_fixed_guards_still_block(self) -> None:
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
        values = (
            (token.encode(), "privacy.github-token", ()),
            (("AKIA" + "A" * 16).encode(), "privacy.aws-access-key", ()),
            (("-----BEGIN " + "PRIVATE KEY-----").encode(), "privacy.private-key", ()),
            (("SHA256:" + "a" * 24).encode(), "privacy.ssh-fingerprint", ()),
            (b"private-canary", "privacy.private-literal", ("private-canary",)),
            (b"# @no-commit", "scaffold.no-commit", ()),
            (b"<<<<<<< branch", "text.merge-marker", ()),
            (b"bad\x01text", "text.control-character", ()),
            (b"bad\xff", "text.invalid-utf8", ()),
        )
        for extra, rule, private in values:
            with self.subTest(rule=rule):
                content = self.public + b"\n" + extra + b"\n"
                policy = self.policy([self.entry(content=content)])
                self.assertIn(
                    rule, self.rules(content=content, policy=policy, private=private)
                )

    def initialize(self):
        initialize_repository(self.root)
        for path, document in self.documents.items():
            (self.root / path).write_bytes(document.content)
        (self.root / "vendor").mkdir()
        self.stage_policy(self.policy())
        target = self.root / self.path
        target.write_bytes(self.public)
        run_git(self.root, "add", "--", "README.md", "AGENTS.md", self.path)
        return target

    def stage_policy(self, policy):
        path = self.root / ".repo-policy.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "immutable_vendor_files": [
                        vars(item) for item in policy.immutable_vendor_files
                    ],
                }
            )
            + "\n"
        )
        run_git(self.root, "add", "--", ".repo-policy.json")

    def test_staged_bytes_not_worktree_control_matching(self) -> None:
        target = self.initialize()
        policy = self.policy()
        target.write_bytes(self.public + b"edited")
        with patch("first_commit.validation.scan_staged", return_value=()) as scanner:
            self.assertEqual((), validation.staged(self.root, policy).findings)
        scanner.assert_called_once()
        self.assertIn(
            "privacy.unapproved-email",
            {f.rule_id for f in validation.working(self.root, policy).findings},
        )
        run_git(self.root, "add", "--", self.path)
        target.write_bytes(self.public)
        with patch("first_commit.validation.scan_staged", return_value=()):
            self.assertIn(
                "privacy.unapproved-email",
                {f.rule_id for f in validation.staged(self.root, policy).findings},
            )
        self.assertEqual((), validation.working(self.root, policy).findings)

    def test_unlisted_files_scanner_environment_and_forbidden_paths_remain(
        self,
    ) -> None:
        self.initialize()
        policy = self.policy()
        new = self.root / "vendor/new.txt"
        new.write_bytes(self.public)
        self.assertIn(
            "privacy.unapproved-email",
            {f.rule_id for f in validation.working(self.root, policy).findings},
        )
        new.unlink()
        finding = Finding(
            rule_id="secrets.gitleaks",
            severity=Severity.ERROR,
            path=self.path,
            summary="Scanner detected a secret.",
        )
        with patch(
            "first_commit.validation.scan_staged", return_value=(finding,)
        ) as scanner:
            self.assertEqual((finding,), validation.staged(self.root, policy).findings)
        scanner.assert_called_once()
        policy = self.policy(
            forbidden_paths=[
                {"match": "exact", "value": self.path, "reason": "Private file."}
            ]
        )
        self.assertIn(
            "privacy.forbidden-path",
            {f.rule_id for f in validation.working(self.root, policy).findings},
        )
        dotenv = self.root / "vendor/.env"
        dotenv.write_bytes(self.public)
        policy = self.policy([self.entry(path="vendor/.env")])
        self.assertIn(
            "environment.not-ignored",
            {f.rule_id for f in validation.working(self.root, policy).findings},
        )
        run_git(self.root, "add", "--", "vendor/.env")
        with patch("first_commit.validation.scan_staged", return_value=()):
            self.assertIn(
                "environment.tracked-private-file",
                {f.rule_id for f in validation.staged(self.root, policy).findings},
            )

    def test_symlink_bytes_never_receive_vendor_exemptions(self) -> None:
        self.initialize()
        target = self.root / self.path
        target.unlink()
        link_bytes = "upstream" + "@public-source.dev"
        target.symlink_to(link_bytes)
        policy = self.policy([self.entry(content=link_bytes.encode())])
        self.stage_policy(policy)
        for operation in (validation.working, validation.staged):
            run_git(self.root, "add", "--", self.path)
            with patch("first_commit.validation.scan_staged", return_value=()):
                self.assertIn(
                    "privacy.unapproved-email",
                    {f.rule_id for f in operation(self.root, policy).findings},
                )
        target.unlink()
        target.write_bytes(link_bytes.encode())
        with patch("first_commit.validation.scan_staged", return_value=()):
            self.assertIn(
                "privacy.unapproved-email",
                {f.rule_id for f in validation.staged(self.root, policy).findings},
            )
        self.assertEqual((), validation.working(self.root, policy).findings)

    def test_declarations_cannot_escape_through_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            (self.root / "vendor").symlink_to(outside)
            with self.assertRaises(PolicyError):
                self.policy()

    def test_message_validation_keeps_privacy_checks(self) -> None:
        initialize_repository(self.root)
        path = self.root / "message.txt"
        path.write_bytes(self.public)
        policy = self.policy()
        with (
            patch("first_commit.validation.local_git_settings", return_value={}),
            patch("first_commit.validation.load_contributor", return_value=None),
        ):
            result = validation.message(self.root, policy, path)
        self.assertTrue(
            {"privacy.unapproved-email", "privacy.user-home-path"}
            <= {f.rule_id for f in result.findings}
        )

    def test_exemptions_do_not_consume_findings_budget(self) -> None:
        content = self.public + b"\n" + self.public + b"\n" + b"# @no-commit\n"
        policy = replace(self.policy([self.entry(content=content)]), max_findings=1)
        self.assertEqual(
            {"scaffold.no-commit"}, self.rules(content=content, policy=policy)
        )

    def test_worktree_only_declarations_cannot_approve_index_bytes(self) -> None:
        target = self.initialize()
        changed = self.public + b"edited"
        target.write_bytes(changed)
        run_git(self.root, "add", "--", self.path)
        policy = self.policy([self.entry(content=changed)])
        with patch("first_commit.validation.scan_staged", return_value=()):
            self.assertIn(
                "privacy.unapproved-email",
                {f.rule_id for f in validation.staged(self.root, policy).findings},
            )
        self.stage_policy(policy)
        with patch("first_commit.validation.scan_staged", return_value=()):
            self.assertEqual((), validation.staged(self.root, policy).findings)
        run_git(self.root, "rm", "--cached", "--", ".repo-policy.json")
        with patch("first_commit.validation.scan_staged", return_value=()):
            self.assertIn(
                "privacy.unapproved-email",
                {f.rule_id for f in validation.staged(self.root, policy).findings},
            )

    def test_vendor_declarations_reject_internal_symlink_ancestors(self) -> None:
        vendor = self.root / "vendor"
        vendor.mkdir()
        original = vendor / "original"
        original.mkdir()
        (vendor / "alias").symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(PolicyError, "symlinks"):
            self.policy([self.entry(path="vendor/alias/file")])

    def test_invalid_or_symlink_index_policy_is_refused(self) -> None:
        self.initialize()
        policy = self.policy()
        policy_file = self.root / ".repo-policy.json"
        policy_file.write_bytes(b"invalid policy")
        run_git(self.root, "add", "--", ".repo-policy.json")
        with self.assertRaisesRegex(PolicyError, "staged .repo-policy.json is invalid"):
            validation.staged(self.root, policy)
        policy_file.unlink()
        policy_file.symlink_to("README.md")
        run_git(self.root, "add", "--", ".repo-policy.json")
        with self.assertRaisesRegex(PolicyError, "staged .repo-policy.json is a link"):
            validation.staged(self.root, policy)

    @needs_real_scanner
    def test_real_scanner_blocks_secret_even_when_vendor_digest_matches(self) -> None:
        target = self.initialize()
        content = self.public + b"\n" + CALIBRATION_INPUT
        target.write_bytes(content)
        policy = self.policy([self.entry(content=content)])
        self.stage_policy(policy)
        run_git(self.root, "add", "--", self.path)
        result = validation.staged(self.root, policy)
        self.assertIn("secrets.gitleaks", {f.rule_id for f in result.findings})
        self.assertNotIn(CALIBRATION_INPUT.decode().strip(), repr(result))

    def test_index_regular_file_metadata_uses_the_same_blob_selection(self) -> None:
        for mode, regular in ((b"120000", False), (b"100644", True)):
            with self.subTest(mode=mode):
                object_id = b"a" * 40
                entry = mode + b" " + object_id + b" 0\tvendor/file\0"
                with (
                    patch(
                        "first_commit.candidates.run_git",
                        side_effect=(entry, object_id + b" blob 3\n"),
                    ) as git,
                    patch(
                        "first_commit.candidates.cat_file_blobs",
                        return_value=iter(((object_id.decode(), b"abc"),)),
                    ) as blobs,
                ):
                    candidate = index_candidate(self.root, "vendor/file", 10)
                self.assertEqual(b"abc", candidate.content)
                self.assertEqual(regular, candidate.regular_file)
                self.assertEqual(2, git.call_count)
                blobs.assert_called_once_with(self.root, {object_id.decode(): 3})
