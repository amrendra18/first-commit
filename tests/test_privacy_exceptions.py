import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.checks.privacy import PrivacyPolicy, privacy_findings
from first_commit.models import Candidate, Origin
from first_commit.policy import parse_policy
from first_commit.policy_fields import DEFAULT_LIMITS, PolicyError
from tests.support import initialize_repository, run_git

MAX_FILE_BYTES = DEFAULT_LIMITS["max_file_bytes"]


class PrivacyExceptionsTest(unittest.TestCase):
    @staticmethod
    def exception(path="LICENSE", line=1, content=b"Copyright Private Person"):
        return {
            "path": path,
            "line": line,
            "sha256": hashlib.sha256(content).hexdigest(),
            "reason": "Approved public copyright attribution.",
        }

    def policy(self, root, exceptions):
        value = {"schema_version": 1, "private_literal_exceptions": exceptions}
        return parse_policy(json.dumps(value).encode(), root)

    def test_existing_privacy_policy_defaults_to_no_exceptions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = parse_policy(b'{"schema_version":1}', Path(directory))
            self.assertEqual((), policy.literal_exceptions)

    def test_exception_schema_is_strict_and_bounded(self) -> None:
        invalid: list[object] = [
            None,
            {},
            ["private-schema-canary"],
            [{**self.exception(), "path": "../LICENSE"}],
            [{**self.exception(), "path": "*.md"}],
            [{**self.exception(), "path": "docs//LICENSE"}],
            [{**self.exception(), "line": 0}],
            [{**self.exception(), "line": True}],
            [{**self.exception(), "line": "1"}],
            [{**self.exception(), "line": MAX_FILE_BYTES + 1}],
            [{**self.exception(), "sha256": "a" * 63}],
            [{**self.exception(), "sha256": "A" * 64}],
            [{**self.exception(), "sha256": "z" * 64}],
            [{**self.exception(), "sha256": None}],
            [{**self.exception(), "reason": " "}],
            [{**self.exception(), "reason": False}],
            [
                {
                    key: value
                    for key, value in self.exception().items()
                    if key != "reason"
                }
            ],
            [{**self.exception(), "private-schema-canary": True}],
            [self.exception(), self.exception(content=b"Different public line")],
            [self.exception(line=index + 1) for index in range(129)],
        ]
        for exceptions in invalid:
            with self.subTest(exceptions=exceptions):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(PolicyError) as context:
                        self.policy(Path(directory), exceptions)
                    self.assertNotIn("private-schema-canary", str(context.exception))

    def test_hash_path_and_origin_must_match_and_the_line_may_move(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = self.policy(Path(directory), [self.exception()])
        for origin in (Origin.WORKTREE, Origin.INDEX):
            accepted = Candidate("LICENSE", b"Copyright Private Person\n", origin)
            self.assertEqual(
                [],
                privacy_findings(
                    accepted,
                    PrivacyPolicy(
                        private_values=("private person",),
                        literal_exceptions=policy.literal_exceptions,
                    ),
                    max_findings=1000,
                ),
            )
        for moved in (
            b"Copyright Private Person",
            b"\nCopyright Private Person\n",
            b"New first line\nSecond line\nCopyright Private Person\n",
        ):
            with self.subTest(moved=moved):
                self.assertEqual(
                    [],
                    privacy_findings(
                        Candidate("LICENSE", moved, Origin.WORKTREE),
                        PrivacyPolicy(
                            private_values=("private person",),
                            literal_exceptions=policy.literal_exceptions,
                        ),
                        max_findings=1000,
                    ),
                )
        invalid = (
            Candidate("README.md", b"Copyright Private Person\n", Origin.WORKTREE),
            Candidate("LICENSE", b"\nCopyright Private Person!\n", Origin.WORKTREE),
            Candidate("LICENSE", b"Copyright Private Person \n", Origin.WORKTREE),
            Candidate("LICENSE", b"Copyright Private Person\r\n", Origin.WORKTREE),
            Candidate("LICENSE", b"Copyright Private Person\n", Origin.MESSAGE),
        )
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                findings = privacy_findings(
                    candidate,
                    PrivacyPolicy(
                        private_values=("private person",),
                        literal_exceptions=policy.literal_exceptions,
                    ),
                    max_findings=1000,
                )
                self.assertEqual(
                    ["privacy.private-literal"], [f.rule_id for f in findings]
                )
                self.assertNotIn("Private Person", repr(findings))

    def test_detector_exceptions_follow_their_line(self) -> None:
        content = ("contact" + "@private.dev").encode()
        item = {
            "path": "docs/contact.md",
            "line": 1,
            "rule": "privacy.unapproved-email",
            "sha256": hashlib.sha256(content).hexdigest(),
            "reason": "Approved public contact line.",
        }
        with tempfile.TemporaryDirectory() as directory:
            policy = parse_policy(
                json.dumps(
                    {"schema_version": 1, "privacy_detector_exceptions": [item]}
                ).encode(),
                Path(directory),
            )
        moved = Candidate(
            "docs/contact.md", b"# Contact\n\n" + content + b"\n", Origin.WORKTREE
        )
        self.assertEqual(
            [],
            privacy_findings(
                moved,
                PrivacyPolicy(detector_exceptions=policy.detector_exceptions),
                max_findings=1000,
            ),
        )
        changed = Candidate(
            "docs/contact.md", b"# Contact\n\n" + content + b" now\n", Origin.WORKTREE
        )
        findings = privacy_findings(
            changed,
            PrivacyPolicy(detector_exceptions=policy.detector_exceptions),
            max_findings=1000,
        )
        self.assertEqual(["privacy.unapproved-email"], [f.rule_id for f in findings])
        self.assertEqual(3, findings[0].line)

    def test_github_owner_url_setting_is_off_by_default_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertFalse(
                parse_policy(b'{"schema_version":1}', root).public_github_owner_urls
            )
            enabled = parse_policy(
                b'{"schema_version":1,"public_github_owner_urls":true}', root
            )
            self.assertTrue(enabled.public_github_owner_urls)
            for value in ("1", "yes", "null", '"true"', "[]"):
                with self.subTest(value=value):
                    with self.assertRaises(PolicyError):
                        parse_policy(
                            (
                                '{"schema_version":1,"public_github_owner_urls":'
                                + value
                                + "}"
                            ).encode(),
                            root,
                        )

    def test_github_owner_urls_are_public_only_when_enabled(self) -> None:
        private = ("privateowner",)
        public_forms = (
            b"https://github.com/privateowner/tool.git\n",
            b"pip install 'tool @ git+https://github.com/PrivateOwner/tool.git@abc'\n",
            b"git clone git" + b"@" + b"github.com:privateowner/tool.git\n",
            b"ssh://git@github.com/privateowner/tool\n",
        )
        for content in public_forms:
            with self.subTest(content=content):
                candidate = Candidate("README.md", content, Origin.WORKTREE)
                self.assertNotIn(
                    "privacy.private-literal",
                    [
                        f.rule_id
                        for f in privacy_findings(
                            candidate,
                            PrivacyPolicy(
                                private_values=private, public_github_owner_urls=True
                            ),
                            max_findings=1000,
                        )
                    ],
                )
                self.assertIn(
                    "privacy.private-literal",
                    [
                        f.rule_id
                        for f in privacy_findings(
                            candidate,
                            PrivacyPolicy(private_values=private),
                            max_findings=1000,
                        )
                    ],
                )
        still_private = (
            b"Written by privateowner\n",
            b"https://github.com/privateowner-fork/tool\n",
            b"https://github.com/someone/privateowner\n",
            b"https://gist.github.com/privateowner/abc\n",
            b"https://github.com/privateowner\n",
            b"https://github.com/privateowner/tool by privateowner\n",
        )
        for content in still_private:
            with self.subTest(content=content):
                findings = privacy_findings(
                    Candidate("README.md", content, Origin.WORKTREE),
                    PrivacyPolicy(
                        private_values=private, public_github_owner_urls=True
                    ),
                    max_findings=1000,
                )
                self.assertEqual(
                    ["privacy.private-literal"], [f.rule_id for f in findings]
                )
                self.assertNotIn("privateowner", repr(findings))
        message = Candidate(
            "<commit-message>",
            b"docs: link https://github.com/privateowner/tool\n",
            Origin.MESSAGE,
        )
        self.assertEqual(
            ["privacy.private-literal"],
            [
                f.rule_id
                for f in privacy_findings(
                    message,
                    PrivacyPolicy(
                        private_values=private, public_github_owner_urls=True
                    ),
                    max_findings=1000,
                )
            ],
        )

    def test_later_matches_and_unicode_changes_are_not_exempt(self) -> None:
        public = "Copyright Café Person".encode()
        with tempfile.TemporaryDirectory() as directory:
            policy = self.policy(Path(directory), [self.exception(content=public)])
        for content, line in (
            (public + b"\nOther CAF\xc3\x89 PERSON\n", 2),
            ("Copyright Cafe\u0301 Person\n".encode(), 1),
        ):
            findings = privacy_findings(
                Candidate("LICENSE", content, Origin.WORKTREE),
                PrivacyPolicy(
                    private_values=("café person",),
                    literal_exceptions=policy.literal_exceptions,
                ),
                max_findings=1000,
            )
            self.assertEqual(1, len(findings))
            self.assertEqual(line, findings[0].line)

    def test_exceptions_do_not_suppress_other_privacy_rules(self) -> None:
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
        content = ("Private Person contact" + "@private.dev " + token).encode()
        with tempfile.TemporaryDirectory() as directory:
            policy = self.policy(Path(directory), [self.exception(content=content)])
        findings = privacy_findings(
            Candidate("LICENSE", content + b"\n", Origin.INDEX),
            PrivacyPolicy(
                content_emails=("maintainer@example.com",),
                private_values=("private person",),
                literal_exceptions=policy.literal_exceptions,
            ),
            max_findings=1000,
        )
        self.assertEqual(
            {"privacy.github-token", "privacy.unapproved-email"},
            {finding.rule_id for finding in findings},
        )
        self.assertNotIn(token, repr(findings))

    def test_multiple_exceptions_and_finding_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = self.policy(
                Path(directory), [self.exception(), self.exception(line=2)]
            )
        findings = privacy_findings(
            Candidate("LICENSE", b"Copyright Private Person\n" * 3, Origin.WORKTREE),
            PrivacyPolicy(
                private_values=("private person", "copyright"),
                literal_exceptions=policy.literal_exceptions,
            ),
            max_findings=1,
        )
        self.assertEqual(1, len(findings))
        self.assertEqual(3, findings[0].line)
        for content in (
            b"Copyright Private Person\n" * 3,
            b"Changed Copyright Private Person\n",
        ):
            findings = privacy_findings(
                Candidate("LICENSE", content, Origin.WORKTREE),
                PrivacyPolicy(
                    private_values=("private person", "copyright"),
                    literal_exceptions=policy.literal_exceptions,
                ),
                max_findings=1000,
            )
            self.assertEqual(2, len(findings))

    def test_index_hashes_apply_per_scope_and_never_exempt_messages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            policy = self.policy(root, [self.exception()])
            values = ("private person",)
            public = root / "LICENSE"
            public.write_text("Copyright Private Person\n", encoding="utf-8")
            (root / ".repo-policy.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "private_literal_exceptions": [self.exception()],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            run_git(root, "add", "--", "LICENSE", ".repo-policy.json")
            public.write_text("Changed Private Person\n", encoding="utf-8")
            message = root / ".git" / "COMMIT_EDITMSG"
            message.write_text("Copyright Private Person\n", encoding="utf-8")

            def literal_paths(result):
                self.assertNotIn("Private Person", repr(result))
                return [
                    item.path
                    for item in result.findings
                    if item.rule_id == "privacy.private-literal"
                ]

            with patch("first_commit.validation.scan_staged", return_value=()):
                staged = validation.staged(root, policy, values)
            self.assertEqual([], literal_paths(staged))
            self.assertEqual(
                ["LICENSE"], literal_paths(validation.working(root, policy, values))
            )
            self.assertEqual(
                ["<commit-message>"],
                literal_paths(validation.message(root, policy, message, values)),
            )

            public.write_text("Changed Private Person\n", encoding="utf-8")
            run_git(root, "add", "--", "LICENSE")
            public.write_text("Copyright Private Person\n", encoding="utf-8")
            with patch("first_commit.validation.scan_staged", return_value=()):
                staged = validation.staged(root, policy, values)
            self.assertEqual(["LICENSE"], literal_paths(staged))
            self.assertEqual(
                [], literal_paths(validation.working(root, policy, values))
            )


if __name__ == "__main__":
    unittest.main()
