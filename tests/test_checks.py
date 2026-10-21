import unittest

from first_commit.checks.identity import (
    SIGNATURE_TRUST_RULE,
    SIGNATURE_TRUST_SUMMARY,
    TRUST_SETTING,
    identity_findings,
    signature_trust_findings,
)
from first_commit.checks.privacy import (
    PrivacyPolicy,
    forbidden_path_findings,
    privacy_findings,
)
from first_commit.checks.text import no_commit_findings, text_findings
from first_commit.hooks import GITHUB_REPOSITORY
from first_commit.models import Candidate, Origin
from first_commit.policy_fields import ForbiddenPath

COMPLETE_IDENTITY = {
    "user.name": "Example Person",
    "user.email": "person@example.com",
    "user.signingkey": "example.pub",
    "gpg.format": "ssh",
    "commit.gpgsign": "true",
    "tag.gpgsign": "true",
    "user.useConfigOnly": "true",
}


def candidate(path: str, content: bytes) -> Candidate:
    return Candidate(path=path, content=content, origin=Origin.WORKTREE)


class ChecksTest(unittest.TestCase):
    def test_forbidden_paths_match_without_file_content_or_globs(self) -> None:
        policies = (
            ForbiddenPath("exact", "private/customer.csv", "Private export."),
            ForbiddenPath("prefix", "exports/", "Generated exports are private."),
            ForbiddenPath("suffix", ".kdbx", "Password vaults are private."),
        )
        findings = forbidden_path_findings(
            (
                "private/customer.csv",
                "exports/archive.bin",
                "nested/passwords.kdbx",
                "exports-old/archive.bin",
                "nested/passwords.KDBX",
            ),
            policies,
            max_findings=10,
        )

        self.assertEqual(
            [
                "exports/archive.bin",
                "nested/passwords.kdbx",
                "private/customer.csv",
            ],
            [item.path for item in findings],
        )
        self.assertTrue(
            all(item.rule_id == "privacy.forbidden-path" for item in findings)
        )
        self.assertIn("Generated exports are private.", findings[0].summary)
        self.assertEqual(
            1, len(forbidden_path_findings(("a.kdbx",), policies, max_findings=1))
        )
        self.assertEqual(
            [], forbidden_path_findings(("a.kdbx",), policies, max_findings=0)
        )

    def test_no_commit_marker_requires_a_standalone_comment(self) -> None:
        content = (
            b"Generated starter text for manual review.\n"
            b"<!-- @no-commit -->\n"
            b"Mentioning @no-commit in prose is safe.\n"
            b"# @no-commit\n"
        )
        findings = no_commit_findings(
            candidate("README.md", content), max_findings=1000
        )
        self.assertEqual([2, 4], [item.line for item in findings])
        self.assertEqual(
            ["scaffold.no-commit", "scaffold.no-commit"],
            [item.rule_id for item in findings],
        )
        self.assertTrue(all("@no-commit" not in item.summary for item in findings))
        self.assertEqual(
            [], no_commit_findings(candidate("blob", b"\xff"), max_findings=1000)
        )
        self.assertEqual(
            [], no_commit_findings(candidate("blob", b"a\0b"), max_findings=1000)
        )
        self.assertEqual(
            [], no_commit_findings(candidate("README.md", content), max_findings=0)
        )
        self.assertEqual(
            1, len(no_commit_findings(candidate("README.md", content), max_findings=1))
        )

    def test_no_commit_marker_lines_count_only_newlines(self) -> None:
        for separator in ("\f", "\v", "\x1c", "\N{LINE SEPARATOR}"):
            with self.subTest(separator=repr(separator)):
                content = f"intro{separator}more\n<!-- @no-commit -->\n".encode()
                findings = no_commit_findings(
                    candidate("README.md", content), max_findings=1000
                )
                self.assertEqual([2], [item.line for item in findings])

    def test_a_marker_after_another_line_break_on_its_line_is_still_found(self) -> None:
        for text, line in (
            ("intro\r<!-- @no-commit -->\r", 1),
            ("intro\f<!-- @no-commit -->\n", 1),
            ("intro\n<!-- @no-commit -->\N{LINE SEPARATOR}rest\n", 2),
        ):
            with self.subTest(text=repr(text)):
                findings = no_commit_findings(
                    candidate("README.md", text.encode()), max_findings=1000
                )
                self.assertEqual([line], [item.line for item in findings])

    def test_text_handles_binary_invalid_and_bounded_findings(self) -> None:
        self.assertEqual(
            [], text_findings(candidate("value.txt", b"x\0y"), max_findings=1000)
        )
        invalid = text_findings(candidate("value.txt", b"\xff"), max_findings=1000)
        self.assertEqual(["text.invalid-utf8"], [item.rule_id for item in invalid])
        self.assertEqual(
            [], text_findings(candidate("value.txt", b"bad\n"), max_findings=0)
        )
        self.assertEqual(
            ["text.merge-marker"],
            [
                item.rule_id
                for item in text_findings(
                    candidate("value.txt", b"<<<<<<< branch\n"), max_findings=1
                )
            ],
        )
        self.assertEqual(
            ["text.control-character"],
            [
                item.rule_id
                for item in text_findings(
                    candidate("value.txt", b"safe\vvalue\n"), max_findings=1
                )
            ],
        )
        self.assertTrue(
            text_findings(
                candidate("value.txt", b"no final newline"), max_findings=1000
            )
        )

    def test_privacy_handles_non_text_and_all_pattern_classes(self) -> None:
        self.assertEqual(
            [],
            privacy_findings(
                candidate("value.txt", b"private\n"), PrivacyPolicy(), max_findings=0
            ),
        )
        self.assertEqual(
            [],
            privacy_findings(
                candidate("value.txt", b"x\0y"), PrivacyPolicy(), max_findings=10
            ),
        )
        self.assertEqual(
            [],
            privacy_findings(
                candidate("value.txt", b"\xff"), PrivacyPolicy(), max_findings=1000
            ),
        )
        values = (
            b"-----BEGIN " + b"PRIVATE KEY-----\n",
            b"AKIA" + b"1234567890ABCDEF\n",
            b"SHA256:" + b"abcdefghijklmnopqrstuv\n",
            b"/Users/" + b"example/private\n",
        )
        for content in values:
            with self.subTest(content=content):
                self.assertTrue(
                    privacy_findings(
                        candidate("value.txt", content),
                        PrivacyPolicy(),
                        max_findings=1000,
                    )
                )
        self.assertEqual(
            [],
            privacy_findings(
                candidate("value.txt", b"safe\n"),
                PrivacyPolicy(private_values=("absent",)),
                max_findings=1000,
            ),
        )
        self.assertEqual(
            1,
            len(
                privacy_findings(
                    candidate("value.txt", b"private\n"),
                    PrivacyPolicy(private_values=("private",)),
                    max_findings=1,
                )
            ),
        )
        bounded = privacy_findings(
            candidate(
                "value.txt",
                ("ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890\n").encode(),
            ),
            PrivacyPolicy(),
            max_findings=1,
        )
        self.assertEqual(1, len(bounded))

    def test_reports_text_hygiene_without_content(self) -> None:
        canary = b"private-canary   "
        findings = text_findings(candidate("value.txt", canary), max_findings=1000)
        rendered = repr(findings)

        self.assertTrue(findings)
        self.assertNotIn("private-canary", rendered)

    def test_text_and_privacy_checks_respect_finding_budget(self) -> None:
        value = candidate(
            "value.txt",
            (("person" + "@" + "private.dev   \n") * 100).encode("utf-8"),
        )

        text = text_findings(value, max_findings=2)
        privacy = privacy_findings(
            value,
            PrivacyPolicy(content_emails=("maintainer@example.com",)),
            max_findings=3,
        )

        self.assertEqual(2, len(text))
        self.assertEqual(3, len(privacy))

    def test_a_merge_marker_is_seven_characters_then_a_space_or_end(self) -> None:
        content = (
            b"T\n==========\nG\n=======\n<<<<<<<<\n<<<<<<<\n>>>>>>> b\n======= theirs\n"
        )
        findings = text_findings(candidate("index.rst", content), max_findings=100)
        lines = [item.line for item in findings if item.rule_id == "text.merge-marker"]
        self.assertEqual([4, 6, 7, 8], lines)

    def test_reports_vertical_tab_and_diff3_conflict_marker(self) -> None:
        findings = text_findings(
            candidate("value.txt", b"safe\vvalue\n||||||| base\n"), max_findings=1000
        )
        rules = {finding.rule_id for finding in findings}

        self.assertIn("text.control-character", rules)
        self.assertIn("text.merge-marker", rules)

    def test_reports_delete_character_like_other_control_characters(self) -> None:
        findings = text_findings(
            candidate("value.txt", b"safe\x7fvalue\n\tindented\n"), max_findings=1000
        )

        self.assertEqual(
            [("text.control-character", 1)],
            [(item.rule_id, item.line) for item in findings],
        )

    def test_reports_private_pattern_without_matched_value(self) -> None:
        secret = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
        findings = privacy_findings(
            candidate("value.txt", (secret + "\n").encode()),
            PrivacyPolicy(content_emails=("maintainer@example.com",)),
            max_findings=1000,
        )
        rendered = repr(findings)

        self.assertTrue(findings)
        self.assertNotIn(secret, rendered)

    def test_reports_unapproved_email_but_accepts_reserved_domains(self) -> None:
        rejected = privacy_findings(
            candidate("value.txt", ("person" + "@" + "private.dev\n").encode()),
            PrivacyPolicy(content_emails=("maintainer@example.com",)),
            max_findings=1000,
        )
        for domain in (
            "example.com",
            "example.net",
            "example.org",
            "fixture.invalid",
            "fixture.test",
        ):
            with self.subTest(domain=domain):
                accepted = privacy_findings(
                    candidate("value.txt", f"person@{domain}\n".encode()),
                    PrivacyPolicy(content_emails=("maintainer@example.com",)),
                    max_findings=1000,
                )
                self.assertEqual([], accepted)
        approved = "maintainer" + "@" + "private.dev"
        exact = privacy_findings(
            candidate("value.txt", (approved + "\n").encode()),
            PrivacyPolicy(content_emails=(approved,)),
            max_findings=1000,
        )

        self.assertTrue(rejected)
        self.assertEqual([], exact)

    def test_reserved_domain_matching_does_not_accept_lookalikes(self) -> None:
        for domain in ("notexample.com", "example.com.evil.dev", "invalid.dev"):
            with self.subTest(domain=domain):
                findings = privacy_findings(
                    candidate("value.txt", f"person@{domain}\n".encode()),
                    PrivacyPolicy(),
                    max_findings=1000,
                )
                self.assertEqual(
                    ["privacy.unapproved-email"],
                    [item.rule_id for item in findings],
                )

    def test_protocol_algorithm_identifiers_are_not_personal_emails(self) -> None:
        for token in (
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "ssh-ed25519-cert-v01@openssh.com",
            "chacha20-poly1305@openssh.com",
            "curve25519-sha256@libssh.org",
        ):
            with self.subTest(token=token):
                findings = privacy_findings(
                    candidate("keys.py", f'TYPE = "{token}"\n'.encode()),
                    PrivacyPolicy(),
                    max_findings=1000,
                )
                self.assertEqual([], findings)

    def test_protocol_domain_matching_does_not_accept_lookalikes(self) -> None:
        for domain in ("openssh.com.evil.dev", "notopenssh.com", "libssh.org.evil"):
            with self.subTest(domain=domain):
                findings = privacy_findings(
                    candidate("keys.py", f"person@{domain}\n".encode()),
                    PrivacyPolicy(),
                    max_findings=1000,
                )
                self.assertEqual(
                    ["privacy.unapproved-email"],
                    [item.rule_id for item in findings],
                )

    def test_github_ssh_transport_user_is_not_a_personal_email(self) -> None:
        service_address = "git" + "@" + "github.com"
        for value in (
            "ssh://" + service_address + "/" + GITHUB_REPOSITORY,
            "git+ssh://" + service_address + "/" + GITHUB_REPOSITORY,
            "git clone " + service_address + ":" + GITHUB_REPOSITORY + ".git",
            service_address + ":" + GITHUB_REPOSITORY,
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    [],
                    privacy_findings(
                        candidate("hooks.yaml", value.encode()),
                        PrivacyPolicy(),
                        max_findings=1000,
                    ),
                )
        for value in (
            service_address,
            "https://" + service_address + "/" + GITHUB_REPOSITORY,
            "ssh://" + service_address + ".evil/" + GITHUB_REPOSITORY,
            "https://" + service_address + ":" + GITHUB_REPOSITORY,
        ):
            with self.subTest(value=value):
                findings = privacy_findings(
                    candidate("hooks.yaml", value.encode()),
                    PrivacyPolicy(),
                    max_findings=1000,
                )
                self.assertEqual(
                    ["privacy.unapproved-email"], [item.rule_id for item in findings]
                )

    def test_identity_reports_each_missing_or_invalid_requirement(self) -> None:
        findings = identity_findings({"user.email": "not-allowed" + "@example.net"}, ())
        self.assertEqual(
            {
                "git.local-name",
                "git.allowed-email",
                "git.signing-key",
                "git.ssh-format",
                "git.signed-commits",
                "git.signed-tags",
                "git.explicit-identity",
            },
            {item.rule_id for item in findings},
        )
        values = dict(COMPLETE_IDENTITY)
        del values["user.email"]
        self.assertEqual(
            ["git.local-email", "git.allowed-email"],
            [item.rule_id for item in identity_findings(values, ())],
        )

    def test_identity_summaries_name_the_setting_and_its_required_value(self) -> None:
        summaries = {
            item.rule_id: item.summary
            for item in identity_findings({"user.email": "person@example.com"}, ())
        }
        self.assertEqual(
            {
                "git.local-name": "user.name is not set in .git/config.",
                "git.allowed-email": (
                    "user.email in .git/config is not the email in "
                    ".local/first-commit/contributor.json."
                ),
                "git.signing-key": "user.signingkey is not set in .git/config.",
                "git.ssh-format": "gpg.format is not ssh in .git/config.",
                "git.signed-commits": "commit.gpgsign is not true in .git/config.",
                "git.signed-tags": "tag.gpgsign is not true in .git/config.",
                "git.explicit-identity": (
                    "user.useConfigOnly is not true in .git/config."
                ),
            },
            summaries,
        )
        self.assertEqual(
            "user.email is not set in .git/config.",
            identity_findings({}, ())[1].summary,
        )

    def test_identity_email_allowlist_is_deny_all_when_empty(self) -> None:
        findings = identity_findings(COMPLETE_IDENTITY, ())

        self.assertEqual(["git.allowed-email"], [item.rule_id for item in findings])

    def test_identity_requires_complete_local_ssh_policy(self) -> None:
        values = dict(COMPLETE_IDENTITY)
        allowed = ("person@example.com",)

        self.assertEqual([], identity_findings(values, allowed))
        del values["tag.gpgsign"]
        findings = identity_findings(values, allowed)
        self.assertEqual(["git.signed-tags"], [f.rule_id for f in findings])

    def test_identity_accepts_git_boolean_spellings(self) -> None:
        values = {
            **COMPLETE_IDENTITY,
            "commit.gpgsign": "yes",
            "tag.gpgsign": "on",
            "user.useConfigOnly": "1",
        }

        self.assertEqual([], identity_findings(values, ("person@example.com",)))

    def test_signature_trust_warning_leaves_the_command_to_its_fix_line(self) -> None:
        findings = signature_trust_findings(COMPLETE_IDENTITY)

        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("git.signature-verification-trust", finding.rule_id)
        self.assertEqual(SIGNATURE_TRUST_RULE, finding.rule_id)
        self.assertEqual("warning", finding.severity)
        self.assertEqual(".git/config", finding.path)
        self.assertIsNone(finding.line)
        self.assertEqual(SIGNATURE_TRUST_SUMMARY, finding.summary)
        self.assertNotIn("setup", finding.summary)
        self.assertNotIn("run ", finding.summary.lower())
        self.assertEqual(
            "gpg.ssh.allowedSignersFile is not set in .git/config, so signed commits "
            "may not verify in this checkout.",
            finding.summary,
        )
        self.assertEqual([finding.summary], finding.summary.splitlines())

    def test_signature_trust_warning_clears_once_trust_is_configured(self) -> None:
        self.assertEqual(
            [],
            signature_trust_findings(
                {
                    **COMPLETE_IDENTITY,
                    TRUST_SETTING: ".local/first-commit/allowed-signers",
                }
            ),
        )
        self.assertEqual(
            [SIGNATURE_TRUST_RULE],
            [
                item.rule_id
                for item in signature_trust_findings(
                    {**COMPLETE_IDENTITY, TRUST_SETTING: ""}
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
