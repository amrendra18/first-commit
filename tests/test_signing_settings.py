import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from first_commit.checks.identity import identity_findings
from first_commit.models import Severity
from first_commit.policy import parse_policy
from first_commit.validation import message
from tests.support import commit_message, initialize_repository, run_git
from tests.validation_support import IDENTITY, commit_identity

APPROVED = (IDENTITY["user.email"],)
# Each signing or identity setting the commit hooks require, the rule that reports
# it, and the values that turn it off. None means the setting is missing.
OFF_VALUES = (None, "", "false", "no", "off", "0")
REQUIRED = (
    ("commit.gpgsign", "git.signed-commits", OFF_VALUES),
    ("tag.gpgsign", "git.signed-tags", OFF_VALUES),
    ("user.useConfigOnly", "git.explicit-identity", OFF_VALUES),
    ("gpg.format", "git.ssh-format", (None, "", "openpgp", "x509")),
    ("user.signingkey", "git.signing-key", (None, "")),
)


def _changed(key: str, value: str | None) -> dict[str, str]:
    settings = dict(IDENTITY)
    if value is None:
        del settings[key]
    else:
        settings[key] = value
    return settings


class SigningSettingsOffTest(unittest.TestCase):
    def test_each_setting_turned_off_or_missing_is_an_error(self) -> None:
        self.assertEqual([], identity_findings(IDENTITY, APPROVED))
        for key, rule_id, values in REQUIRED:
            for value in values:
                with self.subTest(key=key, value=value):
                    findings = identity_findings(_changed(key, value), APPROVED)
                    self.assertEqual(
                        [(rule_id, Severity.ERROR)],
                        [(item.rule_id, item.severity) for item in findings],
                    )


class CommitHookSigningSettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        for key, value in IDENTITY.items():
            run_git(self.root, "config", "--local", key, value)
        self.message_path = self.root / ".git/COMMIT_EDITMSG"
        self.message_path.write_text(commit_message("feat: add checks"), "utf-8")
        self.policy = replace(
            parse_policy(b'{"schema_version":1}', self.root),
            contributor_emails=APPROVED,
        )

    def rules(self) -> tuple[set[str], bool]:
        with commit_identity():
            result = message(self.root, self.policy, self.message_path)
        errors = {
            item.rule_id for item in result.findings if item.severity == Severity.ERROR
        }
        return errors, result.passed

    def test_the_commit_msg_hook_blocks_each_setting_turned_off(self) -> None:
        required = {rule_id for _, rule_id, _ in REQUIRED}
        self.assertEqual(set(), self.rules()[0] & required)
        for key, rule_id, values in REQUIRED:
            with self.subTest(key=key, value=values[-1]):
                run_git(self.root, "config", "--local", key, values[-1])
                errors, passed = self.rules()
                run_git(self.root, "config", "--local", key, IDENTITY[key])
                self.assertEqual({rule_id}, errors & required)
                self.assertFalse(passed)


if __name__ == "__main__":
    unittest.main()
