import tempfile
from pathlib import Path
from unittest.mock import patch

from first_commit.checks.identity import ALLOWED_SIGNERS_PATH, TRACKED_SIGNERS_RULE
from first_commit.contributor import Contributor
from first_commit.models import SetupError, Severity
from first_commit.policy import parse_policy
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_trust import allowed_signers_line
from first_commit.validation import doctor
from tests.setup_support import REVISION, SetupFixture, synthetic_key
from tests.support import run_git

OTHER_KEY = synthetic_key(data=b"\x07" * 32)


class ExistingTrustFileTest(SetupFixture):
    def signers(self, content: bytes) -> None:
        self.initialized_with_hooks()
        path = self.root / ALLOWED_SIGNERS_PATH
        path.parent.mkdir(parents=True)
        path.write_bytes(content)
        path.chmod(0o600)

    def own_line(self) -> bytes:
        return allowed_signers_line(self.root, self.person)

    def trust(self) -> tuple[str, ...]:
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            return setup_repository(
                self.root,
                SetupRequest(revision=REVISION, trust_self=True),
                contributor=self.person,
            )

    def setUp(self) -> None:
        super().setUp()
        keys = tempfile.TemporaryDirectory(prefix="first-commit keys ")
        self.addCleanup(keys.cleanup)
        key = Path(keys.name) / "id_ed25519.pub"
        key.write_text(synthetic_key() + "\n", "utf-8")
        self.person = Contributor(self.person.name, self.person.email, str(key))

    def test_a_file_that_trusts_another_key_is_refused(self) -> None:
        email = self.person.email
        own_type, own_data = synthetic_key().split()
        for name, extra in (
            ("another key", f"someone@example.net {OTHER_KEY}\n"),
            ("any principal", f"* {OTHER_KEY}\n"),
            ("own key for any principal", f"* {own_type} {own_data}\n"),
            ("negated principal", f"!x@example.net,{email} {own_type} {own_data}\n"),
            ("key only in the comment", f"{email} {OTHER_KEY} {own_type} {own_data}\n"),
            (
                "certificate authority",
                f"{email} cert-authority {own_type} {own_data}\n",
            ),
            ("open quote", f'{email} namespaces="git {own_type} {own_data}\n'),
            ("control character", f"{email}\x0b {own_type} {own_data}\n"),
        ):
            with self.subTest(name=name):
                self.setUp()
                content = self.own_line() + extra.encode("utf-8")
                self.signers(content)
                with self.assertRaisesRegex(SetupError, "must hold only lines of your"):
                    self.trust()
                self.assertEqual(
                    content, (self.root / ALLOWED_SIGNERS_PATH).read_bytes()
                )

    def test_a_file_that_is_not_utf8_or_lacks_your_email_is_refused(self) -> None:
        for content, message in (
            (b"\xff\n", "must hold only lines of your"),
            (b"# only a comment\n", "does not hold your email"),
        ):
            with self.subTest(content=content):
                self.setUp()
                self.signers(content)
                with self.assertRaisesRegex(SetupError, message):
                    self.trust()

    def test_doctor_reports_a_tracked_trust_file_as_an_error(self) -> None:
        self.signers(self.own_line())
        self.trust()
        policy = parse_policy(b'{"schema_version": 1}', self.root, self.person)

        def rules() -> dict[str, Severity]:
            with (
                patch("first_commit.validation.validate_scanner"),
                patch("first_commit.validation.hook_findings", return_value=[]),
            ):
                result = doctor(self.root, policy)
            return {item.rule_id: item.severity for item in result.findings}

        self.assertNotIn(TRACKED_SIGNERS_RULE, rules())
        # A pulled commit can add the ignored file with git add --force.
        run_git(self.root, "add", "--force", "--", ALLOWED_SIGNERS_PATH)
        self.assertEqual(Severity.ERROR, rules()[TRACKED_SIGNERS_RULE])
