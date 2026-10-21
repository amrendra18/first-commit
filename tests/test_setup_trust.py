import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.checks.identity import ALLOWED_SIGNERS_PATH
from first_commit.contributor import (
    CONTRIBUTOR_PATH,
    Contributor,
)
from first_commit.gitleaks_scanner import DependencyError
from first_commit.models import SetupError
from first_commit.policy import parse_policy
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_trust import (
    SSH_SIGNING_KEY_TYPES,
    allowed_signers_line,
)
from first_commit.validation import doctor
from tests.setup_support import (
    PRIVATE_KEY_HEADER,
    REVISION,
    SetupFixture,
    create_allowed_signers,
    synthetic_key,
)
from tests.support import run_git


class LocalSignatureTrustTest(SetupFixture):
    def setUp(self) -> None:
        super().setUp()
        keys = tempfile.TemporaryDirectory(prefix="first-commit keys ")
        self.addCleanup(keys.cleanup)
        self.keys = Path(keys.name)

    def public_key(self, name: str = "id_ed25519.pub", line: str | None = None) -> Path:
        path = self.keys / name
        path.write_text((line if line is not None else synthetic_key()) + "\n", "utf-8")
        return path

    def person_with(self, reference: str) -> Contributor:
        return Contributor(self.person.name, self.person.email, reference)

    def signers(self) -> Path:
        return self.root / ALLOWED_SIGNERS_PATH

    def setting(self) -> str | None:
        try:
            raw = run_git(
                self.root, "config", "--local", "--get", "gpg.ssh.allowedSignersFile"
            )
        except subprocess.CalledProcessError:
            return None
        return raw.stdout.decode("utf-8").strip()

    def apply(
        self, person: Contributor, *, trust_self: bool = False
    ) -> tuple[str, ...]:
        self.initialized_with_hooks()
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            return setup_repository(
                self.root,
                SetupRequest(revision=REVISION, trust_self=trust_self),
                contributor=person,
            )

    def test_trust_is_off_by_default_and_changes_nothing(self) -> None:
        actions = self.apply(self.person_with(str(self.public_key())))

        self.assertFalse(self.signers().exists())
        self.assertIsNone(self.setting())
        self.assertNotIn("Local signature trust", "\n".join(actions))
        self.assertIn(
            "Signature verification: not performed; trust is not checked", actions
        )

    def test_trust_self_writes_one_expected_line_owner_private(self) -> None:
        key = self.public_key()
        key_type, key_data = key.read_text("utf-8").split()[:2]

        actions = self.apply(self.person_with(str(key)), trust_self=True)

        self.assertEqual(
            f"{self.person.email} {key_type} {key_data}\n",
            self.signers().read_text("utf-8"),
        )
        self.assertEqual(0o600, self.signers().stat().st_mode & 0o777)
        self.assertEqual(ALLOWED_SIGNERS_PATH, self.setting())
        self.assertIn(
            f"Local signature trust: wrote {ALLOWED_SIGNERS_PATH}; "
            "set gpg.ssh.allowedSignersFile",
            actions,
        )
        self.assertIn(
            "Signature verification: local trust is configured; "
            "no existing signature was verified",
            actions,
        )
        self.assertNotIn(
            "Signature verification: not performed; trust is not checked", actions
        )

    def test_trust_self_accepts_a_repository_relative_reference(self) -> None:
        self.initialized_with_hooks()
        (self.root / "keys").mkdir()
        (self.root / "keys/signing.pub").write_text(synthetic_key() + "\n", "utf-8")
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, trust_self=True),
                contributor=self.person_with("keys/signing.pub"),
            )

        self.assertTrue(self.signers().read_text("utf-8").startswith(self.person.email))

    def test_trust_self_accepts_every_supported_signing_key_type(self) -> None:
        for key_type in SSH_SIGNING_KEY_TYPES:
            with self.subTest(key_type=key_type):
                line = synthetic_key(key_type)
                self.assertEqual(
                    f"{self.person.email} {line}\n".encode(),
                    allowed_signers_line(
                        self.root,
                        self.person_with(
                            str(self.public_key(key_type + ".pub", line + " host"))
                        ),
                    ),
                )

    def test_trust_self_preview_states_actions_and_writes_nothing(self) -> None:
        self.initialized_with_hooks()
        preview = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, trust_self=True, dry_run=True),
            contributor=self.person_with(str(self.public_key())),
        )

        self.assertIn(
            f"Local signature trust: would write {ALLOWED_SIGNERS_PATH}; "
            "would set gpg.ssh.allowedSignersFile",
            preview,
        )
        self.assertIn(
            "Signature verification: local trust would be configured; "
            "no existing signature was verified",
            preview,
        )
        self.assertFalse(self.signers().exists())
        self.assertIsNone(self.setting())

    def test_blank_trust_preview_states_actions_without_identity(self) -> None:
        preview = setup_repository(
            self.root, SetupRequest(revision=REVISION, trust_self=True, dry_run=True)
        )

        self.assertIn(
            f"Local signature trust: would write {ALLOWED_SIGNERS_PATH}; "
            "would set gpg.ssh.allowedSignersFile",
            preview,
        )
        self.assertEqual([], list(self.root.iterdir()))

        run_git(self.root, "init", "-q")
        self.local_hooks()
        initialized = setup_repository(
            self.root, SetupRequest(revision=REVISION, trust_self=True, dry_run=True)
        )
        self.assertIn("Local contributor: required", initialized)
        self.assertIn(
            f"Local signature trust: would write {ALLOWED_SIGNERS_PATH}; "
            "would set gpg.ssh.allowedSignersFile",
            initialized,
        )
        self.assertFalse(self.signers().exists())

    def existing_signers(self, content: bytes, *, track: bool = False) -> None:
        self.initialized_with_hooks()
        (self.root / ".local/first-commit").mkdir(parents=True)
        self.signers().write_bytes(content)
        self.signers().chmod(0o600)
        if track:
            run_git(self.root, "add", "--force", "--", ALLOWED_SIGNERS_PATH)

    def trust_existing(self) -> tuple[str, ...]:
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            return setup_repository(
                self.root,
                SetupRequest(revision=REVISION, trust_self=True),
                contributor=self.person_with(str(self.public_key())),
            )

    def test_existing_trust_file_is_preserved_and_reported(self) -> None:
        key_type, key_data = synthetic_key().split()
        preserved = (
            b"# Reviewed signers.\n\n"
            + f'other@example.net,{self.person.email} namespaces="git" {key_type} '
            f"{key_data} c\r\n".encode()
        )
        self.existing_signers(preserved)

        actions = self.trust_existing()

        self.assertEqual(preserved, self.signers().read_bytes())
        self.assertEqual(ALLOWED_SIGNERS_PATH, self.setting())
        self.assertIn(
            f"Local signature trust: retained existing {ALLOWED_SIGNERS_PATH}; "
            "set gpg.ssh.allowedSignersFile",
            actions,
        )

    def test_existing_trust_file_must_be_untracked_and_hold_the_own_key(self) -> None:
        line = allowed_signers_line(self.root, self.person_with(str(self.public_key())))
        for name, content, track, message in (
            ("tracked", line, True, "tracked by Git"),
            ("other key", b"someone@example.net ssh-ed25519 Other\n", False, "your"),
            ("other email", line.replace(b"public@", b"other@"), False, "your"),
        ):
            with self.subTest(name=name):
                self.setUp()
                self.existing_signers(content, track=track)
                with self.assertRaisesRegex(SetupError, message):
                    self.trust_existing()
                self.assertEqual(content, self.signers().read_bytes())
                self.assertIsNone(self.setting())

    def test_existing_trust_setting_is_preserved_and_reported(self) -> None:
        self.initialized_with_hooks()
        run_git(
            self.root,
            "config",
            "--local",
            "gpg.ssh.allowedSignersFile",
            "project/signers",
        )

        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            actions = setup_repository(
                self.root,
                SetupRequest(revision=REVISION, trust_self=True),
                contributor=self.person_with(str(self.public_key())),
            )

        self.assertEqual("project/signers", self.setting())
        self.assertFalse(self.signers().exists())
        self.assertIn(
            "Local signature trust: retained existing gpg.ssh.allowedSignersFile",
            actions,
        )

    def test_rollback_removes_a_trust_file_setup_created(self) -> None:
        self.initialized_with_hooks()
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[object()]),
        ):
            with self.assertRaisesRegex(SetupError, "readiness"):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, trust_self=True),
                    contributor=self.person_with(str(self.public_key())),
                )

        self.assertFalse(self.signers().exists())
        self.assertFalse((self.root / ".local/first-commit").exists())
        self.assertIsNone(self.setting())

    def test_rollback_preserves_a_trust_file_edited_during_setup(self) -> None:
        self.initialized_with_hooks()
        edited = b"edited@example.net ssh-ed25519 ConcurrentEdit\n"

        def concurrent_edit(root, arguments, **_options):
            if arguments[0] == "install-hooks":
                (root / ALLOWED_SIGNERS_PATH).write_bytes(edited)
                raise DependencyError("hook.environment.install: synthetic failure")

        with patch(
            "first_commit.setup_apply.run_pre_commit", side_effect=concurrent_edit
        ):
            with self.assertRaises(DependencyError):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, trust_self=True),
                    contributor=self.person_with(str(self.public_key())),
                )

        self.assertEqual(edited, self.signers().read_bytes())

    def test_repeat_setup_without_the_flag_preserves_trust(self) -> None:
        key = str(self.public_key())
        self.apply(self.person_with(key), trust_self=True)
        content = self.signers().read_bytes()
        mode = self.signers().stat().st_mode & 0o777

        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            repeated = setup_repository(
                self.root,
                SetupRequest(revision=REVISION),
                contributor=self.person_with(key),
            )

        self.assertEqual(content, self.signers().read_bytes())
        self.assertEqual(mode, self.signers().stat().st_mode & 0o777)
        self.assertEqual(ALLOWED_SIGNERS_PATH, self.setting())
        self.assertNotIn("Local signature trust", "\n".join(repeated))
        self.assertIn(
            "Signature verification: local trust is configured; "
            "no existing signature was verified",
            repeated,
        )

    def test_unusable_key_references_are_rejected_before_any_mutation(self) -> None:
        self.initialized_with_hooks()
        canary = "private-key-canary"
        directory = self.keys / "directory.pub"
        directory.mkdir()
        link = self.keys / "link.pub"
        link.symlink_to(self.public_key("target.pub"))
        references = {
            "missing": str(self.keys / "absent.pub"),
            "directory": str(directory),
            "symlink": str(link),
            "private name": str(self.keys / "id_ed25519"),
            "private suffix": str(self.public_key("key.pem", synthetic_key())),
            "escaping": "../outside.pub",
            "oversized": str(
                self.public_key("big.pub", synthetic_key() + " " + canary * 2000)
            ),
            "two keys": str(
                self.public_key("two.pub", synthetic_key() + "\n" + synthetic_key())
            ),
            "malformed data": str(self.public_key("bad.pub", "ssh-ed25519 not-base64")),
            "mismatched data": str(
                self.public_key("swap.pub", "ssh-rsa " + synthetic_key().split()[1])
            ),
            "wrong type": str(self.public_key("dss.pub", synthetic_key("ssh-dss"))),
            "one field": str(self.public_key("one.pub", "ssh-ed25519")),
            "private material": str(
                self.public_key("leaked.pub", PRIVATE_KEY_HEADER + " " + canary)
            ),
            "non-ascii": str(self.public_key("utf8.pub", "ssh-ed25519 é" + canary)),
            "empty": str(self.public_key("empty.pub", "")),
        }
        for label, reference in references.items():
            with self.subTest(reference=label):
                with self.assertRaises(SetupError) as context:
                    setup_repository(
                        self.root,
                        SetupRequest(revision=REVISION, trust_self=True),
                        contributor=self.person_with(reference),
                    )
                message = str(context.exception)
                self.assertNotIn(canary, message)
                self.assertNotIn(reference, message)
                self.assertFalse((self.root / ".repo-policy.json").exists())
                self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
                self.assertFalse(self.signers().exists())
                self.assertIsNone(self.setting())

    def test_private_key_shaped_reference_is_rejected_without_reading(self) -> None:
        secret = self.keys / "id_ed25519"
        secret.write_text(PRIVATE_KEY_HEADER + "\ncanary\n", "utf-8")
        opened = []
        real_open = os.open

        def record(path, *arguments, **keywords):
            opened.append(str(path))
            return real_open(path, *arguments, **keywords)

        with patch("first_commit.paths.os.open", side_effect=record):
            with self.assertRaisesRegex(SetupError, "public-key"):
                allowed_signers_line(self.root, self.person_with(str(secret)))

        self.assertEqual([], [item for item in opened if item == str(secret)])

    def test_unknown_home_reference_is_refused_without_a_crash(self) -> None:
        with self.assertRaisesRegex(SetupError, "readable bounded regular"):
            allowed_signers_line(
                self.root, self.person_with("~no-such-user-for-first-commit/key.pub")
            )

    def test_unsafe_trust_folder_is_rejected(self) -> None:
        self.initialized_with_hooks()
        (self.root / ".local").mkdir()
        (self.root / ".local/first-commit").write_text("not a folder\n", "utf-8")
        with self.assertRaisesRegex(
            SetupError,
            r"^The \.local folder or \.local/first-commit is a link or not a folder"
            r"(?s:.*)\nfix: run `ls -ld \.local \.local/first-commit`",
        ):
            create_allowed_signers(self.root, b"person@example.net ssh-ed25519 Data\n")

    def test_trust_file_and_its_directories_are_owner_private(self) -> None:
        content = b"person@example.net ssh-ed25519 Data\n"

        path = create_allowed_signers(self.root, content)

        self.assertEqual(content, path.read_bytes())
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        for directory in (self.root / ".local", path.parent):
            self.assertEqual(0o700, directory.stat().st_mode & 0o777)
        with self.assertRaises(OSError):
            create_allowed_signers(self.root, content)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is unavailable")
    def test_signed_commit_verifies_and_doctor_reports_no_trust_warning(self) -> None:
        subprocess.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "comment@host",
                "-f",
                str(self.keys / "id_ed25519"),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
        person = self.person_with(str(self.keys / "id_ed25519.pub"))
        self.apply(person, trust_self=True)

        (self.root / "work.txt").write_text("content\n", encoding="utf-8")
        run_git(self.root, "add", "work.txt")
        run_git(self.root, "commit", "--no-verify", "-q", "-m", "feat(x): add work")

        verified = run_git(self.root, "verify-commit", "HEAD")
        shown = run_git(self.root, "log", "--show-signature", "-1")
        self.assertIn(b"Good", verified.stdout + verified.stderr)
        self.assertIn(b"Good", shown.stdout + shown.stderr)
        self.assertIn(person.email.encode("utf-8"), shown.stdout + shown.stderr)

        policy = parse_policy(b'{"schema_version": 1}', self.root, person)
        with (
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.validation.hook_findings", return_value=[]),
        ):
            result = doctor(self.root, policy)
        self.assertNotIn(
            "git.signature-verification-trust",
            [item.rule_id for item in result.findings],
        )


if __name__ == "__main__":
    unittest.main()
