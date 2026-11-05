import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.checks.identity import ALLOWED_SIGNERS_PATH, TRUST_SETTING
from first_commit.contributor import Contributor
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_trust import allowed_signers_line
from tests.setup_support import REVISION, SetupFixture, synthetic_key
from tests.support import run_git

README = (Path(__file__).resolve().parents[1] / "README.md").read_text("utf-8")
RECOVERY = (
    README.split("**Wrong identity or key.**", 1)[1]
    .split("```sh\n", 1)[1]
    .split("```", 1)[0]
)


class TrustRecoveryTest(SetupFixture):
    def setUp(self) -> None:
        super().setUp()
        keys = tempfile.TemporaryDirectory(prefix="first-commit keys ")
        self.addCleanup(keys.cleanup)
        self.keys = Path(keys.name)
        self.initialized_with_hooks()

    def contributor(self, email: str, key: Path) -> Contributor:
        return Contributor(self.person.name, email, str(key))

    def synthetic(self, name: str, data: bytes) -> Path:
        path = self.keys / f"{name}.pub"
        path.write_text(synthetic_key(data=data) + "\n", "utf-8")
        return path

    def generated(self, name: str) -> Path:
        path = self.keys / name
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        return path.with_name(name + ".pub")

    def trust(self, person: Contributor) -> tuple[str, ...]:
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            return setup_repository(
                self.root,
                SetupRequest(revision=REVISION, trust_self=True),
                contributor=person,
            )

    def settings(self) -> list[str]:
        listed = subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "--local",
                "--get-all",
                TRUST_SETTING,
            ],
            check=False,
            capture_output=True,
        )
        return listed.stdout.decode("utf-8").splitlines()

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is unavailable")
    def test_the_readme_recovery_trusts_only_the_new_key(self) -> None:
        self.trust(self.contributor("old@example.net", self.generated("old")))
        self.recover()
        new = self.contributor("new@example.net", self.generated("new"))

        self.trust(new)
        (self.root / "work.txt").write_text("content\n", encoding="utf-8")
        run_git(self.root, "add", "work.txt")
        run_git(self.root, "commit", "--no-verify", "-q", "-m", "feat(x): add work")

        verified = subprocess.run(
            ["git", "-C", str(self.root), "verify-commit", "HEAD"],
            check=False,
            capture_output=True,
        )
        self.assertEqual(0, verified.returncode, verified.stderr)
        self.assertEqual(
            allowed_signers_line(self.root, new),
            (self.root / ALLOWED_SIGNERS_PATH).read_bytes(),
        )
        self.assertEqual([ALLOWED_SIGNERS_PATH], self.settings())

    def recover(self) -> None:
        subprocess.run(
            ["sh", "-e", "-c", RECOVERY], cwd=self.root, check=True, capture_output=True
        )

    def test_a_kept_setting_does_not_keep_a_file_without_your_key(self) -> None:
        old = self.contributor(self.person.email, self.synthetic("old", b"\x01" * 32))
        self.trust(old)
        line = (self.root / ALLOWED_SIGNERS_PATH).read_bytes()
        self.recover()
        (self.root / ALLOWED_SIGNERS_PATH).write_bytes(line)

        with self.assertRaisesRegex(SetupError, "delete the file and run setup again"):
            self.trust(
                self.contributor(self.person.email, self.synthetic("new", b"\x02" * 32))
            )

        self.assertEqual(line, (self.root / ALLOWED_SIGNERS_PATH).read_bytes())
        self.assertEqual([ALLOWED_SIGNERS_PATH], self.settings())

    def test_setup_without_trust_names_the_missing_file_and_the_command(self) -> None:
        old = self.contributor(self.person.email, self.synthetic("old", b"\x04" * 32))
        self.trust(old)
        self.recover()
        new = self.contributor(self.person.email, self.synthetic("new", b"\x05" * 32))

        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            actions = setup_repository(
                self.root, SetupRequest(revision=REVISION), contributor=new
            )

        self.assertIn(
            f"Signature verification: not performed; {ALLOWED_SIGNERS_PATH} is "
            "missing; run first-commit setup --trust-self to write it",
            actions,
        )
        self.assertFalse((self.root / ALLOWED_SIGNERS_PATH).exists())

    def setup_without_trust(self, *, setup_hook: bool = False) -> tuple[str, ...]:
        person = self.contributor(self.person.email, self.synthetic("k", b"\x06" * 32))
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
            patch(
                "first_commit.setup_preview.declares_setup_hook",
                return_value=setup_hook,
            ),
        ):
            return setup_repository(
                self.root, SetupRequest(revision=REVISION), contributor=person
            )

    def test_the_missing_file_line_names_the_hook_form_or_another_file(self) -> None:
        run_git(self.root, "config", "--local", TRUST_SETTING, ALLOWED_SIGNERS_PATH)
        self.assertIn(
            f"Signature verification: not performed; {ALLOWED_SIGNERS_PATH} is "
            "missing; run FIRST_COMMIT_TRUST_SELF=1 pre-commit run "
            "first-commit-setup --hook-stage manual to write it",
            self.setup_without_trust(setup_hook=True),
        )
        run_git(self.root, "config", "--local", TRUST_SETTING, "project/signers")
        self.assertIn(
            f"Signature verification: not performed; the file that {TRUST_SETTING} "
            "names is missing; restore it",
            self.setup_without_trust(),
        )

    def test_a_missing_file_that_the_kept_setting_names_is_written_again(self) -> None:
        person = self.contributor(
            self.person.email, self.synthetic("key", b"\x03" * 32)
        )
        run_git(self.root, "config", "--local", TRUST_SETTING, ALLOWED_SIGNERS_PATH)

        actions = self.trust(person)

        self.assertEqual(
            allowed_signers_line(self.root, person),
            (self.root / ALLOWED_SIGNERS_PATH).read_bytes(),
        )
        self.assertEqual([ALLOWED_SIGNERS_PATH], self.settings())
        self.assertIn(
            f"Local signature trust: wrote {ALLOWED_SIGNERS_PATH}; "
            f"retained existing {TRUST_SETTING}",
            actions,
        )


if __name__ == "__main__":
    unittest.main()
