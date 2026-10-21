import importlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import ModuleType

from first_commit.hooks import HTTPS_REPOSITORY

ROOT = Path(__file__).resolve().parents[1]
DRY_RUN = f"""\
Git repository: would initialize
Files: would create .repo-policy.json, README.md
Local contributor: would create
Private values: would create .local/first-commit/private-values.txt; add one private value per line
Git identity/signing: would configure
Commit template: would set commit.template
Local signature trust: would write .local/first-commit/allowed-signers; \
would set gpg.ssh.allowedSignersFile
Hook source: HTTPS ({HTTPS_REPOSITORY})
Hook cache: custom PRE_COMMIT_HOME
Signature verification: local trust would be configured; no existing signature was verified
Gitleaks: would download and install 8.30.0 from GitHub Releases
Hook scripts: would install
Hook environments: would install or verify; not checked (dry run)
Verification: Git-dependent checks will run after initialization; no changes made
Next action: review generated documents and remove @no-commit markers
"""
SCANNER = '#!/bin/sh\n[ "$1" = version ] && echo 8.30.0\n'
REVISION = "c" * 40


def harness(name: str) -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module(f"verify_lib.{name}")


core = harness("core")
effects = harness("effects")


class EffectsTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.project = self.work / "project"
        self.project.mkdir()
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        env.update(
            HOME=str(self.work),
            GIT_CONFIG_NOSYSTEM="1",
            PRE_COMMIT_HOME=str(self.work / "pre-commit"),
            VERIFY_KEY=str(self.work / "key"),
        )
        self.run_state = core.Run(
            work=self.work, python=sys.executable, environment=env, revision=REVISION
        )

    def git(self, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.project), *arguments],
            env=self.run_state.environment,
            check=True,
            capture_output=True,
        )

    def apply_everything(self) -> None:
        self.git("init", "-q")
        for name in (
            ".repo-policy.json",
            "README.md",
            ".gitmessage",
            ".local/first-commit/contributor.json",
            ".local/first-commit/private-values.txt",
            ".local/first-commit/allowed-signers",
        ):
            (self.project / name).parent.mkdir(parents=True, exist_ok=True)
            (self.project / name).write_text("x\n", "utf-8")
        scanner = self.project / ".local/bin/gitleaks"
        scanner.parent.mkdir(parents=True)
        scanner.write_text(SCANNER, "utf-8")
        scanner.chmod(0o755)
        for stage in ("pre-commit", "commit-msg", "pre-push"):
            hook = self.project / ".git/hooks" / stage
            hook.write_text("#!/bin/sh\n", "utf-8")
            hook.chmod(0o755)
        cache = self.work / "pre-commit"
        (cache / "repo1234").mkdir(parents=True)
        with closing(sqlite3.connect(cache / "db.db")) as database, database:
            database.execute("CREATE TABLE repos (repo TEXT, ref TEXT, path TEXT)")
            database.execute(
                "INSERT INTO repos VALUES (?, ?, ?)",
                (core.HTTPS, REVISION, str(cache / "repo1234")),
            )
        settings = {
            **effects.SIGNING_SETTINGS,
            "user.name": core.IDENTITY["FIRST_COMMIT_AUTHOR_NAME"],
            "user.email": core.IDENTITY["FIRST_COMMIT_AUTHOR_EMAIL"],
            "user.signingkey": str(self.work / "key.pub"),
            "commit.template": ".gitmessage",
            "gpg.ssh.allowedSignersFile": ".local/first-commit/allowed-signers",
        }
        for key, value in settings.items():
            self.git("config", "--local", key, value)

    def test_reads_only_the_lines_that_announce_an_action(self) -> None:
        labels = [label for label, _ in effects.announced_actions(DRY_RUN)]
        self.assertEqual(
            [
                "Git repository",
                "Files",
                "Local contributor",
                "Private values",
                "Git identity/signing",
                "Commit template",
                "Local signature trust",
                "Signature verification",
                "Gitleaks",
                "Hook scripts",
                "Hook environments",
            ],
            labels,
        )

    def test_every_announced_effect_is_found(self) -> None:
        self.apply_everything()
        proofs = effects.prove_effects(self.run_state, self.project, DRY_RUN)
        self.assertEqual(11, len(proofs))
        self.assertIn("Files: .repo-policy.json, README.md exist", proofs)
        self.assertIn("Gitleaks: .local/bin/gitleaks reports 8.30.0", proofs)

    def test_each_missing_effect_fails_with_its_label(self) -> None:
        removed = {
            "Git repository": ".git/HEAD",
            "Files": "README.md",
            "Local contributor": ".local/first-commit/contributor.json",
            "Private values": ".local/first-commit/private-values.txt",
            "Commit template": ".gitmessage",
            "Hook scripts": ".git/hooks/pre-push",
            "Hook environments": "../pre-commit/db.db",
        }
        changed = {
            "Git identity/signing": ("commit.gpgsign", "false"),
            "Local signature trust": ("--unset", "gpg.ssh.allowedSignersFile"),
        }
        for label in [*removed, *changed, "Gitleaks"]:
            with self.subTest(label=label):
                self.setUp()
                self.apply_everything()
                if label in removed:
                    (self.project / removed[label]).unlink()
                elif label in changed:
                    self.git("config", "--local", *changed[label])
                else:
                    scanner = self.project / ".local/bin/gitleaks"
                    scanner.write_text("#!/bin/sh\necho 8.29.0\n", "utf-8")
                with self.assertRaisesRegex(core.FeatureFailedError, label):
                    effects.prove_effects(self.run_state, self.project, DRY_RUN)

    def test_an_action_without_an_effect_check_fails(self) -> None:
        self.apply_everything()
        output = DRY_RUN + "Shell profile: would edit ~/.zshrc\n"
        with self.assertRaisesRegex(
            core.FeatureFailedError, "no effect check for 'Shell profile: would edit"
        ):
            effects.prove_effects(self.run_state, self.project, output)

    def test_a_dry_run_that_announces_nothing_fails(self) -> None:
        with self.assertRaisesRegex(core.FeatureFailedError, "announced no action"):
            effects.prove_effects(
                self.run_state, self.project, "Files: already present\n"
            )


if __name__ == "__main__":
    unittest.main()
