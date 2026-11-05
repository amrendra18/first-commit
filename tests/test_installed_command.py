import os
from pathlib import Path
from unittest.mock import patch

from first_commit.hooks import HTTPS_REPOSITORY
from first_commit.models import SetupError, SetupFailedError
from first_commit.setup import SetupRequest, setup_repository
from first_commit.setup_command import HOOK_CONFIG
from first_commit.setup_hooks import hook_bytes, local_hook_bytes
from first_commit.setup_installed_command import verify_installed_command
from tests.gitleaks_support import needs_real_scanner
from tests.setup_support import REVISION
from tests.support import run_git
from tests.test_setup_hooks_installed import InstalledFixture

KEPT = (
    "Hook source: existing project-owned configuration retained; --hooks installed "
    "shapes only a new hook file"
)
INSTALLED_COMMAND_FIX = (
    "Put first-commit on PATH in a folder outside this repository, as Install in "
    "the first-commit README shows, or declare the pinned first-commit hooks."
)


class InstalledCommandTest(InstalledFixture):
    def installed_command_findings(self) -> list[dict[str, str]]:
        _, findings = self.doctor()
        return [
            item for item in findings if item["rule_id"] == "hooks.installed-command"
        ]

    def first_commit_in(self, folder: Path, script: str) -> None:
        folder.mkdir(exist_ok=True)
        program = folder / "first-commit"
        program.write_text(script, "utf-8")
        program.chmod(0o755)

    @needs_real_scanner
    def test_a_clone_without_first_commit_on_path_stops_setup_and_doctor(
        self,
    ) -> None:
        self.installed_setup()
        self.clone()
        with self.only_git_on_path():
            preview, _, preview_error = self.run_cli("setup", "--dry-run")
            code, _, error = self.run_cli("setup", "--yes")
            (finding,) = self.installed_command_findings()
        self.assertEqual((1, 1), (preview, code))
        self.assertIn("PATH has no first-commit", preview_error)
        self.assertIn("PATH has no first-commit", error)
        self.assertNotIn("--hooks pinned", error)
        self.assertFalse((self.project / ".local").exists())
        self.assertEqual("error", finding["severity"])
        self.assertIn("PATH has no first-commit", finding["summary"])
        self.assertEqual(INSTALLED_COMMAND_FIX, finding["fix"])
        code, _, error = self.run_cli("setup", "--yes")
        self.assertEqual(0, code, error)
        self.assertEqual([], self.installed_command_findings())

    def test_a_proposal_needs_first_commit_on_path(self) -> None:
        run_git(self.project, "init", "-q")
        (self.project / HOOK_CONFIG).write_text("repos: []\n", "utf-8")
        with self.only_git_on_path():
            code, _, error = self.run_cli("setup", "--hooks", "installed", "--yes")
        self.assertEqual(1, code)
        self.assertIn("PATH has no first-commit", error)
        self.assertIn("--hooks pinned", error)
        self.assertEqual(
            {".git", HOOK_CONFIG}, {path.name for path in self.project.iterdir()}
        )

    @needs_real_scanner
    def test_a_first_commit_inside_the_repository_is_refused(self) -> None:
        self.installed_setup()
        inside = self.project / "tools"
        self.first_commit_in(inside, '#!/bin/sh\necho "0.5.0"\n')
        path = f"{inside}{os.pathsep}{os.environ['PATH']}"
        with patch.dict(os.environ, {"PATH": path}):
            code, _, error = self.run_cli("setup", "--dry-run")
            (finding,) = self.installed_command_findings()
        self.assertEqual(1, code)
        self.assertIn(
            "first-commit on PATH is tools/first-commit inside this repository", error
        )
        self.assertNotIn(str(self.project), error)
        self.assertIn("tools/first-commit inside this repository", finding["summary"])

    def test_a_program_that_prints_no_version_fails_verification(self) -> None:
        self.first_commit_in(self.tools / "quiet", "#!/bin/sh\nexit 0\n")
        path = f"{self.tools / 'quiet'}{os.pathsep}{os.environ['PATH']}"
        with patch.dict(os.environ, {"PATH": path}):
            code, _, error = self.run_cli("setup", "--hooks", "installed", "--yes")
        self.assertEqual(1, code)
        self.assertIn("The first-commit on PATH did not print its version", error)
        self.assertEqual([], list(self.project.iterdir()))

    @needs_real_scanner
    def test_doctor_names_the_local_shape_for_a_changed_local_hook(self) -> None:
        self.installed_setup()
        hook_file = self.project / HOOK_CONFIG
        changed = hook_file.read_text("utf-8").replace(
            "always_run: true", "always_run: false", 1
        )
        hook_file.write_text(changed, "utf-8")
        _, findings = self.doctor()
        (staged,) = [
            item for item in findings if item["rule_id"] == "hooks.staged-check"
        ]
        self.assertEqual(
            "Declare first-commit-staged once as a repo: local hook with entry "
            "first-commit hook pre-commit, language system, always_run true, "
            "pass_filenames false, and stages [pre-commit].",
            staged["fix"],
        )
        hook_file.write_bytes(
            hook_bytes(REVISION).replace(
                b"      - id: first-commit-staged\n",
                b"      - id: first-commit-staged\n        args: [x]\n",
            )
        )
        _, findings = self.doctor()
        (staged,) = [
            item for item in findings if item["rule_id"] == "hooks.staged-check"
        ]
        self.assertIn("with no keys but id and stages", staged["fix"])

    def test_an_installed_request_says_a_kept_pinned_file_stays_pinned(self) -> None:
        run_git(self.project, "init", "-q")
        (self.project / HOOK_CONFIG).write_bytes(hook_bytes(REVISION))
        code, output, error = self.run_cli("setup", "--hooks", "installed", "--dry-run")
        self.assertEqual(0, code, error)
        self.assertIn(KEPT, output.splitlines())
        files = next(line for line in output.splitlines() if line.startswith("Files:"))
        self.assertIn("README.md", files)
        code, output, _ = self.run_cli("setup", "--dry-run")
        self.assertIn(
            "Hook source: existing project-owned configuration retained",
            output.splitlines(),
        )

    def test_a_kept_pinned_file_keeps_the_pinned_onboarding(self) -> None:
        run_git(self.project, "init", "-q")
        (self.project / HOOK_CONFIG).write_bytes(hook_bytes(REVISION))
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            code, _, error = self.run_cli("setup", "--hooks", "installed", "--yes")
        self.assertEqual(0, code, error)
        readme = (self.project / "README.md").read_text("utf-8")
        self.assertIn(f"`{HTTPS_REPOSITORY}` at the commit", readme)
        self.assertEqual(
            hook_bytes(REVISION), (self.project / HOOK_CONFIG).read_bytes()
        )

    def test_an_unknown_hook_form_is_refused(self) -> None:
        with self.assertRaisesRegex(
            SetupError, "Hook form must be pinned or installed"
        ):
            setup_repository(self.project, SetupRequest(hooks="floating", dry_run=True))
        self.assertEqual([], list(self.project.iterdir()))

    def test_verification_checks_the_program_again_and_bounds_its_run(self) -> None:
        verify_installed_command(self.project)
        (self.project / HOOK_CONFIG).write_bytes(local_hook_bytes())
        with (
            self.only_git_on_path(),
            self.assertRaisesRegex(
                SetupFailedError, "^Setup verification failed: PATH has no first-commit"
            ),
        ):
            verify_installed_command(self.project)
        self.first_commit_in(self.tools / "slow", "#!/bin/sh\nexec sleep 5\n")
        path = f"{self.tools / 'slow'}{os.pathsep}{os.environ['PATH']}"
        with (
            patch.dict(os.environ, {"PATH": path}),
            patch("first_commit.setup_installed_command.VERSION_TIMEOUT_SECONDS", 0.2),
            self.assertRaisesRegex(SetupFailedError, "did not print its version"),
        ):
            verify_installed_command(self.project)
