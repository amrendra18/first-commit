import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import cli
from first_commit.generated_files import HOOK_PROPOSAL
from first_commit.hooks import (
    HOOK_IDS,
    HOOK_TYPES,
    HTTPS_REPOSITORY,
    declaration_conflicts,
    hook_entries,
    load_hook_config,
)
from first_commit.setup_command import (
    CHECK_HOOK_COMMAND,
    HOOK_CONFIG,
    SETUP_HOOK_COMMAND,
)
from first_commit.setup_hooks import PROPOSAL_HEADER
from first_commit.setup_preview import plan_lines
from tests.gitleaks_support import needs_real_scanner
from tests.setup_support import REVISION, SetupFixture
from tests.support import run_git

LAUNCHER = Path(__file__).resolve().parents[1] / "bin/first-commit"
ENTRIES = {
    "first-commit-staged": "first-commit hook pre-commit",
    "first-commit-message": "first-commit hook commit-msg",
    "first-commit-push": "first-commit hook pre-push",
    "first-commit-doctor": "first-commit doctor",
    "first-commit-check": "first-commit check",
}
PINNED_TODAY = (
    'minimum_pre_commit_version: "3.2.0"\n'
    "default_install_hook_types:\n"
    "  - pre-commit\n"
    "  - commit-msg\n"
    "  - pre-push\n"
    "repos:\n"
    f'  - repo: "{HTTPS_REPOSITORY}"\n'
    f'    rev: "{REVISION}"\n'
    "    hooks:\n"
    "      - id: first-commit-staged\n"
    "      - id: first-commit-message\n"
    "      - id: first-commit-push\n"
    "      - id: first-commit-setup\n"
    "      - id: first-commit-doctor\n"
    "      - id: first-commit-check\n"
).encode()
# Files a clone of a project has once the first commit is pushed.
TRACKED = (HOOK_CONFIG, ".repo-policy.json", ".gitignore", ".gitmessage")


# Setup looks up Git only to run the hook source preflight, `git ls-remote`.
@contextmanager
def no_network(form: str) -> Iterator[None]:
    with patch(
        "first_commit.setup.git_executable",
        side_effect=AssertionError(f"the {form} form reached the network"),
    ):
        yield


class InstalledFixture(SetupFixture):
    def setUp(self) -> None:
        super().setUp()
        tools = tempfile.TemporaryDirectory(prefix="first-commit tools ")
        self.addCleanup(tools.cleanup)
        self.tools = Path(tools.name)
        (self.tools / "first-commit").symlink_to(LAUNCHER)
        (self.root / "project").mkdir()
        self.project = (self.root / "project").resolve()
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "PATH": f"{self.tools}{os.pathsep}{os.environ['PATH']}",
                    "FIRST_COMMIT_IDENTITY_FILE": str(self.tools / "identity.json"),
                    "FIRST_COMMIT_AUTHOR_NAME": self.person.name,
                    "FIRST_COMMIT_AUTHOR_EMAIL": self.person.email,
                    "FIRST_COMMIT_SIGNING_KEY": self.person.signing_key,
                },
            )
        )

    # No scanner in the project, so doctor and check use the pinned one on PATH.
    def install_scanner(self, _root: Path) -> bool:
        return False

    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        output = io.StringIO()
        error = io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main((*arguments, "--root", str(self.project)))
        return code, output.getvalue(), error.getvalue()

    def installed_setup(self) -> str:
        code, output, error = self.run_cli("setup", "--hooks", "installed", "--yes")
        self.assertEqual(0, code, error)
        self.assertIn("Verification: passed", output)
        return output

    def doctor(self) -> tuple[int, list[dict[str, str]]]:
        code, output, _ = self.run_cli("doctor", "--format", "json")
        findings = [
            finding
            for result in json.loads(output)["checks"]
            for finding in result["findings"]
        ]
        return code, findings

    @contextmanager
    def only_git_on_path(self) -> Iterator[None]:
        git = shutil.which("git") or self.fail("git is not on PATH")
        only_git = self.tools / "only-git"
        only_git.mkdir(exist_ok=True)
        if not (only_git / "git").exists():
            (only_git / "git").symlink_to(git)
        with patch.dict(os.environ, {"PATH": str(only_git)}):
            yield

    def clone(self) -> None:
        clone = self.project.with_name("clone")
        clone.mkdir()
        run_git(clone, "init", "-q")
        for name in TRACKED:
            shutil.copyfile(self.project / name, clone / name)
        self.project = clone

    def assert_installed_form(self, raw: bytes) -> None:
        data = load_hook_config(raw)
        entries = hook_entries(data)
        self.assertEqual(ENTRIES, {hook["id"]: hook["entry"] for _, hook in entries})
        self.assertEqual(list(HOOK_TYPES), data["default_install_hook_types"])
        for repository, hook in entries:
            self.assertEqual("local", repository["repo"])
            self.assertNotIn("rev", repository)
            self.assertEqual("system", hook["language"])
            if hook["id"] in HOOK_IDS.values():
                self.assertFalse(declaration_conflicts(repository, hook), hook["id"])
            else:
                self.assertEqual(["manual"], hook["stages"])


class InstalledHooksTest(InstalledFixture):
    def test_installed_form_writes_local_hooks(self) -> None:
        with no_network("installed"):
            self.installed_setup()
        self.assert_installed_form((self.project / HOOK_CONFIG).read_bytes())
        for stage in HOOK_TYPES:
            self.assertTrue((self.project / ".git/hooks" / stage).is_file(), stage)

    def test_the_network_sentinel_fires_for_the_pinned_form(self) -> None:
        with (
            no_network("pinned"),
            self.assertRaisesRegex(AssertionError, "the pinned form reached"),
        ):
            self.run_cli("setup", "--revision", REVISION, "--yes")

    def test_pinned_default_writes_todays_hook_file(self) -> None:
        with (
            patch("first_commit.setup._preflight_source"),
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            code, _, error = self.run_cli("setup", "--revision", REVISION, "--yes")
        self.assertEqual(0, code, error)
        self.assertEqual(PINNED_TODAY, (self.project / HOOK_CONFIG).read_bytes())

    def test_installed_preview_equals_apply(self) -> None:
        with patch("first_commit.setup.plan_lines", wraps=plan_lines) as shown:
            code, preview, error = self.run_cli(
                "setup", "--hooks", "installed", "--dry-run"
            )
        self.assertEqual(0, code, error)
        self.assertEqual([], list(self.project.iterdir()))
        applied = self.installed_setup()
        pending = shown.call_args.args[0].pending
        self.assertIn(self.project / HOOK_CONFIG, pending)
        for path, content in pending.items():
            self.assertEqual(content, path.read_bytes(), path.name)
        files = [line for line in preview.splitlines() if line.startswith("Files:")]
        self.assertEqual(
            [line.replace("would create", "created") for line in files],
            [line for line in applied.splitlines() if line.startswith("Files:")],
        )
        source = "Hook source: the first-commit command on PATH (repo: local)"
        self.assertIn(source, preview.splitlines())
        self.assertIn(source, applied.splitlines())

    @needs_real_scanner
    def test_doctor_accepts_installed_form(self) -> None:
        self.installed_setup()
        code, findings = self.doctor()
        self.assertEqual(0, code, findings)
        self.assertEqual(
            [],
            [
                item["rule_id"]
                for item in findings
                if item["rule_id"].startswith("hooks.")
            ],
        )

    @needs_real_scanner
    def test_check_hook_command_runs_in_an_installed_form_project(self) -> None:
        self.installed_setup()
        result = subprocess.run(
            [sys.executable, "-m", "pre_commit", *CHECK_HOOK_COMMAND.split()[1:]],
            cwd=self.project,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotIn("No hook with id", result.stdout + result.stderr)
        self.assertIn("first-commit check", result.stdout)
        self.assertIn("ok - doctor policy passed", result.stdout)
        self.assertIn('scaffold.no-commit "README.md"', result.stdout)

    @needs_real_scanner
    def test_fix_lines_and_starter_name_commands_that_work_here(self) -> None:
        self.installed_setup()
        readme = (self.project / "README.md").read_text("utf-8")
        self.assertIn("first-commit setup\n", readme)
        self.assertIn(CHECK_HOOK_COMMAND, readme)
        self.assertNotIn(SETUP_HOOK_COMMAND, readme)
        self.assertNotIn("pins", readme)
        self.assertIn(f"Install first-commit from `{HTTPS_REPOSITORY}`", readme)
        run_git(self.project, "config", "--local", "--unset", "commit.gpgsign")
        _, findings = self.doctor()
        fixes = [item["fix"] for item in findings if "fix" in item]
        (signed,) = [
            item for item in findings if item["rule_id"] == "git.signed-commits"
        ]
        self.assertTrue(
            signed["fix"].startswith("Run first-commit setup in this checkout")
        )
        self.assertFalse([fix for fix in fixes if "first-commit-setup" in fix])
        _, output, _ = self.run_cli("doctor")
        self.assertIn("Next action: run first-commit setup", output)

    @needs_real_scanner
    def test_a_clone_of_an_installed_form_project_runs_first_commit_setup(
        self,
    ) -> None:
        self.installed_setup()
        self.clone()
        code, output, error = self.run_cli("setup", "--yes")
        self.assertEqual(0, code, error)
        self.assertIn("Verification: passed", output)
        self.assertIn("Files: already present", output)
        code, findings = self.doctor()
        self.assertEqual(0, code, findings)
        self.assertFalse(
            [item for item in findings if item["rule_id"].startswith("hooks.")]
        )

    def test_a_project_hook_file_gets_an_installed_form_proposal(self) -> None:
        run_git(self.project, "init", "-q")
        (self.project / ".repo-policy.json").write_text('{"schema_version":1}\n')
        (self.project / HOOK_CONFIG).write_text(
            "repos:\n  - repo: local\n    hooks:\n      - id: project-lint\n"
            "        name: lint\n        entry: true\n        language: system\n",
            "utf-8",
        )
        code, _, error = self.run_cli("setup", "--hooks", "installed", "--yes")
        self.assertEqual(2, code)
        self.assertIn(f"fix: merge {HOOK_PROPOSAL} into {HOOK_CONFIG}", error)
        self.assertNotIn("--revision", error)
        header = PROPOSAL_HEADER.encode("utf-8")
        proposal = (self.project / HOOK_PROPOSAL).read_bytes()
        self.assertTrue(proposal.startswith(header))
        self.assert_installed_form(proposal.removeprefix(header))

    def test_pinning_options_with_the_installed_form_are_a_bad_call(self) -> None:
        for extra, named in (
            (("--revision", REVISION), ("--revision",)),
            (("--transport", "ssh"), ("--transport",)),
            (
                ("--revision", REVISION, "--transport", "https"),
                ("--revision", "--transport"),
            ),
        ):
            with self.subTest(extra=extra):
                code, _, error = self.run_cli(
                    "setup", "--hooks", "installed", "--dry-run", *extra
                )
                self.assertEqual(2, code)
                for flag in named:
                    self.assertIn(f"`{flag}`", error)
                self.assertIn("pins no commit and no address", error)
        code, output, _ = self.run_cli(
            "setup", "--hooks", "installed", "--transport", "ssh", "--format", "json"
        )
        self.assertEqual(2, code)
        self.assertEqual("invalid-arguments", json.loads(output)["error"]["code"])
        self.assertEqual([], list(self.project.iterdir()))

    def test_the_installed_form_needs_first_commit_on_path(self) -> None:
        with self.only_git_on_path():
            code, _, error = self.run_cli("setup", "--hooks", "installed", "--dry-run")
        self.assertEqual(1, code)
        self.assertIn("PATH has no first-commit", error)
        self.assertIn("--hooks pinned", error)
        self.assertEqual([], list(self.project.iterdir()))
