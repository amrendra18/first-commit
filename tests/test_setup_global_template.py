import os
from pathlib import Path

from first_commit.models import SetupError
from first_commit.setup import SetupRequest, setup_repository
from tests.setup_support import REVISION, SetupFixture
from tests.support import run_git

TEMPLATE_PLAN_LINE = "set commit.template"
# Each dry-run wording and the wording apply prints for the same step, longest first.
APPLIED_WORDS = (
    (
        "would download and install 8.30.0 from GitHub Releases",
        "downloaded and installed 8.30.0",
    ),
    ("would install or verify; not checked (dry run)", "installed or verified"),
    ("would initialize", "initialized"),
    ("would configure", "configured"),
    ("would install", "installed"),
    ("would create", "created"),
    ("would set", "set"),
)


def applied_form(line: str) -> str:
    if line.startswith("Verification: "):
        return "Verification: passed"
    for planned, done in APPLIED_WORDS:
        line = line.replace(planned, done)
    return line


class GlobalTemplateSetupTest(SetupFixture):
    def setUp(self) -> None:
        super().setUp()
        # Product Git calls drop GIT_CONFIG_GLOBAL and read ~/.gitconfig.
        global_config = Path(os.environ["HOME"]) / ".gitconfig"
        global_config.write_text("[commit]\n\ttemplate = ~/.gitmessage\n", "utf-8")
        self.addCleanup(global_config.unlink)

    def assert_preview_matches_apply(self) -> None:
        preview = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )
        applied = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, confirmed=True),
            contributor=self.person,
        )
        self.assertIn("Commit template: would " + TEMPLATE_PLAN_LINE, preview)
        self.assertEqual([applied_form(line) for line in preview], list(applied))
        self.assertEqual("Verification: passed", applied[-2])
        self.assertEqual(
            b".gitmessage",
            run_git(self.root, "config", "--local", "commit.template").stdout.strip(),
        )

    def test_an_empty_folder_sets_a_local_template(self) -> None:
        self.local_hooks()
        self.assert_preview_matches_apply()

    def test_an_initialized_folder_sets_a_local_template(self) -> None:
        self.initialized_with_hooks()
        self.assert_preview_matches_apply()

    def test_an_unusable_local_template_names_the_fix(self) -> None:
        self.initialized_with_hooks()
        run_git(self.root, "config", "--local", "commit.template", "~/.gitmessage")
        with self.assertRaises(SetupError) as refused:
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        self.assertIn(
            "fix: run `git config --local --unset commit.template`",
            str(refused.exception),
        )
