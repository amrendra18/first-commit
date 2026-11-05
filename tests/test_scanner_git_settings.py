import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from first_commit.candidates import environment_files
from first_commit.checks.environment import DOTENV_PATHSPECS
from first_commit.gitleaks import RULE_ID, scan_history, scan_pushed, scan_staged
from first_commit.gitleaks_blobs import scan_hidden_staged
from first_commit.gitleaks_ignore_format import IGNORE_PATH
from first_commit.models import Finding
from first_commit.pushed import PushedScope
from tests.gitleaks_support import (
    SLACK_LINE,
    commit_fixture,
    history_cli,
    needs_real_scanner,
)
from tests.support import initialize_repository, run_git

LIMITS = (100, 1024 * 1024)
ATTRIBUTES = "{attributes}"
USER_SETTINGS = {
    "color.ui": "[color]\n\tui = always\n",
    "color.diff": "[color]\n\tdiff = always\n",
    "log.showRoot": "[log]\n\tshowRoot = false\n",
    "format.pretty": "[format]\n\tpretty = oneline\n",
    "log.date": "[log]\n\tdate = relative\n",
    "core.bigFileThreshold": "[core]\n\tbigFileThreshold = 1\n",
    "core.attributesFile": (
        f'[core]\n\tattributesFile = {ATTRIBUTES}\n[diff "hide"]\n\ttextconv = true\n'
    ),
    "diff.noprefix": "[diff]\n\tnoprefix = true\n",
    "diff.mnemonicPrefix": "[diff]\n\tmnemonicPrefix = true\n",
    "diff.srcPrefix": "[diff]\n\tsrcPrefix = x/\n\tdstPrefix = y/\n",
}
PATHSPEC_VARIABLES = (
    "GIT_GLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
    "GIT_LITERAL_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
)


def _locations(findings: tuple[Finding, ...]) -> set[tuple[str, int | None]]:
    return {(item.path, item.line) for item in findings if item.rule_id == RULE_ID}


class ScannerGitSettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.root = self.scratch / "repository"
        self.root.mkdir()
        initialize_repository(self.root)
        self.config = self.scratch / "xdg/git/config"
        self.config.parent.mkdir(parents=True)
        self.config.write_text("", encoding="utf-8")
        attributes = self.scratch / "attributes"
        attributes.write_text("* diff=hide\n", encoding="utf-8")
        self.attributes = str(attributes)
        environment = {
            "HOME": str(self.scratch),
            "XDG_CONFIG_HOME": str(self.scratch / "xdg"),
        }
        patcher = mock.patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, name: str, content: str) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def plant_keys(self) -> str:
        self.write("root.cfg", SLACK_LINE)
        commit_fixture(self.root, "root.cfg")
        self.write("later.txt", "later\n")
        commit_fixture(self.root, "later.txt")
        self.write("staged.cfg", SLACK_LINE)
        run_git(self.root, "add", "--", "staged.cfg")
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def use(self, setting: str) -> None:
        self.config.write_text(
            USER_SETTINGS[setting].replace(ATTRIBUTES, self.attributes), "utf-8"
        )

    def staged_locations(self) -> set[tuple[str, int | None]]:
        return _locations(scan_staged(self.root, max_findings=10)) | _locations(
            scan_hidden_staged(self.root, ("staged.cfg",), LIMITS, max_findings=10)
        )

    def assert_found_at_every_scope(self, head: str) -> None:
        self.assertIn(("staged.cfg", 1), self.staged_locations())
        self.assertIn(
            ("root.cfg", 1), _locations(scan_history(self.root, max_findings=10))
        )
        scope = PushedScope(head, None)
        self.assertIn(
            ("root.cfg", 1), _locations(scan_pushed(self.root, scope, max_findings=10))
        )

    @needs_real_scanner
    def test_user_git_settings_hide_no_key_at_any_scope(self) -> None:
        head = self.plant_keys()
        for setting in USER_SETTINGS:
            with self.subTest(setting=setting):
                self.use(setting)
                self.assert_found_at_every_scope(head)

    @needs_real_scanner
    def test_user_git_settings_leave_a_clean_history_scan_complete(self) -> None:
        self.write("root.txt", "root\n")
        commit_fixture(self.root, "root.txt")
        self.write("later.txt", "later\n")
        commit_fixture(self.root, "later.txt")
        head = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        for setting in USER_SETTINGS:
            with self.subTest(setting=setting):
                self.use(setting)
                self.assertEqual((), scan_history(self.root, max_findings=10))
                scope = PushedScope(head, None)
                self.assertEqual((), scan_pushed(self.root, scope, max_findings=10))

    @needs_real_scanner
    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is unavailable")
    def test_show_signature_leaves_a_signed_history_scan_complete(self) -> None:
        key = self.scratch / "id_ed25519"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        self.write(".repo-policy.json", '{"schema_version":1}\n')
        self.write("root.cfg", SLACK_LINE)
        commit_fixture(self.root, ".repo-policy.json", "root.cfg")
        signing = ("-c", "gpg.format=ssh", "-c", f"user.signingkey={key}")
        run_git(self.root, *signing, "commit", "-q", "-S", "--allow-empty", "-m", "x")
        head = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        self.config.write_text("[log]\n\tshowSignature = true\n", "utf-8")

        self.assertIn(
            ("root.cfg", 1), _locations(scan_history(self.root, max_findings=10))
        )
        scope = PushedScope(head, None)
        self.assertIn(
            ("root.cfg", 1), _locations(scan_pushed(self.root, scope, max_findings=10))
        )
        pushed = {"PRE_COMMIT_TO_REF": head}
        for arguments, environment in (
            (("check",), {}),
            (("hook", "pre-push"), pushed),
        ):
            with self.subTest(arguments=arguments):
                code, output = history_cli(self.root, arguments, environment)
                self.assertEqual(1, code)
                self.assertIn(f'{RULE_ID} "root.cfg":1', output)
                self.assertNotIn("incomplete", output)

    @needs_real_scanner
    def test_a_repository_textconv_driver_hides_no_key(self) -> None:
        self.write(".gitattributes", "*.cfg diff=hide\n")
        run_git(self.root, "add", "--", ".gitattributes")
        head = self.plant_keys()
        self.config.write_text('[diff "hide"]\n\ttextconv = true\n', "utf-8")

        self.assert_found_at_every_scope(head)

    @needs_real_scanner
    def test_a_user_attributes_file_that_marks_files_binary_hides_no_key(
        self,
    ) -> None:
        head = self.plant_keys()
        Path(self.attributes).write_text("* binary\n", encoding="utf-8")
        self.use("core.attributesFile")

        self.assert_found_at_every_scope(head)

    @needs_real_scanner
    def test_abbreviated_commit_ids_keep_a_reviewed_commit_exception(self) -> None:
        self.write("config.txt", SLACK_LINE)
        commit_fixture(self.root, "config.txt")
        reviewed = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        run_git(self.root, "rm", "-q", "--", "config.txt")
        digest = hashlib.sha256(SLACK_LINE.encode()).hexdigest()
        self.write(
            IGNORE_PATH,
            f"# reason: Synthetic fixture token.\n# file-sha256: {digest}\n"
            f"{reviewed}:config.txt:slack-bot-token:1\n",
        )
        commit_fixture(self.root, IGNORE_PATH)
        self.assertEqual((), scan_history(self.root, max_findings=10))

        self.config.write_text("[log]\n\tabbrevCommit = true\n", "utf-8")

        self.assertEqual((), scan_history(self.root, max_findings=10))

    def test_pathspec_variables_hide_no_nested_dotenv_file(self) -> None:
        self.write(".env", "A=1\n")
        self.write("nested/.env", "B=2\n")
        for variable in PATHSPEC_VARIABLES:
            with (
                self.subTest(variable=variable),
                mock.patch.dict(os.environ, {variable: "1"}),
            ):
                found = environment_files(self.root, DOTENV_PATHSPECS, 100)
                self.assertEqual({".env", "nested/.env"}, {item.path for item in found})


if __name__ == "__main__":
    unittest.main()
