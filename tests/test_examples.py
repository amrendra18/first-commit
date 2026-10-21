import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from first_commit.policy import load_policy
from tests.support import initialize_repository


class ExamplesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.examples = self.root / "examples"

    def test_configuration_example_inventory_is_complete(self) -> None:
        paths = {
            path.relative_to(self.examples).as_posix()
            for path in self.examples.rglob("*")
            if path.is_file()
        }

        self.assertEqual(
            {"repo-policy.json"},
            paths,
        )

    def test_first_commit_example_keeps_universal_checks_fixed(self) -> None:
        policy = load_policy(self.examples / "repo-policy.json", self.root)
        self.assertFalse(hasattr(policy, "coverage_reports"))
        self.assertEqual(("maintainers@example.org",), policy.public_emails)
        self.assertNotIn(policy.public_emails[0], policy.contributor_emails)
        self.assertIsInstance(policy.commit_body_sections, bool)
        self.assertTrue(policy.commit_body_sections)
        self.assertEqual("privacy.private-key", policy.detector_exceptions[0].rule)
        self.assertEqual(
            [("prefix", "exports/"), ("suffix", ".kdbx")],
            [(item.match, item.value) for item in policy.forbidden_paths],
        )

    def test_repository_gitignore_includes_public_environment_templates(self) -> None:
        content = (self.root / ".gitignore").read_text("utf-8").splitlines()

        for rule in (
            ".env",
            ".env.*",
            "*.env",
            "*.env.*",
            "!.env.example",
            "!.env.schema",
            "!.env.template",
        ):
            self.assertIn(rule, content)

    def test_ignore_rules_protect_keys_without_hiding_public_sources(self) -> None:
        private_paths = (
            ".local/draft.md",
            "nested/.env",
            "nested/server.env",
            ".ssh/config",
            "id_ed25519",
            "github_example-user_example-host_auth_ed25519",
            "git_example-user_example-host_sign_ed25519.pub",
            "nested/private.pem",
        )
        public_paths = (
            "PRD.md",
            "docs/new.md",
            "src/module.py",
            ".env.example",
            "nested/.env.schema",
            "nested/.env.template",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            shutil.copyfile(self.root / ".gitignore", root / ".gitignore")
            for path in private_paths + public_paths:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(root),
                        "check-ignore",
                        "--quiet",
                        "--no-index",
                        "--",
                        path,
                    ],
                    check=False,
                    capture_output=True,
                )
                self.assertEqual(
                    0 if path in private_paths else 1, result.returncode, path
                )


if __name__ == "__main__":
    unittest.main()
