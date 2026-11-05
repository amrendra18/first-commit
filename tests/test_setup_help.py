import unittest
from typing import Any, cast

from first_commit.arguments import build_parser
from first_commit.help_text import AGENT_RULES, help_object

REDIRECT_HOSTS = (
    "a githubusercontent.com host for the Gitleaks release",
    "files.pythonhosted.org for Python packages",
)


def _command(path: str) -> dict[str, Any]:
    commands = cast(dict[str, dict[str, Any]], help_object(build_parser())["commands"])
    return commands[path]


class SetupHelpTest(unittest.TestCase):
    def test_setup_help_names_the_gitleaks_and_pre_commit_setup_uses(self) -> None:
        for path in ("setup", "hook setup"):
            with self.subTest(path=path):
                writes = str(_command(path)["writes"])
                self.assertIn(
                    "`<repository>/.local/bin/gitleaks` when that file is missing, "
                    "even when Gitleaks is on PATH;",
                    writes,
                )
                self.assertNotIn("when no Gitleaks is found", writes)
        before = str(_command("setup")["before"])
        self.assertIn(
            "Git on PATH, and pre-commit 3.2.0 or newer in the Python environment "
            "that runs first-commit",
            before,
        )
        self.assertNotIn("pre-commit 3.2.0 or newer on PATH", before)

    def test_setup_help_names_the_hosts_downloads_redirect_to(self) -> None:
        for path in ("setup", "hook setup"):
            with self.subTest(path=path):
                found = _command(path)
                for host in REDIRECT_HOSTS:
                    self.assertIn(host, str(found["before"]))
                self.assertEqual(
                    [
                        "writes repository",
                        "writes own state",
                        "network github.com",
                        "network pypi.org",
                    ],
                    found["effects"],
                )

    def test_the_agent_rule_runs_check_only_after_review_and_staging(self) -> None:
        self.assertIn(
            "After setup, run `first-commit doctor`. Run `first-commit check` once "
            "the `@no-commit` markers are reviewed and the files are staged.",
            AGENT_RULES,
        )


if __name__ == "__main__":
    unittest.main()
