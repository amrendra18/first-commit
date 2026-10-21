import os
import subprocess
import unittest
from pathlib import Path

from first_commit.git import sanitized_git_environment


def global_settings(environment: dict[str, str]) -> str:
    result = subprocess.run(
        ["git", "config", "--global", "--list"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result.stdout


class IsolationTest(unittest.TestCase):
    def test_fixture_and_product_git_read_no_global_or_system_settings(self) -> None:
        self.assertEqual("1", os.environ["GIT_CONFIG_NOSYSTEM"])
        self.assertEqual(b"", Path(os.environ["GIT_CONFIG_GLOBAL"]).read_bytes())
        self.assertEqual("", global_settings(dict(os.environ)))
        product = sanitized_git_environment()
        self.assertNotIn("GIT_CONFIG_GLOBAL", product)
        self.assertEqual("", global_settings(product))
        self.assertFalse((Path(os.environ["HOME"]) / ".gitconfig").exists())


if __name__ == "__main__":
    unittest.main()
