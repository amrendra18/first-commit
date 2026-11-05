import subprocess
import unittest

from tests.support import TemporaryRootTest, run_git


class RunGitErrorTest(TemporaryRootTest):
    def test_a_failed_fixture_command_shows_what_git_said(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            run_git(self.root, "rev-parse", "--verify", "no-such-commit")
        self.assertIn("fatal", str(caught.exception))
        self.assertEqual(128, caught.exception.returncode)


if __name__ == "__main__":
    unittest.main()
