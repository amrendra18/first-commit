import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_verify_evidence import harness

core = harness("core")
clones = harness("clones")


class RunPrintedTest(unittest.TestCase):
    def run_printed(self, command: str) -> tuple[list[str], dict[str, str]]:
        run = core.Run(work=Path(), python=sys.executable, environment={})
        with patch.object(core.Run, "command", return_value=(0, "")) as called:
            clones.run_printed(run, command, Path())
        return called.call_args.args[0], called.call_args.kwargs["environment"]

    def test_only_leading_assignments_set_the_environment(self) -> None:
        self.assertEqual(
            (["git", "config", "user.name=Someone"], {"A": "1"}),
            self.run_printed("A=1 git config user.name=Someone"),
        )
        self.assertEqual(
            (["git", "log", "A"], {"A": "1"}), self.run_printed("A=1 git log A")
        )

    def test_pre_commit_runs_on_the_harness_python(self) -> None:
        arguments, environment = self.run_printed(
            "FIRST_COMMIT_TRUST_SELF=1 pre-commit run first-commit-setup"
        )
        self.assertEqual(
            [sys.executable, "-m", "pre_commit", "run", "first-commit-setup"], arguments
        )
        self.assertEqual({"FIRST_COMMIT_TRUST_SELF": "1"}, environment)


if __name__ == "__main__":
    unittest.main()
