import tempfile
import unittest
from pathlib import Path

from first_commit.hooks import HOOK_TYPES, hook_findings
from tests.support import initialize_repository
from tests.test_hooks import generated_hook


class HookReadinessTest(unittest.TestCase):
    def test_a_generated_hook_without_the_execute_bit_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            for hook_type in HOOK_TYPES:
                path = root / ".git/hooks" / hook_type
                path.write_text(generated_hook(hook_type), encoding="utf-8")
                path.chmod(0o644)

            findings = hook_findings(root)

        self.assertEqual(
            ["hooks.invalid"] * len(HOOK_TYPES),
            [finding.rule_id for finding in findings],
        )


if __name__ == "__main__":
    unittest.main()
