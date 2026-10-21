import tomllib
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PYYAML_HOOKS = ("first-commit-doctor", "first-commit-check")


def _hooks() -> dict[str, dict[str, object]]:
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text("utf-8"))
    return {hook["id"]: hook for hook in hooks}


class HookDependenciesTest(unittest.TestCase):
    def test_clone_setup_hook_installs_the_whole_pinned_setup_extra(self) -> None:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
        setup = pyproject["project"]["optional-dependencies"]["setup"]

        self.assertEqual(
            setup, _hooks()["first-commit-setup"]["additional_dependencies"]
        )

    def test_doctor_and_check_hooks_can_read_the_hook_file(self) -> None:
        hooks = _hooks()
        for hook_id in PYYAML_HOOKS:
            with self.subTest(hook=hook_id):
                self.assertEqual(
                    ["PyYAML==6.0.3"], hooks[hook_id].get("additional_dependencies")
                )


if __name__ == "__main__":
    unittest.main()
