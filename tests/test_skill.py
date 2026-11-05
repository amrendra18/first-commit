import io
import os
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from first_commit import cli
from tests.cli_support import PROJECT
from tests.test_contract import SKILL, TOP_VERBS

GENERATE = "first-commit help --format markdown"
HOSTS = ("~/.claude", "~/.codex")
SKILL_FOLDER = "skills/first-commit"
RULES = (
    "Preview first with `first-commit setup --dry-run`.",
    "Review each conflict and each `@no-commit` proposal by hand; never overwrite",
    "Git initialization, local Git settings, dependency installation, and hooks",
    "Never stage, commit, change remotes, or publish without the user's permission.",
    "`first-commit doctor` and `first-commit check` are read-only, except that",
    "remove group and other access from the user's private-values list",
    "Never read private-key contents or print matched private content.",
    "Put the project's own tests and builds in the project's own hooks.",
    "Never add a switch or setting that turns a check off.",
    "After setup, run `first-commit doctor`. Run `first-commit check` once the",
    "Setup writes each starter file once; the project owns it from then on.",
)


def _generated() -> str:
    output = io.StringIO()
    with redirect_stdout(output):
        code = cli.main(tuple(GENERATE.split()[1:]))
    if code != 0:
        raise AssertionError(f"{GENERATE} exited {code}")
    return output.getvalue()


def _readme_section(heading: str) -> str:
    readme = (PROJECT / "README.md").read_text("utf-8")
    return readme.split(f"\n## {heading}\n", 1)[1].split("\n## ", 1)[0]


class SkillTest(unittest.TestCase):
    def test_skill_states_the_adoption_rules(self) -> None:
        rules = _generated().split("\n## Rules for agents\n", 1)[1].split("\n## ")[0]
        flat = " ".join(rules.split())
        for rule in RULES:
            with self.subTest(rule=rule):
                self.assertIn(rule, flat)

    def test_skill_description_says_when_to_use_the_tool(self) -> None:
        front = _generated().split("---\n", 2)[1]
        description = front.split("description: ", 1)[1].strip()
        self.assertTrue(description.startswith("Use first-commit when "), description)
        self.assertIn("new or existing", description)
        self.assertTrue(description.endswith("."), description)
        self.assertNotIn(". ", description)

    def test_skill_names_only_its_own_verbs_and_works_outside_the_checkout(
        self,
    ) -> None:
        text = _generated()
        named = set(re.findall(r"`first-commit ([a-z-]+)", text))
        self.assertTrue(named)
        self.assertLessEqual(named, set(TOP_VERBS))
        for private in (str(Path.home()), "/Users/", "/home/"):
            self.assertNotIn(private, text)
        self.assertEqual([], re.findall(r"\]\(([^)]+)\)", text))

    def test_readme_skill_lines_write_the_generated_skill(self) -> None:
        blocks = re.findall(r"```sh\n(.*?)```", _readme_section("Install"), re.DOTALL)
        found = [block for block in blocks if "SKILL.md" in block]
        self.assertEqual(1, len(found), "one skill block in Install")
        folders = [f"{host}/{SKILL_FOLDER}" for host in HOSTS]
        self.assertEqual(
            [
                f"mkdir -p {' '.join(folders)}",
                *(f"{GENERATE} > {folder}/SKILL.md" for folder in folders),
            ],
            found[0].splitlines(),
        )
        self.assertIn("skill lines", " ".join(_readme_section("Upgrade").split()))
        with tempfile.TemporaryDirectory() as scratch:
            home, tools = Path(scratch, "home"), Path(scratch, "bin")
            home.mkdir()
            tools.mkdir()
            launcher = tools / "first-commit"
            launcher.write_text(
                f'#!/bin/sh\nexec "{PROJECT}/bin/first-commit" "$@"\n', "utf-8"
            )
            launcher.chmod(0o755)
            environment = os.environ | {
                "HOME": str(home),
                "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}",
                "XDG_CONFIG_HOME": str(home / ".config"),
            }
            subprocess.run(
                ["bash", "-euc", found[0]],
                cwd=scratch,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=60,
                check=True,
            )
            written = sorted(
                path.relative_to(home).as_posix()
                for path in home.rglob("*")
                if path.is_file()
            )
            self.assertEqual(
                [f"{host[2:]}/{SKILL_FOLDER}/SKILL.md" for host in HOSTS], written
            )
            for name in written:
                with self.subTest(path=name):
                    self.assertEqual(SKILL.read_bytes(), (home / name).read_bytes())

    def test_agent_rules_point_at_the_skill_and_its_command(self) -> None:
        agents = " ".join((PROJECT / "AGENTS.md").read_text("utf-8").split())
        self.assertEqual(2, agents.count(f"`{SKILL_FOLDER}/SKILL.md`"))
        self.assertIn(f"`bin/{GENERATE} > {SKILL_FOLDER}/SKILL.md`", agents)
        self.assertFalse((PROJECT / ".agents").exists())


if __name__ == "__main__":
    unittest.main()
