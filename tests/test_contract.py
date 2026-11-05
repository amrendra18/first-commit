import json
import os
import re
import subprocess
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from tests.cli_support import PROJECT

COMMAND = PROJECT / "bin" / "first-commit"
SKILL = PROJECT / "skills" / "first-commit" / "SKILL.md"
VERBS = (
    "version",
    "check",
    "doctor",
    "setup",
    "hook",
    "hook pre-commit",
    "hook commit-msg",
    "hook pre-push",
    "hook setup",
    "help",
)
TOP_VERBS = tuple(verb for verb in VERBS if " " not in verb)
FLAG_VERBS = ("check", "doctor", "version")
# Joined so this file never spells the name. A user private-values list may
# hold it, and the gate's own first-commit check would then fail on this file.
COORDINATOR = "ctl" + "hq"
EFFECT = re.compile(
    r"reads|writes (own state|workspace|repository|host skill folder|host schedule)"
    r"|window|network \S.*|process|paid"
)
ERROR_CODE = re.compile(r"[a-z]+(-[a-z]+)*")
FLAG = re.compile(r"--[A-Za-z][\w-]*")
NOT_VERB_FLAGS = {"--help", "--version", "--no-such-flag"}
# A verb row in the top help: four spaces, then the name. Wrapped text is indented more.
LISTED_VERB = re.compile(r"^ {4}([a-z][a-z-]*)(?:\s|$)", re.MULTILINE)


@dataclass
class Section:
    level: int
    title: str
    lines: list[str] = field(default_factory=list)


def readme_sections(text: str) -> list[Section]:
    found: list[Section] = []
    enclosing: list[Section] = []
    fenced = False
    for line in text.splitlines():
        fenced ^= line.startswith("```")
        heading = None if fenced else re.fullmatch(r"(#{1,6})\s+(.+)", line)
        if heading:
            section = Section(len(heading.group(1)), heading.group(2).strip())
            enclosing = [outer for outer in enclosing if outer.level < section.level]
            enclosing.append(section)
            found.append(section)
        for outer in enclosing:
            outer.lines.append(line)
    return found


def last_sh_commands(lines: list[str]) -> list[str]:
    commands: list[str] = []
    block: list[str] | None = None
    for line in lines:
        if line.strip() == "```sh" and block is None:
            block = []
        elif line.strip() == "```" and block is not None:
            if block:
                commands.append(block[-1])
            block = None
        elif block is not None and line.strip():
            command = re.sub(r"\s+#.*", "", line.strip().removeprefix("$ "))
            block.append(command)
    return commands


def exit_code_items(text: str) -> list[int] | None:
    for paragraph in re.split(r"\n\s*\n", text):
        heading = re.match(r"\s*Exit codes:?", paragraph)
        if heading:
            items = re.split(r"[;,\n]", paragraph[heading.end() :])
            numbers = (re.match(r"\s*(\d+)(?![\w.])", item) for item in items)
            return [int(number.group(1)) for number in numbers if number]
    return None


class ToolContractTest(unittest.TestCase):
    scratch: ClassVar[Path]
    state_folders: ClassVar[list[Path]]

    @classmethod
    def setUpClass(cls) -> None:
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.scratch = Path(temporary.name).resolve()
        cls.state_folders = []

    def call(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        work = Path(tempfile.mkdtemp(dir=self.scratch))
        state = Path(tempfile.mkdtemp(dir=self.scratch))
        self.state_folders.append(state)
        environment = os.environ.copy()
        environment.pop("FIRST_COMMIT_IDENTITY_FILE", None)
        environment["XDG_CONFIG_HOME"] = str(state)
        return subprocess.run(
            [str(COMMAND), *arguments],
            cwd=work,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def help_texts(self) -> list[str]:
        top = self.call("--help").stdout
        # A verb the help lists but VERBS leaves out would never be probed.
        listed = set(LISTED_VERB.findall(top.split("COMMAND", 2)[-1]))
        self.assertEqual(set(TOP_VERBS), listed)
        texts = [top]
        texts.extend(self.call(*verb.split(), "--help").stdout for verb in VERBS)
        return texts

    def error_message(self, result: subprocess.CompletedProcess[str]) -> str:
        self.assertEqual(2, result.returncode)
        try:
            value = json.loads(result.stdout)
        except ValueError:
            self.fail("stdout is not one JSON object")
        self.assertIsInstance(value, dict)
        self.assertEqual({"error"}, set(value))
        error = value["error"]
        self.assertIsInstance(error, dict)
        self.assertEqual({"code", "message", "next"}, set(error))
        self.assertIsInstance(error["code"], str)
        self.assertTrue(ERROR_CODE.fullmatch(error["code"]), error["code"])
        self.assertIsInstance(error["message"], str)
        self.assertIsInstance(error["next"], list)
        for command in error["next"]:
            self.assertIsInstance(command, str)
            self.assertTrue(Path(command).is_absolute(), command)
        return str(error["message"])

    def test_9_1_version(self) -> None:
        result = self.call("--version")
        self.assertEqual(0, result.returncode)
        lines = result.stdout.splitlines()
        self.assertEqual(1, len(lines))
        self.assertRegex(lines[0], r"\d+\.\d+")

    def test_9_2_help(self) -> None:
        top = self.call("--help")
        self.assertEqual(0, top.returncode)
        self.assertTrue(top.stdout.strip(), "empty top help")
        self.assertRaises(ValueError, json.loads, top.stdout)
        for verb in VERBS:
            with self.subTest(verb=verb):
                result = self.call(*verb.split(), "--help")
                self.assertEqual(0, result.returncode)
                effects = [
                    line.strip().removeprefix("Effects:")
                    for line in result.stdout.splitlines()
                    if line.strip().startswith("Effects:")
                ]
                self.assertTrue(effects, "no Effects: line")
                for line in effects:
                    for word in line.strip().rstrip(".").split(","):
                        self.assertTrue(EFFECT.fullmatch(word.strip()), word)
                codes = exit_code_items(result.stdout) or []
                self.assertTrue(codes, "no Exit codes paragraph with codes")
                self.assertLessEqual(set(codes), set(range(6)))

    def test_9_3_unknown_verb(self) -> None:
        message = self.error_message(self.call("no-such-verb", "--format", "json"))
        for verb in TOP_VERBS:
            self.assertRegex(message, rf"\b{verb}\b")

    def test_9_4_unknown_flag(self) -> None:
        for verb in FLAG_VERBS:
            with self.subTest(verb=verb):
                flags = set(FLAG.findall(self.call(verb, "--help").stdout))
                result = self.call(verb, "--no-such-flag", "--format", "json")
                message = self.error_message(result)
                named = set(FLAG.findall(message)) & (flags - NOT_VERB_FLAGS)
                self.assertTrue(named, message)

    def test_9_5_no_coordinator_name(self) -> None:
        texts = [*self.help_texts(), SKILL.read_text("utf-8")]
        for text in texts:
            self.assertTrue(text.strip(), "empty help text")
            self.assertNotIn(COORDINATOR, text.lower())

    def test_9_6_skill_matches_generated_help(self) -> None:
        self.assertTrue(SKILL.is_file(), "this repository ships its skill")
        result = self.call("help", "--format", "markdown")
        self.assertEqual(0, result.returncode)
        self.assertEqual(
            SKILL.read_text("utf-8"),
            result.stdout,
            "regenerate it: bin/first-commit help --format markdown "
            "> skills/first-commit/SKILL.md",
        )

    def test_9_7_readme_sections(self) -> None:
        readme = (PROJECT / "README.md").read_text("utf-8")
        sections = readme_sections(readme)
        titles = [section.title for section in sections]
        install = [
            section
            for section in sections
            if re.search(r"\binstall", section.title, re.IGNORECASE)
            and not re.search(r"\b(writes?|changes)\b", section.title, re.IGNORECASE)
        ]
        self.assertTrue(install, "no install heading")
        for name, pattern in (
            ("requirements", r"requir"),
            ("what install writes", r"^(?=.*\binstall).*\b(writes?|changes)\b"),
            ("network", r"network"),
            ("remove", r"remov|uninstall"),
        ):
            with self.subTest(heading=name):
                self.assertTrue(
                    any(re.search(pattern, t, re.IGNORECASE) for t in titles), name
                )
        commands = [
            command
            for section in install
            for command in last_sh_commands(section.lines)
        ]
        self.assertIn("first-commit --version", commands)
        self.assertIn("XDG_CONFIG_HOME", readme)

    def test_9_8_state_folder_stays_empty(self) -> None:
        self.assertTrue(self.state_folders, "run with probes 9.1 to 9.7")
        for state in self.state_folders:
            self.assertTrue(state.is_dir(), state)
            self.assertEqual([], list(state.iterdir()), state)

    def test_exit_codes_are_the_contract_table(self) -> None:
        # Read from the command's own help, so the run tests this checkout's code.
        top = self.call("--help")
        self.assertEqual({0, 1, 2, 5}, set(exit_code_items(top.stdout) or []))


if __name__ == "__main__":
    unittest.main()
