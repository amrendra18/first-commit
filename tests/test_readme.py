import hashlib
import io
import json
import os
import re
import signal
import subprocess
import tempfile
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from first_commit import __version__, cli
from first_commit.candidates import CandidateError, _split_paths
from first_commit.checks.identity import SIGNATURE_TRUST_RULE
from first_commit.checks.messages import TYPES, message_findings
from first_commit.checks.privacy import PrivacyPolicy, privacy_findings
from first_commit.fixes import HOOK_FIXES
from first_commit.gitleaks_scanner import SCANNER_VERSION
from first_commit.hooks import GITHUB_REPOSITORY, HTTPS_REPOSITORY, SSH_REPOSITORY
from first_commit.models import Candidate, Origin
from first_commit.policy import parse_policy
from first_commit.policy_fields import DEFAULT_LIMITS
from first_commit.setup_apply import terminated_error
from tests.test_verify_script import harness

ROOT = Path(__file__).resolve().parents[1]
core = harness("core")
README = (ROOT / "README.md").read_text("utf-8")
ARCHITECTURE = (ROOT / "ARCHITECTURE.md").read_text("utf-8")
FIRST_RUN = (ROOT / "verify/features/first-run.md").read_text("utf-8")
COMMIT = (ROOT / "verify/features/commit.md").read_text("utf-8")
# Documents and metadata that cannot import the address; the test compares them.
PUBLIC_TEXTS = (
    "README.md",
    "AGENTS.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    ".agents/skills/first-commit/SKILL.md",
    ".github/ISSUE_TEMPLATE/bug_report.md",
    "verify/features/README.md",
    "pyproject.toml",
    ".github/workflows/ci.yml",
    ".pre-commit-hooks.yaml",
)
GITHUB_ADDRESS = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
THIRD_PARTY = frozenset({"gitleaks/gitleaks", "zricethezav/gitleaks"})
DRY_RUN_HEADING = (
    "Expected dry run in an empty folder, with no saved identity:\n\n```text\n"
)
EXAMPLE_MESSAGE_HEADING = "Example message:\n\n```text\n"
HOOK_LINES_HEADING = "Expected hook lines:\n\n```text\n"
DIGEST_LINE = re.compile(r"^awk .*shasum -a 256$", re.MULTILINE)
VERSION = re.compile(r"\b\d+\.\d+\.\d+\b")
PRIVATE = "Private Person"


def _block(text: str, heading: str) -> str:
    return text.split(heading, 1)[1].split("```", 1)[0]


def _section(heading: str, text: str = README) -> str:
    return " ".join(text.split(f"\n## {heading}\n", 1)[1].split("\n## ", 1)[0].split())


def _flat(path: str) -> str:
    return " ".join((ROOT / path).read_text("utf-8").split())


class ReadmeTest(unittest.TestCase):
    def test_dry_run_block_equals_the_real_dry_run(self) -> None:
        unset = (
            "PRE_COMMIT_HOME",
            "FIRST_COMMIT_AUTHOR_NAME",
            "FIRST_COMMIT_AUTHOR_EMAIL",
            "FIRST_COMMIT_SIGNING_KEY",
        )
        with (
            tempfile.TemporaryDirectory() as machine,
            tempfile.TemporaryDirectory() as blank,
        ):
            environment = {
                key: value for key, value in os.environ.items() if key not in unset
            }
            environment["FIRST_COMMIT_IDENTITY_FILE"] = str(Path(machine) / "none.json")
            output, error = io.StringIO(), io.StringIO()
            with (
                patch.dict(os.environ, environment, clear=True),
                redirect_stdout(output),
                redirect_stderr(error),
            ):
                code = cli.main(
                    ("setup", "--dry-run", "--revision", "1" * 40, "--root", blank)
                )
            self.assertEqual((0, ""), (code, error.getvalue()))
            self.assertEqual(
                _block(FIRST_RUN, DRY_RUN_HEADING).splitlines(),
                output.getvalue().splitlines(),
            )
            self.assertEqual([], list(Path(blank).iterdir()))

    def test_first_commit_example_message_passes_the_message_check(self) -> None:
        message = _block(README, EXAMPLE_MESSAGE_HEADING)
        self.assertEqual(
            [],
            message_findings(
                Candidate("message", message.encode("utf-8"), Origin.MESSAGE),
                max_findings=100,
            ),
        )

    def test_first_commit_stages_every_file_the_dry_run_creates(self) -> None:
        created = next(
            line.split("would create ", 1)[1].split(", ")
            for line in _block(FIRST_RUN, DRY_RUN_HEADING).splitlines()
            if line.startswith("Files: ")
        )
        staged = next(
            line.split()[2:]
            for line in README.splitlines()
            if line.startswith("git add ")
        )
        self.assertEqual(sorted(created), sorted(staged))
        self.assertIn("\ngit commit\n", README)

    def test_expected_hook_lines_name_the_shipped_commit_hooks(self) -> None:
        manifest = (ROOT / ".pre-commit-hooks.yaml").read_text("utf-8")
        names = set(re.findall(r"^  name: (.+)$", manifest, re.MULTILINE))
        lines = _block(COMMIT, HOOK_LINES_HEADING).splitlines()
        shown = [line.split("..", 1)[0] for line in lines if line.endswith("Passed")]
        self.assertEqual(
            ["first-commit staged hygiene", "first-commit commit-message hygiene"],
            shown,
        )
        self.assertLessEqual(set(shown), names)

    def test_line_digest_command_gives_the_digest_the_exception_needs(self) -> None:
        template = DIGEST_LINE.search(ARCHITECTURE)
        if template is None:
            self.fail("ARCHITECTURE.md has no line digest command")
        for ending in ("\n", "\r\n"):
            with (
                self.subTest(ending=repr(ending)),
                tempfile.TemporaryDirectory() as folder,
            ):
                content = ending.join(
                    ("First line", f"Copyright {PRIVATE}", "Last", "")
                )
                (Path(folder) / "LICENSE").write_bytes(content.encode("utf-8"))
                command = template.group(0).replace("NR == 12", "NR == 2")
                command = command.replace("path/to/file", "LICENSE")
                result = subprocess.run(
                    ["/bin/sh", "-c", command],
                    cwd=folder,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                digest = result.stdout.split()[0]
                exception = {
                    "path": "LICENSE",
                    "line": 2,
                    "sha256": digest,
                    "reason": "Approved public copyright attribution.",
                }
                policy = parse_policy(
                    json.dumps(
                        {"schema_version": 1, "private_literal_exceptions": [exception]}
                    ).encode(),
                    Path(folder),
                )
                candidate = Candidate("LICENSE", content.encode("utf-8"), Origin.INDEX)
                privacy = PrivacyPolicy(private_values=(PRIVATE.lower(),))
                self.assertEqual(
                    1, len(privacy_findings(candidate, privacy, max_findings=1000))
                )
                approved = PrivacyPolicy(
                    private_values=(PRIVATE.lower(),),
                    literal_exceptions=policy.literal_exceptions,
                )
                self.assertEqual(
                    [], privacy_findings(candidate, approved, max_findings=1000)
                )
                line = content.split("\n")[1]
                self.assertEqual(hashlib.sha256(line.encode()).hexdigest(), digest)


class PublicFactsTest(unittest.TestCase):
    def test_install_tag_is_the_package_version_and_can_be_checked(self) -> None:
        tags = re.findall(r"\.git@(v[^'\s]+)'", README)
        self.assertEqual([f"v{__version__}"] * 2, tags)
        self.assertIn(f"git ls-remote {HTTPS_REPOSITORY} 'v{__version__}^{{}}'", README)

    def test_readme_names_the_version_command(self) -> None:
        self.assertIn('"$FIRST_COMMIT" version\n', README)
        self.assertIn("`--version`", README)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, cli.main(("version",)))
        self.assertEqual(__version__ + "\n", output.getvalue())

    def test_every_github_address_is_the_one_constant(self) -> None:
        for document in PUBLIC_TEXTS:
            with self.subTest(path=document):
                text = (ROOT / document).read_text("utf-8")
                found = {
                    name.removesuffix(".git") for name in GITHUB_ADDRESS.findall(text)
                }
                self.assertLessEqual(found, {GITHUB_REPOSITORY, *THIRD_PARTY})
        code = [
            *(ROOT / "src").rglob("*.py"),
            *(ROOT / "tests").rglob("*.py"),
            *(path for path in (ROOT / "scripts").rglob("*") if path.is_file()),
        ]
        for path in code:
            if path.name == "hooks.py" or "__pycache__" in path.parts:
                continue
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                self.assertNotIn(GITHUB_REPOSITORY, path.read_text("utf-8"))
        self.assertIn(HTTPS_REPOSITORY, README)
        self.assertIn(f"git+{SSH_REPOSITORY}.git@", README)
        urls = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"][
            "urls"
        ]
        self.assertEqual(
            {
                "Homepage": HTTPS_REPOSITORY,
                "Repository": HTTPS_REPOSITORY,
                "Issues": HTTPS_REPOSITORY + "/issues",
                "Releases": HTTPS_REPOSITORY + "/releases",
            },
            urls,
        )
        self.assertEqual((HTTPS_REPOSITORY, SSH_REPOSITORY), (core.HTTPS, core.SSH))

    def test_commit_types_are_listed_in_the_reference_and_the_template(self) -> None:
        types = TYPES.split("|")
        listed = ", ".join(f"`{name}`" for name in types)
        self.assertIn(f"`<type>` is one of {listed}.", " ".join(ARCHITECTURE.split()))
        template = (ROOT / ".gitmessage").read_text("utf-8")
        comments = " ".join(
            line.removeprefix("#").strip()
            for line in template.splitlines()
            if line.startswith("#")
        )
        self.assertIn(f"Types: {', '.join(types)}.", comments)

    def test_each_identity_file_mention_names_the_xdg_location(self) -> None:
        for name, text in (("README.md", README), ("ARCHITECTURE.md", ARCHITECTURE)):
            mentions = [
                part
                for part in text.split("\n\n")
                if "~/.config/first-commit/identity.json" in part
            ]
            self.assertTrue(mentions, name)
            for part in mentions:
                with self.subTest(path=name, part=part[:60]):
                    self.assertIn("$XDG_CONFIG_HOME/first-commit/identity.json", part)

    def test_readme_says_how_to_install_pre_commit(self) -> None:
        hooks = (ROOT / ".pre-commit-hooks.yaml").read_text("utf-8")
        minimum = re.findall(r'minimum_pre_commit_version: "([^"]+)"', hooks)
        self.assertEqual(1, len(set(minimum)))
        text = " ".join(README.split())
        for detail in (
            f"pre-commit {minimum[0]} or newer",
            "`pipx install --python python3.13 pre-commit`",
            "`brew install pre-commit`",
            "`pre-commit --version`",
        ):
            with self.subTest(detail=detail):
                self.assertIn(detail, text)

    def test_recovery_names_the_commands_for_pre_commit_on_an_old_python(self) -> None:
        recover = _section("Stop and recover")
        for detail in (
            "`No matching distribution found for setuptools`",
            "`python3 -m pip uninstall pre-commit`",
            "`pipx install --force --python python3.13 pre-commit`",
            "`pre-commit install`",
        ):
            with self.subTest(detail=detail):
                self.assertIn(detail, recover)

    def test_recovery_names_each_pre_commit_log_location(self) -> None:
        recover = _section("Stop and recover")
        for detail in (
            "`~/.cache/pre-commit/pre-commit.log`",
            "`$PRE_COMMIT_HOME/pre-commit.log`",
            "`$XDG_CACHE_HOME/pre-commit/pre-commit.log`",
        ):
            with self.subTest(detail=detail):
                self.assertIn(detail, recover)

    def test_readme_and_architecture_name_the_path_limit_and_its_fix(self) -> None:
        limit = DEFAULT_LIMITS["max_files"]
        with self.assertRaises(CandidateError) as context:
            _split_paths(b"path\0" * (limit + 1), limit)
        first_sentence = str(context.exception).split(". ", 1)[0]
        for text in (_section("Stop and recover"), _section("Limits", ARCHITECTURE)):
            self.assertIn(f"`{first_sentence}.`", text)
        self.assertIn("`node_modules/`", _section("Stop and recover"))

    def test_first_run_names_the_printed_results_and_the_trust_fix(self) -> None:
        first_run = _section("Start a project")
        printed_fix = HOOK_FIXES[SIGNATURE_TRUST_RULE]
        command = printed_fix.removeprefix("Run ").split(" in this checkout", 1)[0]
        for detail in (
            "`Verification: passed`",
            "`WARN doctor`",
            f"`{SIGNATURE_TRUST_RULE}`",
            command,
        ):
            with self.subTest(detail=detail):
                self.assertIn(detail, first_run)

    def test_architecture_names_the_printed_ctrl_c_lines(self) -> None:
        for line in (cli.INTERRUPTED, str(terminated_error(signal.SIGINT))):
            with self.subTest(line=line):
                self.assertIn(f"`error: {line}`", _flat("ARCHITECTURE.md"))

    def test_documented_gitleaks_and_pre_commit_pins_match_their_owners(self) -> None:
        dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))[
            "project"
        ]["optional-dependencies"]["setup"]
        pins = {item for item in dependencies if item.startswith("pre-commit==")}
        found: dict[str, set[str]] = {"Gitleaks": set(), "pre-commit": set()}
        for name in ("README.md", "ARCHITECTURE.md", "CONTRIBUTING.md"):
            text = _flat(name)
            for match in VERSION.finditer(text):
                before = text[max(0, match.start() - 50) : match.start()]
                minimum = text.startswith(" or newer", match.end())
                if "Gitleaks" in before:
                    found["Gitleaks"].add(match.group())
                elif before.endswith("pre-commit ") and not minimum:
                    found["pre-commit"].add("pre-commit==" + match.group())
        self.assertEqual({"Gitleaks": {SCANNER_VERSION}, "pre-commit": pins}, found)


if __name__ == "__main__":
    unittest.main()
