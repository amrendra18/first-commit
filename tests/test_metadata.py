import hashlib
import json
import os
import re
import tomllib
import unittest
from pathlib import Path

from first_commit import __version__
from first_commit.hooks import HTTPS_REPOSITORY, SSH_REPOSITORY
from first_commit.models import EXIT_CODE_MEANINGS
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from first_commit.setup_hooks import hook_bytes

# The only public email this repository approves: the agent co-author trailer address.
AGENT_TRAILER_EMAIL = "noreply@" + "anthropic.com"
# Private-era statements and private workflow words; public documents state current facts.
# The README starts with its banner image.
BANNER = "![first-commit: No more setting up hooks by hand.](.github/banner.svg)\n\n"
PRIVATE_ERA_WORDS = re.compile(
    r"is private|private repository|development host|not been run yet|"
    r"before Actions runs|once the repository is public|\boperator\b|handoff|"
    r"handing off|Agents run",
    re.IGNORECASE,
)


def _anchors(document: Path) -> set[str]:
    text = document.read_text("utf-8")
    prose = re.sub(r"^```.*?^```", "", text, flags=re.MULTILINE | re.DOTALL)
    anchors: set[str] = set()
    for heading in re.findall(r"^#+ (.+)$", prose, re.MULTILINE):
        base = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        anchor, repeat = base, 1
        while anchor in anchors:
            anchor, repeat = f"{base}-{repeat}", repeat + 1
        anchors.add(anchor)
    return anchors


class MetadataTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]

    def test_commit_policy_and_local_template_are_consistent(self) -> None:
        from first_commit.checks.messages import message_findings
        from first_commit.models import Candidate, Origin

        template = (self.root / ".gitmessage").read_text("utf-8")
        packaged = self.root / "src/first_commit/data/commit-message.txt"
        self.assertEqual(template, packaged.read_text("utf-8"))
        for section in ("Why:", "Changes:", "Test Plan:", "Risks:"):
            self.assertIn(section, template)
        filled = template.replace(
            "<type>(<scope>)!: <subject>", "feat(cli): add policy checks"
        )
        for placeholder, replacement in (
            ("<reason>", "Explain the need."),
            ("<changes>", "Describe the update."),
            ("<commands and results>", "Run the focused tests."),
            ("<risks>", "Low: limited to commit validation."),
        ):
            filled = filled.replace(placeholder, replacement)
        self.assertEqual(
            [],
            message_findings(
                Candidate("message", filled.encode("utf-8"), Origin.MESSAGE),
                max_findings=100,
            ),
        )

    def test_documentation_inventory_has_one_file_per_contract(self) -> None:
        expected = {
            "AGENTS.md",
            "CLAUDE.md",
            "README.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "ARCHITECTURE.md",
            ".agents/skills/first-commit/SKILL.md",
        }
        actual = {
            path.relative_to(self.root).as_posix() for path in self.root.glob("*.md")
        }
        actual.update(
            path.relative_to(self.root).as_posix()
            for path in (self.root / ".agents").rglob("*.md")
        )
        self.assertEqual(expected, actual)
        policy = json.loads((self.root / ".repo-policy.json").read_text("utf-8"))
        self.assertEqual(
            {"schema_version": 1, "public_emails": [AGENT_TRAILER_EMAIL]}, policy
        )
        for path in expected - {".agents/skills/first-commit/SKILL.md", "CLAUDE.md"}:
            content = (self.root / path).read_text("utf-8")
            if path == "README.md":
                content = content.removeprefix(BANNER)
            self.assertTrue(content.startswith("# "), path)
            self.assertNotIn("<!--", content, path)

    def test_repository_policy_requires_existing_documents(self) -> None:
        raw = (self.root / ".repo-policy.json").read_bytes()
        policy = parse_policy(raw, self.root)
        self.assertEqual((), policy.contributor_emails)
        self.assertIsInstance(policy.commit_body_sections, bool)
        self.assertTrue(policy.commit_body_sections)
        self.assertEqual((AGENT_TRAILER_EMAIL,), policy.public_emails)
        for path in REQUIRED_DOCUMENTS:
            self.assertTrue((self.root / path).is_file(), path)

    def test_readme_stays_a_short_entry_point(self) -> None:
        readme = (self.root / "README.md").read_text("utf-8")
        words = readme.removeprefix(BANNER).split()
        self.assertLessEqual(len(words), 1500)

    def test_public_documents_hold_no_private_era_or_workflow_words(self) -> None:
        documents = [
            *self.root.glob("*.md"),
            *(self.root / ".agents").rglob("*.md"),
            *(self.root / ".github").rglob("*.md"),
            *(self.root / "verify").rglob("*.md"),
        ]
        for document in documents:
            text = " ".join(document.read_text("utf-8").split())
            with self.subTest(path=document.relative_to(self.root).as_posix()):
                self.assertEqual([], PRIVATE_ERA_WORDS.findall(text))

    def test_reference_exit_codes_match_the_command(self) -> None:
        reference = (self.root / "ARCHITECTURE.md").read_text("utf-8")
        codes = ", ".join(
            f"`{int(code)}` {meaning}" for code, meaning in EXIT_CODE_MEANINGS.items()
        )
        self.assertIn(f"Exit codes: {codes}.", " ".join(reference.split()))

    def test_contributing_runs_only_scripts_that_exist(self) -> None:
        contributing = (self.root / "CONTRIBUTING.md").read_text("utf-8")
        blocks = "".join(re.findall(r"```sh\n(.*?)```", contributing, re.DOTALL))
        scripts = set(re.findall(r"(?<![\w/.])scripts/[\w-]+", blocks))
        self.assertTrue(scripts)
        for script in scripts:
            with self.subTest(script=script):
                self.assertTrue(os.access(self.root / script, os.X_OK))

    def test_readme_covers_upgrade_and_removal(self) -> None:
        readme = (self.root / "README.md").read_text("utf-8")
        section = readme.split("\n## Upgrade\n", 1)[1].split("\n## Learn more\n", 1)[0]
        for detail in (
            "pre-commit autoupdate --freeze",
            "pre-commit uninstall",
            "git config --local --unset-all",
            "rm -rf .local/first-commit .local/bin/gitleaks",
        ):
            with self.subTest(detail=detail):
                self.assertIn(detail, section)

    def test_readme_clone_commands_need_no_installed_tool(self) -> None:
        readme = (self.root / "README.md").read_text("utf-8")
        for command in (
            "pre-commit run first-commit-check --hook-stage manual --all-files",
            "pre-commit run first-commit-doctor --hook-stage manual --all-files",
        ):
            with self.subTest(command=command):
                self.assertIn(command + "\n", readme)

    def test_readme_first_run_commands_are_ordered_and_use_the_tool_path(
        self,
    ) -> None:
        readme = (self.root / "README.md").read_text("utf-8")
        steps = (
            f"git+{HTTPS_REPOSITORY}.git@v{__version__}",
            f"git+{SSH_REPOSITORY}.git@v{__version__}",
            "FIRST_COMMIT=/path/first-commit/bin/first-commit",
            '"$FIRST_COMMIT" version',
            '"$FIRST_COMMIT" setup --dry-run',
            '"$FIRST_COMMIT" setup\n',
            '"$FIRST_COMMIT" doctor',
            "\ngit add ",
            "\ngit commit\n",
            '"$FIRST_COMMIT" check',
        )
        positions = [readme.index(step) for step in steps]
        self.assertEqual(sorted(positions), positions)
        commands = re.findall(r"```sh\n(.*?)```", readme, re.DOTALL)
        for line in "".join(commands).splitlines():
            self.assertFalse(line.startswith("first-commit "), line)

    def test_package_and_policy_versions_match(self) -> None:
        example = json.loads(
            (self.root / "examples/repo-policy.json").read_text("utf-8")
        )
        pyproject = (self.root / "pyproject.toml").read_text("utf-8")
        packaged = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)

        if packaged is None:
            self.fail("pyproject.toml has no version line")
        self.assertEqual(1, example["schema_version"])
        self.assertEqual(__version__, packaged.group(1))

    def test_test_environment_includes_exact_build_dependencies(self) -> None:
        pyproject = tomllib.loads((self.root / "pyproject.toml").read_text("utf-8"))
        build_dependencies = set(pyproject["build-system"]["requires"])
        test_dependencies = set(pyproject["project"]["optional-dependencies"]["test"])

        self.assertTrue(build_dependencies)
        self.assertTrue(all("==" in dependency for dependency in build_dependencies))
        self.assertLessEqual(build_dependencies, test_dependencies)
        setup_dependencies = set(pyproject["project"]["optional-dependencies"]["setup"])
        self.assertLessEqual(setup_dependencies, test_dependencies)
        self.assertEqual([], pyproject["project"]["dependencies"])

    def test_setup_extra_pins_the_whole_pre_commit_tree_exactly(self) -> None:
        pyproject = tomllib.loads((self.root / "pyproject.toml").read_text("utf-8"))
        setup = pyproject["project"]["optional-dependencies"]["setup"]
        pins = dict(item.split("==", 1) for item in setup)

        self.assertTrue(all(item.count("==") == 1 for item in setup))
        self.assertEqual(
            {
                "PyYAML",
                "cfgv",
                "distlib",
                "filelock",
                "identify",
                "nodeenv",
                "platformdirs",
                "pre-commit",
                "python-discovery",
                "virtualenv",
            },
            set(pins),
        )

    def test_python_support_matches_the_ci_matrix(self) -> None:
        pyproject = tomllib.loads((self.root / "pyproject.toml").read_text("utf-8"))
        workflow = (self.root / ".github" / "workflows" / "ci.yml").read_text("utf-8")

        self.assertEqual(">=3.11,<3.15", pyproject["project"]["requires-python"])
        self.assertIn('python: ["3.11", "3.12", "3.13", "3.14"]', workflow)

    def test_public_identity_is_first_commit(self) -> None:
        pyproject = tomllib.loads((self.root / "pyproject.toml").read_text("utf-8"))
        readme = (self.root / "README.md").read_text("utf-8")
        consumer_example = hook_bytes("1" * 40).decode("utf-8")
        repository_url = HTTPS_REPOSITORY

        self.assertEqual("first-commit", pyproject["project"]["name"])
        self.assertEqual(
            {"first-commit": "first_commit.cli:main"},
            pyproject["project"]["scripts"],
        )
        self.assertEqual(
            repository_url,
            pyproject["project"]["urls"]["Repository"],
        )
        self.assertIn(repository_url, readme)
        self.assertIn(f'repo: "{repository_url}"', consumer_example)
        self.assertNotIn("OWNER", readme)
        self.assertNotIn("OWNER", consumer_example)
        self.assertTrue((self.root / "examples/repo-policy.json").is_file())
        self.assertTrue((self.root / "bin" / "first-commit").is_file())
        self.assertTrue((self.root / "src" / "first_commit" / "cli.py").is_file())

    def test_documentation_links_and_anchors_resolve(self) -> None:
        documents = [
            *self.root.glob("*.md"),
            *(self.root / ".agents").rglob("*.md"),
            *(self.root / ".github").rglob("*.md"),
            *(self.root / "verify").rglob("*.md"),
        ]
        for document in documents:
            for target in re.findall(
                r"\[[^\]]+\]\(([^)]+)\)", document.read_text("utf-8")
            ):
                if "://" in target:
                    continue
                path, _, anchor = target.partition("#")
                linked = (document.parent / path).resolve() if path else document
                with self.subTest(document=document.name, target=target):
                    self.assertTrue(linked.exists())
                    if anchor:
                        self.assertIn(anchor, _anchors(linked))

    def test_license_is_exact_apache_2_text(self) -> None:
        digest = hashlib.sha256((self.root / "LICENSE").read_bytes()).hexdigest()

        self.assertEqual(
            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
            digest,
        )

    def test_hook_metadata_declares_all_required_stages(self) -> None:
        provider = (self.root / ".pre-commit-hooks.yaml").read_text("utf-8")
        consumer = hook_bytes("1" * 40).decode("utf-8")

        message_hook = provider.split("- id: first-commit-message\n", 1)[1].split(
            "- id: ", 1
        )[0]
        self.assertIn("verbose: true", message_hook)

        for hook_id, stage in (
            ("first-commit-staged", "pre-commit"),
            ("first-commit-message", "commit-msg"),
            ("first-commit-push", "pre-push"),
            ("first-commit-setup", "manual"),
            ("first-commit-doctor", "manual"),
            ("first-commit-check", "manual"),
        ):
            self.assertIn(f"id: {hook_id}", provider)
            self.assertIn(f"stages: [{stage}]", provider)
            self.assertIn(f"- id: {hook_id}", consumer)
        for command in ("doctor", "check"):
            hook = provider.split(f"- id: first-commit-{command}\n", 1)[1].split(
                "- id: ", 1
            )[0]
            self.assertIn(f"entry: first-commit {command}\n", hook)
            self.assertIn("stages: [manual]", hook)
            self.assertIn("verbose: true", hook)
            self.assertIn("pass_filenames: false", hook)
        self.assertEqual(6, provider.count('minimum_pre_commit_version: "3.2.0"'))
        self.assertEqual(6, provider.count("always_run: true"))
        setup_hook = provider.split("- id: first-commit-setup\n", 1)[1]
        self.assertIn("entry: first-commit hook setup", setup_hook)
        self.assertIn("verbose: true", setup_hook)
        self.assertIn('minimum_pre_commit_version: "3.2.0"', consumer)
        self.assertIn("default_install_hook_types:\n", consumer)
        self.assertIn("repos:\n", consumer)
        self.assertFalse(consumer.startswith("{"))


if __name__ == "__main__":
    unittest.main()
