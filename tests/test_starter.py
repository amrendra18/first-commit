import inspect
import re
import unittest

from first_commit.generated_files import DOCUMENT_NAMES, proposal_name
from first_commit.hooks import HTTPS_REPOSITORY as HTTPS_SOURCE
from first_commit.hooks import SSH_REPOSITORY as SSH_SOURCE
from first_commit.policy import REQUIRED_DOCUMENTS
from first_commit.starter import (
    DOCUMENT_SETS,
    DOCUMENTS,
    IGNORE_FILE,
    MARKER,
    NOTICE,
    STYLE_FILES,
    proposal_content,
    starter_files,
)

CORE = {"README.md", "AGENTS.md"}
FULL = CORE | {"PRD.md", "CONTRIBUTING.md", "SECURITY.md"}
PINNED = "` at the commit `.pre-commit-config.yaml` pins."
COMMIT_SHA = re.compile(r"\b[0-9a-f]{40}\b")
MIN_AGENT_WORDS, MAX_AGENT_WORDS = 150, 210
MIN_SECTIONS, MAX_SECTIONS = 3, 5
INSTEAD_OF = f'git config --global url."{HTTPS_SOURCE}".insteadOf "{SSH_SOURCE}"\n'
MACHINE_WIDE_INSTEAD_OF = 'url."https://github.com/".insteadOf'


def _files(
    docs: str = "full", source: str = SSH_SOURCE, *, hooks: bool = True
) -> dict[str, bytes]:
    return starter_files(docs, source=source, setup_hook=hooks, check_hook=hooks)


def _text(name: str, docs: str = "full", source: str = SSH_SOURCE) -> str:
    return _files(docs, source)[name].decode("utf-8")


class StarterTest(unittest.TestCase):
    def test_core_is_default_and_full_adds_project_documents(self) -> None:
        self.assertEqual(CORE | set(STYLE_FILES), set(_files("core")))
        self.assertEqual(FULL | set(STYLE_FILES), set(_files("full")))
        self.assertEqual(FULL, set(DOCUMENTS))
        self.assertEqual(set(DOCUMENT_NAMES), set(DOCUMENTS))
        self.assertEqual(REQUIRED_DOCUMENTS, DOCUMENT_SETS["core"])
        with self.assertRaises(KeyError):
            _files("all")
        required = {
            name
            for name, parameter in inspect.signature(starter_files).parameters.items()
            if parameter.kind is inspect.Parameter.KEYWORD_ONLY
            and parameter.default is inspect.Parameter.empty
        }
        self.assertEqual({"source", "setup_hook", "check_hook"}, required)

    def test_documents_start_with_notice_then_marker(self) -> None:
        files = _files("full")
        prefix = (NOTICE + MARKER).encode("utf-8")
        for name in DOCUMENTS:
            with self.subTest(name=name):
                self.assertTrue(files[name].startswith(prefix))
                self.assertEqual(1, files[name].count(b"@no-commit"))
        for name in STYLE_FILES:
            with self.subTest(name=name):
                self.assertNotIn(b"@no-commit", files[name])

    def test_readme_sections_follow_execution_order(self) -> None:
        lines = _text("README.md").splitlines()
        headings = [line for line in lines if line.startswith("#")]
        self.assertEqual(
            [
                "# Project name",
                "## Prerequisites",
                "## First run",
                "## Contributors",
                "## Routine use",
                "## Stop and recover",
            ],
            headings,
        )
        for heading in headings:
            with self.subTest(heading=heading):
                guidance = lines[lines.index(heading) + 2]
                self.assertTrue(guidance.endswith("."))
                self.assertFalse(guidance.startswith("#"))

    def test_agents_rules_require_authorization_and_verification(self) -> None:
        text = _text("AGENTS.md")
        flat = " ".join(text.split())
        self.assertEqual(
            ["## Context", "## Authority", "## Engineering", "## Verification"],
            [line for line in text.splitlines() if line.startswith("## ")],
        )
        for rule in (
            (
                "Git configuration, hook or dependency installation, staging, commits, "
                "remotes, publication, and external services require explicit "
                "authorization."
            ),
            "Stage only approved paths",
            "Preserve unrelated work.",
            "Use simple, neutral, technical English.",
            "Use `README.md` as the novice entry point.",
            "in execution order",
            "Prefer the smallest complete design.",
            "Use secure defaults",
            "require opt-in for risky behavior",
            "Use red-green-refactor for behavior changes.",
            (
                "Run focused tests and the project's full check before you open a "
                "pull request."
            ),
            "Report missing dependencies",
            "residual risks",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, flat)
        self.assertNotIn("first-commit", text)
        for private_workflow in (".local/", "review notes", "handoff"):
            with self.subTest(private_workflow=private_workflow):
                self.assertNotIn(private_workflow, text)
        words = len(text.removeprefix(NOTICE + MARKER).split())
        self.assertTrue(MIN_AGENT_WORDS <= words <= MAX_AGENT_WORDS, words)

    def test_full_documents_are_short_section_outlines(self) -> None:
        for name in ("PRD.md", "CONTRIBUTING.md", "SECURITY.md"):
            with self.subTest(name=name):
                lines = _text(name).splitlines()
                sections = [line for line in lines if line.startswith("## ")]
                self.assertTrue(MIN_SECTIONS <= len(sections) <= MAX_SECTIONS)
                self.assertEqual(1, sum(line.startswith("# ") for line in lines))
                for heading in sections:
                    self.assertTrue(lines[lines.index(heading) + 2].endswith("."))
        security = " ".join(_text("SECURITY.md").split())
        self.assertIn("privately", security)
        self.assertIn("Revoke an exposed credential at its issuer", security)

    def test_core_readme_names_the_hook_source_and_no_commit(self) -> None:
        readme = _text("README.md", "core")
        self.assertIn("## Contributors\n", readme)
        self.assertIn("pre-commit hooks", readme)
        self.assertIn("`" + SSH_SOURCE + PINNED, readme)
        self.assertIsNone(COMMIT_SHA.search(readme))
        self.assertIn("pre-commit install\n", readme)
        self.assertIn("pre-commit run first-commit-setup --hook-stage manual\n", readme)
        self.assertIn(
            "pre-commit run first-commit-check --hook-stage manual --all-files", readme
        )
        self.assertIn("FIRST_COMMIT_IDENTITY_FILE", readme)
        self.assertIn("~/.config/first-commit/identity.json", readme)
        self.assertIn("`$XDG_CONFIG_HOME/first-commit/identity.json`", readme)
        self.assertIn("installs the Gitleaks scanner", " ".join(readme.split()))
        self.assertIn("does not change files", readme)
        self.assertIn("Python 3.11 to 3.14", readme)
        self.assertIn("python3.13", readme)
        self.assertIn("takes several minutes", readme)
        self.assertIn(INSTEAD_OF, readme)
        self.assertNotIn(MACHINE_WIDE_INSTEAD_OF, readme)
        self.assertEqual(1, readme.count("@no-commit"))

    def test_onboarding_installs_pre_commit_as_the_tool_readme_does(self) -> None:
        for docs in ("core", "full"):
            text = " ".join(
                _text(
                    "README.md" if docs == "core" else "CONTRIBUTING.md", docs
                ).split()
            )
            for detail in (
                "`pipx install --python python3.13 pre-commit`",
                "`brew install pre-commit`",
            ):
                with self.subTest(docs=docs, detail=detail):
                    self.assertIn(detail, text)
            self.assertNotIn("-m pip install", text)

    def test_onboarding_names_the_clone_hooks_by_the_hook_file_shape(
        self,
    ) -> None:
        setup = "pre-commit run first-commit-setup --hook-stage manual"
        check = "pre-commit run first-commit-check --hook-stage manual --all-files"
        for setup_hook, check_hook in ((False, True), (True, False), (False, False)):
            with self.subTest(setup_hook=setup_hook, check_hook=check_hook):
                readme = starter_files(
                    "core",
                    source=HTTPS_SOURCE,
                    setup_hook=setup_hook,
                    check_hook=check_hook,
                )["README.md"].decode("utf-8")
                self.assertIn("pre-commit install\n", readme)
                self.assertEqual(setup_hook, setup in readme)
                self.assertEqual(setup_hook, "FIRST_COMMIT_AUTHOR_NAME" in readme)
                self.assertEqual(setup_hook or check_hook, check in readme)
                self.assertEqual(
                    setup_hook and not check_hook,
                    "Add the `first-commit-check` hook to `.pre-commit-config.yaml`, "
                    f"then\ncheck this clone with `{check}`." in readme,
                )

    def test_transport_choice_reaches_the_generated_readme(self) -> None:
        ssh = _text("README.md", "core", SSH_SOURCE)
        https = _text("README.md", "core", HTTPS_SOURCE)
        self.assertIn("`" + SSH_SOURCE + PINNED, ssh)
        self.assertNotIn("`" + HTTPS_SOURCE + PINNED, ssh)
        self.assertEqual(1, ssh.count(f'"{HTTPS_SOURCE}"'))
        self.assertIn("`" + HTTPS_SOURCE + PINNED, https)
        self.assertNotIn("ssh://", https)
        self.assertNotIn(INSTEAD_OF, https)

    def test_full_set_moves_onboarding_to_contributing_with_a_readme_pointer(
        self,
    ) -> None:
        readme = _text("README.md", "full")
        contributing = _text("CONTRIBUTING.md", "full")
        self.assertIn("## Contributors\n", readme)
        self.assertIn("CONTRIBUTING.md", readme)
        self.assertNotIn(PINNED, readme)
        self.assertNotIn("```sh", readme)
        self.assertIn("## Repository hooks\n", contributing)
        self.assertIn("`" + SSH_SOURCE + PINNED, contributing)
        self.assertIsNone(COMMIT_SHA.search(contributing))
        self.assertIn(
            "pre-commit run first-commit-setup --hook-stage manual\n", contributing
        )
        self.assertIn("installs the Gitleaks scanner", " ".join(contributing.split()))
        self.assertIn("does not change files", contributing)
        self.assertIn("Python 3.11 to 3.14", contributing)
        self.assertIn("python3.13", contributing)
        self.assertIn("takes several minutes", contributing)
        self.assertIn(INSTEAD_OF, contributing)
        self.assertEqual(1, contributing.count("@no-commit"))
        self.assertEqual(
            [
                "## Setup",
                "## Repository hooks",
                "## Checks",
                "## Commit messages",
                "## Review",
            ],
            [line for line in contributing.splitlines() if line.startswith("## ")],
        )

    def test_starter_text_makes_no_access_or_install_claims(self) -> None:
        for docs in ("core", "full"):
            for source in (HTTPS_SOURCE, SSH_SOURCE):
                for name, content in _files(docs, source).items():
                    with self.subTest(docs=docs, source=source, name=name):
                        text = " ".join(content.decode("utf-8").split())
                        self.assertNotIn("private repository", text)
                        self.assertNotIn("installs first-commit", text)

    def test_generated_readme_stays_short(self) -> None:
        for docs in ("core", "full"):
            with self.subTest(docs=docs):
                words = len(_text("README.md", docs).split())
                self.assertLess(words, 230, words)

    def test_ignore_file_protects_local_state_secrets_keys_and_environments(
        self,
    ) -> None:
        lines = IGNORE_FILE.decode("utf-8").splitlines()
        for rule in (
            ".local/",
            ".env",
            ".env.*",
            "*.env",
            "*.env.*",
            "!.env.example",
            ".secrets/",
            ".ssh/",
            "id_rsa",
            "id_ed25519",
            "*.key",
            "*.pem",
            "*.p12",
            ".venv/",
            "venv/",
            "__pycache__/",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, lines)

    def test_proposal_preserves_original_and_marks_manual_merge(self) -> None:
        generated = _files("core")["README.md"]
        proposal = proposal_content("README.md", generated)
        self.assertEqual(
            "README.md.first-commit-proposal.md", proposal_name("README.md")
        )
        self.assertIn(b"Existing document", proposal)
        self.assertIn(b"README.md", proposal)
        self.assertIn(b"Generated suggestion", proposal)
        self.assertEqual(1, proposal.count(b"<!-- @no-commit -->"))
        self.assertIn(b"# Project name", proposal)
