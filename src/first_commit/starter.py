from first_commit.generated_files import DOCUMENT_NAMES
from first_commit.hooks import HTTPS_REPOSITORY, SSH_REPOSITORY
from first_commit.machine_identity import (
    EMAIL_VARIABLE,
    KEY_VARIABLE,
    NAME_VARIABLE,
    PATH_VARIABLE,
)
from first_commit.setup_command import (
    CHECK_HOOK_COMMAND,
    CHECK_HOOK_ID,
    HOOK_CONFIG,
    SETUP_HOOK_COMMAND,
)

MARKER = "<!-- @no-commit -->\n"
NOTICE = "<!-- Generated starter text. Review it, then remove the marker. -->\n"

README_INTRODUCTION = (
    "# Project name\n\n"
    "State in one sentence what this project does and who it is for.\n\n"
    "## Prerequisites\n\n"
    "List the tools, versions, and access needed before the first run.\n\n"
    "## First run\n\n"
    "Give the commands that take a fresh checkout to a working state and the"
    " expected result.\n\n"
)
README_ROUTINE = (
    "## Routine use\n\n"
    "Give the everyday commands for checks, tests, and builds and what success"
    " looks like.\n\n"
    "## Stop and recover\n\n"
    "Explain how to stop running work and recover from common failures.\n"
)
CONTRIBUTING_SETUP = (
    "# Contributing\n\n"
    "## Setup\n\n"
    "Describe how to prepare a local development environment.\n\n"
)
CONTRIBUTING_REVIEW = (
    "## Checks\n\n"
    "List the commands that must pass before a change is reviewed.\n\n"
    "## Commit messages\n\n"
    "Describe the required format; start from the `.gitmessage` template.\n\n"
    "## Review\n\n"
    "Describe how changes are reviewed, approved, and released.\n"
)
ONBOARDING_POINTER = (
    "## Contributors\n\n"
    "Each clone is set up with pre-commit; see [CONTRIBUTING.md](CONTRIBUTING.md).\n\n"
)

DOCUMENTS = {
    "README.md": README_INTRODUCTION + README_ROUTINE,
    "AGENTS.md": (
        "# Agent rules\n\n"
        "## Context\n\n"
        "- Read `README.md` and the project's requirement, contribution, and design\n"
        "  documents before changing behavior or public interfaces.\n\n"
        "## Authority\n\n"
        "- Git configuration, hook or dependency installation, staging, commits,\n"
        "  remotes, publication, and external services require explicit\n"
        "  authorization.\n"
        "- Stage only approved paths; never use broad staging commands.\n"
        "- Preserve unrelated work.\n\n"
        "## Engineering\n\n"
        "- Use simple, neutral, technical English. Remove filler and repetition;\n"
        "  preserve requirements and security limits.\n"
        "- Use `README.md` as the novice entry point. Present purpose,\n"
        "  prerequisites, first-run and routine commands, expected results, and stop\n"
        "  or recovery steps in execution order.\n"
        "- Prefer the smallest complete design. Add complexity only for a\n"
        "  demonstrated need.\n"
        "- Make correct use easy and obvious. Use secure defaults, require opt-in for\n"
        "  risky behavior, and give precise recovery guidance.\n"
        "- Use red-green-refactor for behavior changes.\n"
        "- Never commit secrets, private keys, or personal data.\n\n"
        "## Verification\n\n"
        "- Run focused tests and the project's full check before you open a pull\n"
        "  request.\n"
        "- Report missing dependencies, residual risks, and checks that were not"
        " run.\n"
    ),
    "PRD.md": (
        "# Product requirements\n\n"
        "## Problem\n\n"
        "Describe the problem and who has it.\n\n"
        "## Users\n\n"
        "Name the primary users and what they need to accomplish.\n\n"
        "## Scope\n\n"
        "List what is in scope and what is explicitly out of scope.\n\n"
        "## Requirements\n\n"
        "List the observable behavior the project must provide.\n\n"
        "## Success criteria\n\n"
        "State how you will know the project works.\n"
    ),
    "CONTRIBUTING.md": CONTRIBUTING_SETUP + CONTRIBUTING_REVIEW,
    "SECURITY.md": (
        "# Security policy\n\n"
        "## Supported versions\n\n"
        "List the versions that receive security fixes.\n\n"
        "## Reporting a vulnerability\n\n"
        "Name the route for reporting vulnerabilities privately and ask reporters"
        " not to open public issues.\n\n"
        "## Exposed credentials\n\n"
        "Revoke an exposed credential at its issuer first; removing it from Git"
        " history does not make it safe.\n"
    ),
}

DOCUMENT_SETS = {
    "core": ("README.md", "AGENTS.md"),
    "full": DOCUMENT_NAMES,
}

STYLE_FILES = {
    ".editorconfig": (
        "root = true\n\n[*]\ncharset = utf-8\nend_of_line = lf\n"
        "insert_final_newline = true\ntrim_trailing_whitespace = true\n"
    ),
    ".gitattributes": "* text=auto eol=lf\n",
}

IGNORE_FILE = (
    b"# Private drafts and local working material\n"
    b".local/\n\n"
    b"# Operating-system and editor state\n"
    b".DS_Store\nThumbs.db\n*.swp\n*.swo\n.idea/\n.vscode/\n\n"
    b"# Local environments and secrets\n"
    b".env\n.env.*\n*.env\n*.env.*\n!.env.example\n!.env.schema\n!.env.template\n"
    b".venv/\nvenv/\n.secrets/\n\n"
    b"# Python output\n"
    b"__pycache__/\n*.py[cod]\n*.egg-info/\n.pytest_cache/\n.mypy_cache/\n"
    b".ruff_cache/\n.tox/\n.nox/\n\n"
    b"# Reports and build output\n"
    b"*.log\n.coverage\n.coverage.*\ncoverage.xml\nhtmlcov/\nreports/\n"
    b"test-results/\ndist/\nbuild/\n.cache/\ntmp/\n.tmp/\n\n"
    b"# Private key and certificate material\n"
    b".ssh/\nid_rsa\nid_dsa\nid_ecdsa\nid_ed25519\nid_ecdsa_sk\nid_ed25519_sk\n"
    b"*_auth_ed25519\n*_auth_ed25519.pub\n*_sign_ed25519\n*_sign_ed25519.pub\n"
    b"*.key\n*.pem\n*.p12\n*.pfx\n"
)


def _clone_setup_lines(*, setup_hook: bool) -> tuple[str, str]:
    if not setup_hook:
        return "", ""
    explanation = (
        "The second command sets this clone's Git identity and SSH signing and\n"
        "installs the Gitleaks scanner; it does not change files this project\n"
        "owns. The first run takes several minutes.\n\n"
        "Add your public identity once per machine. It is saved to\n"
        "`$XDG_CONFIG_HOME/first-commit/identity.json` (default\n"
        f"`~/.config/first-commit/identity.json`); `{PATH_VARIABLE}` chooses\n"
        "another file.\n\n"
        "```sh\n"
        f'{NAME_VARIABLE}="Your Name" {EMAIL_VARIABLE}="you@example.com" \\\n'
        f'  {KEY_VARIABLE}="~/.ssh/id_ed25519.pub" \\\n'
        f"  {SETUP_HOOK_COMMAND}\n"
        "```\n\n"
    )
    return f"{SETUP_HOOK_COMMAND}\n", explanation


# Names no commit: an upgrade changes the commit in the hook file only.
def _onboarding_section(
    heading: str,
    source: str,
    *,
    setup_hook: bool,
    check_hook: bool,
) -> str:
    command, explanation = _clone_setup_lines(setup_hook=setup_hook)
    section = (
        f"## {heading}\n\n"
        "Commits and pushes run pre-commit hooks.\n"
        f"They come from `{source}` at the commit `{HOOK_CONFIG}` pins.\n"
        "Install pre-commit on Python 3.11 to 3.14 with\n"
        "`pipx install --python python3.13 pre-commit` or `brew install pre-commit`,\n"
        "then in each clone run:\n\n"
        "```sh\n"
        "pre-commit install\n"
        f"{command}"
        "```\n\n"
        f"{explanation}"
    )
    if check_hook:
        section += f"Check this clone with `{CHECK_HOOK_COMMAND}`.\n\n"
    elif setup_hook:
        section += (
            f"Add the `{CHECK_HOOK_ID}` hook to `{HOOK_CONFIG}`, then\n"
            f"check this clone with `{CHECK_HOOK_COMMAND}`.\n\n"
        )
    if source == SSH_REPOSITORY:
        section += (
            "For HTTPS instead of SSH, map this address once:\n\n"
            "```sh\n"
            f'git config --global url."{HTTPS_REPOSITORY}".insteadOf'
            f' "{SSH_REPOSITORY}"\n'
            "```\n\n"
        )
    return section


def starter_files(
    docs: str = "core",
    *,
    source: str,
    setup_hook: bool,
    check_hook: bool,
) -> dict[str, bytes]:
    names = DOCUMENT_SETS[docs]
    hooks = {"setup_hook": setup_hook, "check_hook": check_hook}
    documents = dict(DOCUMENTS)
    if "CONTRIBUTING.md" in names:
        documents["README.md"] = (
            README_INTRODUCTION + ONBOARDING_POINTER + README_ROUTINE
        )
        documents["CONTRIBUTING.md"] = (
            CONTRIBUTING_SETUP
            + _onboarding_section("Repository hooks", source, **hooks)
            + CONTRIBUTING_REVIEW
        )
    else:
        documents["README.md"] = (
            README_INTRODUCTION
            + _onboarding_section("Contributors", source, **hooks)
            + README_ROUTINE
        )
    files = {name: content.encode("utf-8") for name, content in STYLE_FILES.items()}
    files.update(
        {name: (NOTICE + MARKER + documents[name]).encode("utf-8") for name in names}
    )
    return files


def proposal_content(name: str, generated: bytes) -> bytes:
    introduction = (
        "# first-commit document proposal\n\n"
        + NOTICE
        + MARKER
        + "## Existing document\n\n"
        + f"Keep `{name}` as the source of truth. It was not changed.\n\n"
        + "## Generated suggestion\n\n"
        + "Merge useful material into the existing document, then delete this proposal.\n\n"
    )
    return introduction.encode("utf-8") + generated.removeprefix(
        (NOTICE + MARKER).encode("utf-8")
    )
