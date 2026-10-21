DOCUMENT_NAMES = ("README.md", "AGENTS.md", "PRD.md", "CONTRIBUTING.md", "SECURITY.md")
HOOK_PROPOSAL = ".pre-commit-config.first-commit-proposal.yaml"


def proposal_name(name: str) -> str:
    return name + ".first-commit-proposal.md"
