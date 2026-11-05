import unittest
from pathlib import Path

from first_commit.checks.identity import ALLOWED_SIGNERS_PATH

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text("utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text("utf-8")
AGENTS = (ROOT / "AGENTS.md").read_text("utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


class ReadmeWordingTest(unittest.TestCase):
    def test_first_commit_says_to_replace_every_template_placeholder(self) -> None:
        start = _flat(README.split("Git opens the template", 1)[1].split("```", 1)[0])
        self.assertIn("Replace each `<...>` placeholder with your own text", start)
        self.assertNotIn("Keep", start)

    def test_identity_recovery_removes_the_old_self_trust(self) -> None:
        step = README.split("**Wrong identity or key.**", 1)[1].split("\n5. ", 1)[0]
        self.assertIn(f"rm -f {ALLOWED_SIGNERS_PATH}\n", step)
        self.assertIn("--trust-self", step)

    def test_public_documents_cite_no_unpublished_contract(self) -> None:
        for name, text in (
            ("README.md", README),
            ("CHANGELOG.md", CHANGELOG),
            ("AGENTS.md", AGENTS),
        ):
            with self.subTest(document=name):
                self.assertFalse("tool contract" in text.lower(), name)


if __name__ == "__main__":
    unittest.main()
