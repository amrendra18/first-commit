import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.policy import parse_policy
from tests.support import initialize_repository, run_git


class RequiredDocumentSizeTest(unittest.TestCase):
    def test_an_oversized_required_document_is_too_large_not_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "README.md").write_text("# Title\n" + "x" * 192 + "\n", "utf-8")
            (root / "AGENTS.md").write_text("# Reviewed\n", "utf-8")
            run_git(root, "add", "--", "README.md", "AGENTS.md")
            policy = replace(
                parse_policy(b'{"schema_version":1}', root), max_file_bytes=100
            )

            with patch("first_commit.validation.scan_staged", return_value=()):
                result = validation.staged(root, policy, ())

        found = {(item.rule_id, item.path) for item in result.findings}
        self.assertIn(("files.too-large", "README.md"), found)
        self.assertNotIn(("documents.required", "README.md"), found)


if __name__ == "__main__":
    unittest.main()
