import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.checks.templates import (
    MAX_TEMPLATE_BYTES,
    read_template,
    template_findings,
)
from first_commit.paths import PathError
from tests.support import initialize_repository, run_git


class TemplateTest(unittest.TestCase):
    def test_missing_valid_and_unusable_templates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            self.assertEqual("template.missing", template_findings(root)[0].rule_id)
            template = root / ".gitmessage"
            template.write_text("Custom template\n", encoding="utf-8")
            run_git(root, "config", "--local", "commit.template", ".gitmessage")
            self.assertEqual([], template_findings(root))
            self.assertEqual(template.read_bytes(), read_template(root, str(template)))
            for raw in (
                b"",
                b" \n",
                b"\xff",
                b"message\0",
                b"x" * (MAX_TEMPLATE_BYTES + 1),
            ):
                template.write_bytes(raw)
                self.assertEqual(
                    "template.unusable", template_findings(root)[0].rule_id
                )
            for value in (
                "",
                "~/private-canary",
                "../private-canary",
                "private-canary\0",
            ):
                with self.subTest(value=value), self.assertRaises(PathError):
                    read_template(root, value)
            template.unlink()
            template.symlink_to(root / "target")
            self.assertEqual("template.unusable", template_findings(root)[0].rule_id)
            template.unlink()
            os.mkfifo(template)
            self.assertEqual("template.unusable", template_findings(root)[0].rule_id)
            with patch(
                "first_commit.checks.templates.effective_git_settings",
                return_value={"commit.template": "../private-canary"},
            ):
                self.assertNotIn("private-canary", str(template_findings(root)))


if __name__ == "__main__":
    unittest.main()
