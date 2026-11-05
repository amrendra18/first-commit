import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from first_commit import cli
from first_commit.contributor import ContributorError, parse_contributor
from first_commit.hooks import MALFORMED, load_hook_config
from first_commit.machine_identity import load_identity
from first_commit.models import SetupError
from first_commit.policy import parse_policy
from first_commit.policy_fields import PolicyError
from tests.cli_support import CliFixture

HUGE_NUMBER = "9" * 5000
IMPOSSIBLE_DATE = "2001-02-30"
RECORD = (
    '{"schema_version":1,"name":"N","email":"n@example.com","signing_key":"k.pub",'
    f'"extra":{HUGE_NUMBER}}}'
).encode()


class ParserValueErrorTest(unittest.TestCase):
    def test_a_huge_number_in_the_policy_is_a_policy_error(self) -> None:
        raw = f'{{"schema_version":1,"x":{HUGE_NUMBER}}}'.encode()
        with self.assertRaisesRegex(PolicyError, "not valid UTF-8 JSON"):
            parse_policy(raw, Path())

    def test_duplicate_policy_fields_keep_their_own_message(self) -> None:
        with self.assertRaisesRegex(PolicyError, "duplicate fields"):
            parse_policy(b'{"schema_version":1,"schema_version":1}', Path())

    def test_a_huge_number_in_the_contributor_record_is_a_contributor_error(
        self,
    ) -> None:
        with self.assertRaisesRegex(ContributorError, "not valid UTF-8 JSON"):
            parse_contributor(RECORD)
        duplicate = b'{"name":"N","name":"N"}'
        with self.assertRaisesRegex(ContributorError, "duplicate fields"):
            parse_contributor(duplicate)

    def test_a_huge_number_in_the_identity_file_is_a_contributor_error(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "identity.json"
            path.write_bytes(RECORD)
            with self.assertRaisesRegex(ContributorError, "not valid UTF-8 JSON"):
                load_identity(path)

    def test_a_huge_number_or_impossible_date_in_the_hook_file_is_malformed(
        self,
    ) -> None:
        for value in (HUGE_NUMBER, IMPOSSIBLE_DATE):
            with (
                self.subTest(value=value[:10]),
                self.assertRaisesRegex(SetupError, MALFORMED),
            ):
                load_hook_config(f"repos: []\nx: {value}\n".encode())
        with self.assertRaisesRegex(SetupError, "duplicate fields"):
            load_hook_config(b"repos: []\nrepos: []\n")


class ParserValueErrorCliTest(CliFixture):
    def error_object(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = cli.main((*arguments, "--format", "json", "--root", str(self.root)))
        self.assertNotIn("Traceback", output.getvalue() + error.getvalue())
        value = json.loads(output.getvalue())
        self.assertEqual(["error"], list(value))
        return code, value["error"]

    def test_a_huge_number_in_the_policy_gives_the_policy_invalid_object(
        self,
    ) -> None:
        (self.root / ".repo-policy.json").write_text(
            f'{{"schema_version":1,"x":{HUGE_NUMBER}}}\n', encoding="utf-8"
        )
        code, value = self.error_object("check")
        self.assertEqual((2, "policy-invalid"), (code, value["code"]))

    def test_an_impossible_date_in_the_hook_file_gives_an_error_object(self) -> None:
        (self.root / ".pre-commit-config.yaml").write_text(
            f"repos: []\nx: {IMPOSSIBLE_DATE}\n", encoding="utf-8"
        )
        code, value = self.error_object("setup", "--dry-run", "--revision", "1" * 40)
        self.assertEqual((2, "setup-input"), (code, value["code"]))
        self.assertIn(MALFORMED, str(value["message"]))


if __name__ == "__main__":
    unittest.main()
