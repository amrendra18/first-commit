import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.candidates import CandidateError, filtered_staged_paths
from first_commit.finding_collector import TOO_LARGE_RULE
from first_commit.gitleaks import RULE_ID
from first_commit.gitleaks_ignore import check_ignore_file
from first_commit.gitleaks_ignore_format import IGNORE_PATH, IgnoreFileError
from first_commit.models import Severity
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from first_commit.validation import FILTERED_UNREADABLE_RULE
from tests.gitleaks_support import SLACK_LINE, commit_fixture, needs_real_scanner
from tests.support import initialize_repository, run_git

PRIVATE_VALUE = "alicecanary"
# The clean filter stores one fixed line per line, as Git LFS stores a pointer.
POINTER = b"version https://git-lfs.github.com/spec/v1\n"


class CleanFilterTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)
        # Each line becomes the first line of a Git LFS pointer, as git-lfs writes.
        run_git(
            self.root,
            "config",
            "filter.lfs.clean",
            "sed 's,.*,version https://git-lfs.github.com/spec/v1,'",
        )
        for path in REQUIRED_DOCUMENTS:
            (self.root / path).write_text("# Reviewed\n", encoding="utf-8")
        (self.root / ".gitattributes").write_text(
            "*.dat filter=lfs\n*.raw filter=unset-driver\n", encoding="utf-8"
        )
        run_git(self.root, "add", "--", ".gitattributes", *REQUIRED_DOCUMENTS)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)

    def stage(self, path: str, content: bytes) -> None:
        (self.root / path).write_bytes(content)
        run_git(self.root, "add", "--", path)

    def staged_rules(
        self, private_values: tuple[str, ...] = ()
    ) -> set[tuple[str, str]]:
        with (
            patch("first_commit.validation.scan_staged", return_value=()),
            patch("first_commit.validation.scan_hidden_staged", return_value=()),
        ):
            result = validation.staged(self.root, self.policy, private_values)
        return {(item.rule_id, item.path) for item in result.findings}

    def index_bytes(self, path: str) -> bytes:
        return run_git(self.root, "cat-file", "blob", f":{path}").stdout

    @needs_real_scanner
    def test_a_secret_in_a_filtered_file_is_reported(self) -> None:
        self.stage("data.dat", b"first\n" + SLACK_LINE.encode("ascii"))
        self.assertEqual(POINTER * 2, self.index_bytes("data.dat"))

        result = validation.staged(self.root, self.policy)

        self.assertIn(
            (RULE_ID, "data.dat", 2),
            {(item.rule_id, item.path, item.line) for item in result.findings},
        )
        self.assertNotIn("xoxb-", repr(result))

    def test_a_private_value_in_a_filtered_file_is_reported(self) -> None:
        self.stage("data.dat", f"Written by {PRIVATE_VALUE}.\n".encode())
        self.assertEqual(POINTER, self.index_bytes("data.dat"))

        rules = self.staged_rules((PRIVATE_VALUE,))

        self.assertIn(("privacy.private-literal", "data.dat"), rules)

    def test_a_file_without_a_filter_is_read_from_the_index(self) -> None:
        line = f"Written by {PRIVATE_VALUE}.\n".encode()
        self.stage("notes.txt", line)
        self.stage("other.raw", line)
        self.stage("data.dat", b"public\n")
        for path in ("notes.txt", "other.raw"):
            (self.root / path).write_bytes(b"public\n")

        paths = ("data.dat", "notes.txt", "other.raw")
        self.assertEqual(("data.dat",), filtered_staged_paths(self.root, paths))
        rules = self.staged_rules((PRIVATE_VALUE,))

        self.assertIn(("privacy.private-literal", "notes.txt"), rules)
        self.assertIn(("privacy.private-literal", "other.raw"), rules)
        self.assertNotIn(("privacy.private-literal", "data.dat"), rules)

    def test_a_filter_named_only_in_the_working_copy_attributes_counts(self) -> None:
        (self.root / ".gitattributes").write_text(
            "*.csv filter=lfs\n", encoding="utf-8"
        )
        self.stage("table.csv", f"{PRIVATE_VALUE}\n".encode())
        self.assertEqual(POINTER, self.index_bytes("table.csv"))

        self.assertIn(
            ("privacy.private-literal", "table.csv"),
            self.staged_rules((PRIVATE_VALUE,)),
        )

    def test_a_process_driver_counts_and_a_link_is_never_filtered(self) -> None:
        self.stage("data.dat", b"public\n")
        (self.root / "link.dat").symlink_to("README.md")
        run_git(self.root, "add", "--", "link.dat")
        run_git(self.root, "config", "--unset", "filter.lfs.clean")
        run_git(self.root, "config", "filter.lfs.process", "unused-program")

        self.assertEqual(
            ("data.dat",), filtered_staged_paths(self.root, ("data.dat", "link.dat"))
        )

    def test_a_missing_or_irregular_working_copy_is_reported(self) -> None:
        self.stage("gone.dat", b"public\n")
        self.stage("folder.dat", b"public\n")
        (self.root / "gone.dat").unlink()
        (self.root / "folder.dat").unlink()
        (self.root / "folder.dat").mkdir()

        rules = self.staged_rules()

        self.assertIn((FILTERED_UNREADABLE_RULE, "gone.dat"), rules)
        self.assertIn((FILTERED_UNREADABLE_RULE, "folder.dat"), rules)

    def test_an_unreadable_working_copy_stops_with_its_path(self) -> None:
        self.stage("data.dat", b"public\n")
        (self.root / "data.dat").chmod(0)
        self.addCleanup((self.root / "data.dat").chmod, 0o600)

        with self.assertRaisesRegex(CandidateError, '(?s)"data.dat": .*chmod u\\+r'):
            self.staged_rules()

    def test_an_oversized_working_copy_warns_and_does_not_block(self) -> None:
        # A large Git LFS file is common; before the working copy was read, the
        # hook passed its small pointer, so a large copy warns and blocks nothing.
        # The pointer line (44 bytes) fits the limit; the working copy does not.
        self.stage("data.dat", b"x" * 64 + b"\n")
        self.policy = replace(self.policy, max_file_bytes=50)

        rules = self.staged_rules()

        self.assertIn(("files.filtered-too-large", "data.dat"), rules)
        self.assertNotIn((TOO_LARGE_RULE, "data.dat"), rules)
        with (
            patch("first_commit.validation.scan_staged", return_value=()),
            patch("first_commit.validation.scan_hidden_staged", return_value=()),
        ):
            result = validation.staged(self.root, self.policy, ())
        (large,) = [f for f in result.findings if f.path == "data.dat"]
        self.assertEqual(Severity.WARNING, large.severity)

    def test_a_staged_exception_is_checked_against_the_working_copy(self) -> None:
        # The index holds one pointer line; the exception names line 3 of the real
        # file and its digest, which the staged check reads.
        content = b"one\ntwo\nthree\n"
        self.stage("data.dat", content)
        digest = hashlib.sha256(content).hexdigest()
        (self.root / IGNORE_PATH).write_text(
            f"# reason: Synthetic fixture.\n# file-sha256: {digest}\n"
            "data.dat:generic-api-key:3\n",
            encoding="utf-8",
        )
        run_git(self.root, "add", "--", IGNORE_PATH)

        self.assertEqual(1, len(check_ignore_file(self.root)))

    def test_a_filter_other_than_lfs_keeps_the_index_copy(self) -> None:
        # An encrypting filter, such as git-crypt, stores a secret only encrypted,
        # so its working copy is not read.
        run_git(self.root, "config", "filter.crypt.clean", "sed s/.*/encrypted/")
        (self.root / ".gitattributes").write_text("*.enc filter=crypt\n", "utf-8")
        run_git(self.root, "add", "--", ".gitattributes")
        self.stage("secret.enc", f"{PRIVATE_VALUE}\n".encode())

        self.assertEqual((), filtered_staged_paths(self.root, ["secret.enc"]))
        self.assertNotIn(
            ("privacy.private-literal", "secret.enc"),
            self.staged_rules((PRIVATE_VALUE,)),
        )

    def lfs_exception(self, content: bytes, line: int) -> None:
        digest = hashlib.sha256(content).hexdigest()
        (self.root / IGNORE_PATH).write_text(
            f"# reason: Synthetic fixture.\n# file-sha256: {digest}\n"
            f"data.dat:generic-api-key:{line}\n",
            encoding="utf-8",
        )

    def test_a_stale_lfs_exception_names_the_working_copy_digest(self) -> None:
        self.stage("data.dat", b"one\ntwo\nthree\n")
        self.lfs_exception(b"old content\n", 1)
        run_git(self.root, "add", "--", IGNORE_PATH)

        with self.assertRaises(IgnoreFileError) as refused:
            check_ignore_file(self.root)

        self.assertIn("shasum -a 256 ./data.dat", str(refused.exception))
        self.assertNotIn("git show", str(refused.exception))

    def test_history_scans_never_check_an_lfs_exception_against_the_pointer(
        self,
    ) -> None:
        # Line 1 is inside the one-line pointer, so a pointer check would compare
        # its digest with the real file's and refuse the exception.
        content = b"one\ntwo\nthree\n"
        self.stage("data.dat", content)
        self.lfs_exception(content, 1)
        commit_fixture(self.root, "data.dat", IGNORE_PATH)

        found = check_ignore_file(self.root, ("--all",))

        self.assertEqual(1, len(found))

    def test_real_bytes_stay_checked_where_lfs_is_named_only_later(self) -> None:
        # A commit stored config.txt's real bytes; an unstaged attributes line now
        # names lfs for it. The staged copy matches the exception, the committed
        # one does not, and its real bytes are still checked.
        new = b"new\n"
        (self.root / "config.txt").write_bytes(b"old\n")
        (self.root / IGNORE_PATH).write_text(
            f"# reason: Synthetic fixture.\n"
            f"# file-sha256: {hashlib.sha256(new).hexdigest()}\n"
            "config.txt:generic-api-key:1\n",
            encoding="utf-8",
        )
        commit_fixture(self.root, "config.txt", IGNORE_PATH)
        self.stage("config.txt", new)
        with (self.root / ".gitattributes").open("a", encoding="utf-8") as file:
            file.write("*.txt filter=lfs\n")

        check_ignore_file(self.root)
        with self.assertRaisesRegex(IgnoreFileError, "does not match its file-sha256"):
            check_ignore_file(self.root, ("--all",))


if __name__ == "__main__":
    unittest.main()
