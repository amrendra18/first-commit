import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from first_commit import validation
from first_commit.gitleaks import RULE_ID, STAGED_SCOPE_PATH, scan_staged, scan_stdin
from first_commit.gitleaks_blobs import (
    BATCH_PREFIX,
    DEFAULT_ALLOWLIST_PATHS,
    MESSAGE_PATH,
    hidden_staged_paths,
    scan_hidden_staged,
    scan_message,
)
from first_commit.gitleaks_ignore_format import IGNORE_PATH
from first_commit.gitleaks_scanner import Scanner, validate_scanner
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from tests.gitleaks_support import SCANNER_PATH, needs_real_scanner
from tests.support import initialize_repository, run_git

SLACK_TOKEN = "xoxb-" + "1234567890123-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"
SECRET_LINE = b'slack = "' + SLACK_TOKEN.encode("ascii") + b'"\n'
LIMITS = (100, 1024 * 1024)
REAL_SCANNER = shutil.which("gitleaks")
# Each file `gitleaks git --staged` skips, with its bytes and the secret's line.
HIDDEN_CASES = {
    "binary.dat": (b"\0header\n" + SECRET_LINE, 2),
    "nodiff.txt": (b"first\n" + SECRET_LINE, 2),
    "assets/icon.svg": (SECRET_LINE, 1),
    "poetry.lock": (b"a\nb\n" + SECRET_LINE, 3),
}
# First bytes that make `gitleaks stdin` treat its whole input as a non-text file.
SNIFFED_SIGNATURES = (
    b"%PDF-1.4",
    b"PK\x03\x04",
    b"\x7fELF",
    b"\x1f\x8b\x08\x00",
    b"!<arch>",
    b"{\\rtf1",
)

# Signatures that h2non/filetype (in Gitleaks 8.30.0) reads at a fixed offset past
# the first bytes, with that offset. A match makes `gitleaks stdin` scan nothing.
OFFSET_SIGNATURES = ((128, b"DICM"), (257, b"ustar\0"), (32769, b"CD001"))
# A batch prefix of this length lets an attacker who knows it put a signature at
# the offset the type check reads.
OLD_PREFIX_BYTES = 13


class GitleaksBlobsTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)

    def stage(self, files: dict[str, bytes]) -> None:
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        run_git(self.root, "add", "--", *files)

    def stage_hidden_cases(self) -> None:
        self.stage({".gitattributes": b"nodiff.txt -diff\n"})
        self.stage({name: content for name, (content, _) in HIDDEN_CASES.items()})

    def test_hidden_paths_are_binary_diff_attribute_and_allowlisted_files(self) -> None:
        self.stage_hidden_cases()
        self.stage({"plain.txt": SECRET_LINE, "marked.txt": b"text\n"})
        self.stage({".gitattributes": b"nodiff.txt -diff\nmarked.txt binary\n"})
        paths = (*HIDDEN_CASES, "plain.txt", "marked.txt", ".gitattributes")

        hidden = hidden_staged_paths(self.root, paths)

        self.assertEqual({*HIDDEN_CASES, "marked.txt"}, set(hidden))

    @needs_real_scanner
    def test_real_scanner_finds_each_slack_token_the_staged_scan_misses(self) -> None:
        self.stage_hidden_cases()

        missed = scan_staged(self.root, max_findings=10)
        found = scan_hidden_staged(
            self.root, tuple(HIDDEN_CASES), LIMITS, max_findings=10
        )

        self.assertEqual((), missed)
        self.assertEqual(
            sorted((name, line) for name, (_, line) in HIDDEN_CASES.items()),
            [(item.path, item.line) for item in found],
        )
        self.assertEqual({RULE_ID}, {item.rule_id for item in found})
        self.assertNotIn(SLACK_TOKEN, repr(found))

    @needs_real_scanner
    def test_batches_split_by_size_and_keep_each_path_and_line(self) -> None:
        self.stage_hidden_cases()
        # Room for two of the 68 to 76 byte blobs: 2 batches of 2 blobs each.
        with (
            mock.patch(
                "first_commit.gitleaks_blobs.BATCH_BYTES", len(BATCH_PREFIX) + 150
            ),
            mock.patch(
                "first_commit.gitleaks_blobs.scan_stdin", wraps=scan_stdin
            ) as scans,
        ):
            found = scan_hidden_staged(
                self.root, tuple(HIDDEN_CASES), LIMITS, max_findings=10
            )

        self.assertEqual(
            [2, 2],
            [call.args[2].count(SECRET_LINE) for call in scans.call_args_list],
        )
        self.assertEqual(
            sorted((name, line) for name, (_, line) in HIDDEN_CASES.items()),
            [(item.path, item.line) for item in found],
        )

    @needs_real_scanner
    def test_a_blob_without_a_final_newline_does_not_shift_the_next_one(self) -> None:
        self.stage({"a.bin": b"\0no newline", "b.bin": b"\0x\n" + SECRET_LINE})

        found = scan_hidden_staged(
            self.root, ("a.bin", "b.bin"), LIMITS, max_findings=10
        )

        self.assertEqual([("b.bin", 2)], [(item.path, item.line) for item in found])

    @needs_real_scanner
    def test_a_pdf_blob_first_does_not_hide_a_token_in_a_later_blob(self) -> None:
        self.stage(
            {
                "a.pdf": b"%PDF-1.4\n%fake\n",
                "data.bin": b"x\0y\n" + SECRET_LINE,
                "poetry.lock": SECRET_LINE,
            }
        )

        found = scan_hidden_staged(
            self.root, ("a.pdf", "data.bin", "poetry.lock"), LIMITS, max_findings=10
        )

        self.assertEqual(
            [("data.bin", 2), ("poetry.lock", 1)],
            [(item.path, item.line) for item in found],
        )

    @needs_real_scanner
    def test_a_token_inside_a_pdf_is_found(self) -> None:
        self.stage({"report.pdf": b"%PDF-1.4\n" + SECRET_LINE})

        found = scan_hidden_staged(self.root, ("report.pdf",), LIMITS, max_findings=10)

        self.assertEqual(
            [("report.pdf", 2)], [(item.path, item.line) for item in found]
        )

    @needs_real_scanner
    def test_without_the_batch_prefix_gitleaks_misses_a_token_in_a_pdf(self) -> None:
        pdf = b"%PDF-1.4\n" + SECRET_LINE
        scanner = Scanner("gitleaks", None)

        missed = scan_stdin(self.root, scanner, pdf)
        found = scan_stdin(self.root, scanner, BATCH_PREFIX + pdf)

        self.assertEqual((), missed)
        self.assertEqual(["slack-bot-token"], [entry.rule for entry in found])

    @needs_real_scanner
    def test_no_sniffed_first_blob_hides_a_later_token(self) -> None:
        self.stage({"poetry.lock": SECRET_LINE})
        for signature in SNIFFED_SIGNATURES:
            with self.subTest(signature=signature):
                self.stage({"a.bin": signature + b"\n"})

                found = scan_hidden_staged(
                    self.root, ("a.bin", "poetry.lock"), LIMITS, max_findings=10
                )

                self.assertEqual(
                    [("poetry.lock", 1)], [(item.path, item.line) for item in found]
                )

    @needs_real_scanner
    def test_a_signature_in_a_blob_hides_no_token(self) -> None:
        # Each first line puts a signature where the type check reads it after a
        # prefix of OLD_PREFIX_BYTES.
        first_lines = {
            signature: b"\0" + b"x" * (offset - OLD_PREFIX_BYTES - 1) + signature
            for offset, signature in OFFSET_SIGNATURES
        }
        # A signature at blob offset 0: the first blob starts with %PDF.
        first_lines[b"%PDF"] = b"%PDF-1.4\0"
        for signature, first_line in first_lines.items():
            with self.subTest(signature=signature):
                self.stage({"crafted.bin": first_line + b"\n" + SECRET_LINE})

                found = scan_hidden_staged(
                    self.root, ("crafted.bin",), LIMITS, max_findings=10
                )

                self.assertEqual(
                    [("crafted.bin", 2)],
                    [(item.path, item.line) for item in found],
                )

    @needs_real_scanner
    def test_reviewed_exception_applies_to_its_path_rule_and_line(self) -> None:
        content = HIDDEN_CASES["assets/icon.svg"][0]
        digest = hashlib.sha256(content).hexdigest()
        self.stage({"assets/icon.svg": content, "poetry.lock": content})
        self.stage(
            {
                ".gitleaksignore": (
                    "# reason: Synthetic token in a test fixture.\n"
                    f"# file-sha256: {digest}\n"
                    "assets/icon.svg:slack-bot-token:1\n"
                ).encode()
            }
        )

        found = scan_hidden_staged(
            self.root, ("assets/icon.svg", "poetry.lock"), LIMITS, max_findings=10
        )

        self.assertEqual(
            [("poetry.lock", 1)], [(item.path, item.line) for item in found]
        )

    def test_blobs_over_the_byte_limit_are_not_read(self) -> None:
        self.stage({"large.bin": b"\0" + b"x" * 64 + b"\n" + SECRET_LINE})
        with mock.patch("first_commit.gitleaks_blobs.scan_stdin") as scanner:
            found = scan_hidden_staged(
                self.root, ("large.bin",), (100, 32), max_findings=10
            )

        self.assertEqual((), found)
        scanner.assert_not_called()

    def test_text_only_and_empty_selections_run_no_scanner(self) -> None:
        self.stage({"plain.txt": SECRET_LINE})
        with mock.patch("first_commit.gitleaks_blobs.scan_stdin") as scanner:
            self.assertEqual(
                (),
                scan_hidden_staged(self.root, ("plain.txt",), LIMITS, max_findings=1),
            )
            self.assertEqual(
                (), scan_hidden_staged(self.root, (), LIMITS, max_findings=1)
            )
            self.assertEqual(
                (),
                scan_hidden_staged(self.root, ("plain.txt",), LIMITS, max_findings=0),
            )
        scanner.assert_not_called()

    def test_unusable_scanner_report_fails_for_the_whole_staged_content(self) -> None:
        self.stage({"binary.dat": HIDDEN_CASES["binary.dat"][0]})
        fake = self.root.parent / f"{self.root.name}-gitleaks"
        fake.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
            "exit 10\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        self.addCleanup(fake.unlink)

        found = scan_hidden_staged(
            self.root,
            ("binary.dat",),
            LIMITS,
            max_findings=10,
            scanner=Scanner(str(fake), {"PATH": SCANNER_PATH}),
        )

        self.assertEqual([(STAGED_SCOPE_PATH, None)], [(f.path, f.line) for f in found])

    @needs_real_scanner
    def test_real_scanner_finds_a_token_in_a_commit_message(self) -> None:
        content = b"feat: add\n\nTest Plan:\n- " + SECRET_LINE

        found = scan_message(self.root, content, max_findings=10)

        self.assertEqual(
            [(RULE_ID, MESSAGE_PATH, 4)],
            [(item.rule_id, item.path, item.line) for item in found],
        )
        self.assertNotIn(SLACK_TOKEN, repr(found))

    @needs_real_scanner
    def test_an_ignore_file_in_the_repository_does_not_hide_a_message_secret(
        self,
    ) -> None:
        content = b"feat: add\n\n" + SECRET_LINE
        # Line 5 of the scanned batch: the batch prefix comes before the message.
        (self.root / IGNORE_PATH).write_text(":slack-bot-token:5\n", encoding="utf-8")

        found = scan_message(self.root, content, max_findings=10)

        self.assertEqual([(MESSAGE_PATH, 3)], [(f.path, f.line) for f in found])

    @needs_real_scanner
    def test_an_ignore_file_in_the_repository_cannot_fail_the_capability_check(
        self,
    ) -> None:
        (self.root / IGNORE_PATH).write_text(":github-pat:1\n", encoding="utf-8")

        with mock.patch("first_commit.gitleaks_scanner._VALIDATED", set()):
            validate_scanner(self.root)

    def test_stdin_scans_and_scanner_checks_run_outside_the_repository(self) -> None:
        folders = self.root.parent / f"{self.root.name}-folders"
        fake = self.root.parent / f"{self.root.name}-gitleaks"
        fake.write_text(
            "#!/bin/sh\n"
            f"pwd -P >> '{folders}'\n"
            "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
            "exit 10\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        self.addCleanup(fake.unlink)
        self.addCleanup(folders.unlink, missing_ok=True)

        with mock.patch("first_commit.gitleaks_scanner._VALIDATED", set()):
            scan_message(
                self.root,
                b"feat: add\n",
                max_findings=10,
                scanner=Scanner(str(fake), {"PATH": SCANNER_PATH}),
            )

        ran_in = folders.read_text("utf-8").splitlines()
        self.assertEqual(3, len(ran_in))
        self.assertNotIn(str(self.root.resolve()), ran_in)

    def test_unusable_message_report_fails_for_the_whole_message(self) -> None:
        fake = self.root.parent / f"{self.root.name}-gitleaks"
        fake.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
            "exit 10\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        self.addCleanup(fake.unlink)
        scanner = Scanner(str(fake), {"PATH": SCANNER_PATH})

        found = scan_message(
            self.root, b"feat: add\n", max_findings=10, scanner=scanner
        )

        self.assertEqual([(MESSAGE_PATH, None)], [(f.path, f.line) for f in found])
        with mock.patch("first_commit.gitleaks_blobs.scan_stdin") as scans:
            self.assertEqual((), scan_message(self.root, b"", max_findings=10))
            self.assertEqual((), scan_message(self.root, b"x\n", max_findings=0))
        scans.assert_not_called()

    @needs_real_scanner
    def test_staged_validation_reports_a_secret_in_a_binary_blob(self) -> None:
        for path in REQUIRED_DOCUMENTS:
            (self.root / path).write_text("# Reviewed\n", encoding="utf-8")
        self.stage({"binary.dat": HIDDEN_CASES["binary.dat"][0]})
        run_git(self.root, "add", "--", *REQUIRED_DOCUMENTS)
        policy = parse_policy(b'{"schema_version":1}', self.root)

        result = validation.staged(self.root, policy)

        self.assertIn(
            (RULE_ID, "binary.dat", 2),
            {(item.rule_id, item.path, item.line) for item in result.findings},
        )

    @needs_real_scanner
    def test_allowlist_matches_the_pinned_scanner_default_configuration(self) -> None:
        binary = Path(str(REAL_SCANNER)).read_bytes()
        start = binary.index(b'description = "global allow lists"\npaths = [')
        section = binary[start : binary.index(b"regexes = [", start)]

        embedded = tuple(
            item.decode("utf-8") for item in re.findall(rb"'''(.*?)'''", section)
        )

        self.assertEqual(DEFAULT_ALLOWLIST_PATHS, embedded)


if __name__ == "__main__":
    unittest.main()
