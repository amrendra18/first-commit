import fcntl
import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.gitleaks_scanner import DependencyError, ScannerTimeoutError
from first_commit.scanner_install import (
    _archive,
    _binary,
    _download,
    install_scanner,
    local_scanner_failed,
)
from first_commit.setup_command import TOOL_SETUP_COMMAND

REPOSITORY = Path("/repository")


def archive_with_binary(content: bytes, name: str = "gitleaks") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        member = tarfile.TarInfo(name)
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


class ScannerInstallTest(unittest.TestCase):
    def test_platform_selection_uses_only_pinned_archives(self) -> None:
        for system, machine, suffix in (
            ("Darwin", "arm64", "darwin_arm64"),
            ("Darwin", "x86_64", "darwin_x64"),
            ("Linux", "aarch64", "linux_arm64"),
            ("Linux", "AMD64", "linux_x64"),
        ):
            with (
                self.subTest(system=system, machine=machine),
                patch(
                    "first_commit.gitleaks_scanner.platform.system", return_value=system
                ),
                patch(
                    "first_commit.gitleaks_scanner.platform.machine",
                    return_value=machine,
                ),
            ):
                url, digest = _archive()
                self.assertIn(suffix, url)
                self.assertEqual(64, len(digest))
        with patch(
            "first_commit.gitleaks_scanner.platform.system", return_value="Windows"
        ):
            with self.assertRaisesRegex(DependencyError, "support"):
                _archive()

    def test_download_is_bounded_and_failure_is_redacted(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return None

            def read(self, _limit):
                return b"oversized-private-canary"

        with (
            patch("first_commit.scanner_install.MAX_ARCHIVE_BYTES", 4),
            patch("first_commit.scanner_install.find_executable", return_value=None),
            patch(
                "first_commit.scanner_install.urllib.request.urlopen",
                return_value=Response(),
            ),
        ):
            with self.assertRaises(DependencyError) as error:
                _download("https://example.com/fixture", REPOSITORY)
        self.assertNotIn("private-canary", str(error.exception))
        with (
            patch("first_commit.scanner_install.find_executable", return_value=None),
            patch(
                "first_commit.scanner_install.urllib.request.urlopen",
                return_value=Response(),
            ),
        ):
            self.assertEqual(
                b"oversized-private-canary",
                _download("https://example.com/fixture", REPOSITORY),
            )
        with (
            patch(
                "first_commit.scanner_install.urllib.request.urlopen",
                side_effect=OSError("private-canary"),
            ),
            patch("first_commit.scanner_install.find_executable", return_value=None),
        ):
            with self.assertRaises(DependencyError) as error:
                _download("https://example.com/fixture", REPOSITORY)
        self.assertNotIn("private-canary", str(error.exception))
        self.assertIn("GitHub Releases", str(error.exception))
        self.assertIn("trusted", str(error.exception))
        self.assertIn("8.30.0", str(error.exception))

    def test_download_prefers_bounded_curl(self) -> None:
        archive = b"synthetic archive"

        def curl(arguments, **options):
            target = Path(arguments[arguments.index("--output") + 1])
            target.write_bytes(archive)
            self.assertEqual(subprocess.DEVNULL, options["stdin"])
            self.assertEqual(subprocess.DEVNULL, options["stdout"])
            self.assertEqual(subprocess.DEVNULL, options["stderr"])
            self.assertFalse(options["check"])
            self.assertIn("--disable", arguments)
            self.assertIn("--max-filesize", arguments)
            self.assertIn(str(24 * 1024 * 1024), arguments)
            self.assertIn("=https", arguments)
            return subprocess.CompletedProcess(arguments, 0)

        with (
            patch(
                "first_commit.scanner_install.urllib.request.urlopen",
                side_effect=AssertionError("Python transport should not run"),
            ) as urlopen,
            patch(
                "first_commit.scanner_install.find_executable",
                return_value="/usr/bin/curl",
            ),
            patch(
                "first_commit.scanner_install.subprocess.run", side_effect=curl
            ) as run,
        ):
            self.assertEqual(
                archive, _download("https://example.com/fixture", REPOSITORY)
            )
        urlopen.assert_not_called()
        run.assert_called_once()

    def test_python_download_retry_can_recover_without_curl(self) -> None:
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_arguments):
                return None

            def read(self, _limit):
                return b"synthetic archive"

        with (
            patch(
                "first_commit.scanner_install.urllib.request.urlopen",
                side_effect=(TimeoutError(), Response()),
            ) as urlopen,
            patch("first_commit.scanner_install.find_executable", return_value=None),
        ):
            self.assertEqual(
                b"synthetic archive",
                _download("https://example.com/fixture", REPOSITORY),
            )
        self.assertEqual(2, urlopen.call_count)

    def test_curl_failure_and_oversize_are_redacted(self) -> None:
        def oversized(arguments, **_options):
            target = Path(arguments[arguments.index("--output") + 1])
            target.write_bytes(b"private-canary")
            return subprocess.CompletedProcess(arguments, 0)

        with (
            patch("first_commit.scanner_install.MAX_ARCHIVE_BYTES", 4),
            patch(
                "first_commit.scanner_install.urllib.request.urlopen",
                side_effect=OSError("private-canary"),
            ),
            patch(
                "first_commit.scanner_install.find_executable",
                return_value="/usr/bin/curl",
            ),
            patch(
                "first_commit.scanner_install.subprocess.run",
                side_effect=oversized,
            ),
        ):
            with self.assertRaises(DependencyError) as error:
                _download("https://example.com/fixture", REPOSITORY)
        self.assertIn("size limit", str(error.exception))
        self.assertNotIn("private-canary", str(error.exception))

        with (
            patch(
                "first_commit.scanner_install.urllib.request.urlopen",
                side_effect=OSError("private-canary"),
            ),
            patch(
                "first_commit.scanner_install.find_executable",
                return_value="/usr/bin/curl",
            ),
            patch(
                "first_commit.scanner_install.subprocess.run",
                return_value=subprocess.CompletedProcess([], 22),
            ),
        ):
            with self.assertRaises(DependencyError) as error:
                _download("https://example.com/private-canary", REPOSITORY)
        self.assertNotIn("private-canary", str(error.exception))

    def test_curl_handles_missing_output_and_process_errors(self) -> None:
        failures = (
            subprocess.CompletedProcess[bytes]([], 0),
            OSError("private-canary"),
            subprocess.TimeoutExpired(("curl",), 1, stderr="private-canary"),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                patch(
                    "first_commit.scanner_install.urllib.request.urlopen",
                    side_effect=OSError("private-canary"),
                ),
                patch(
                    "first_commit.scanner_install.find_executable",
                    return_value="/usr/bin/curl",
                ),
                patch(
                    "first_commit.scanner_install.subprocess.run",
                    side_effect=failure if isinstance(failure, Exception) else None,
                    return_value=failure
                    if isinstance(failure, subprocess.CompletedProcess)
                    else None,
                ),
            ):
                with self.assertRaises(DependencyError) as error:
                    _download("https://example.com/private-canary", REPOSITORY)
            self.assertNotIn("private-canary", str(error.exception))

    def test_rejects_malformed_and_nonregular_archives(self) -> None:
        with self.assertRaisesRegex(DependencyError, "invalid"):
            _binary(b"not-a-tar")
        with self.assertRaisesRegex(DependencyError, "regular binary"):
            _binary(archive_with_binary(b"x", "not-gitleaks"))
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for number in range(33):
                archive.addfile(tarfile.TarInfo(f"other-{number}"))
        with self.assertRaisesRegex(DependencyError, "too many"):
            _binary(output.getvalue())
        with patch("first_commit.scanner_install.MAX_BINARY_BYTES", 1):
            with self.assertRaisesRegex(DependencyError, "size limit"):
                _binary(archive_with_binary(b"two"))

    def test_verified_archive_installs_and_is_reused(self) -> None:
        archive = archive_with_binary(b"synthetic executable")
        digest = hashlib.sha256(archive).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch(
                    "first_commit.scanner_install._archive",
                    return_value=("fixture", digest),
                ),
                patch(
                    "first_commit.scanner_install._download", return_value=archive
                ) as download,
                patch("first_commit.scanner_install.validate_scanner") as validate,
            ):
                self.assertTrue(install_scanner(root))
                self.assertFalse(install_scanner(root))
            target = root / ".local/bin/gitleaks"
            self.assertEqual(b"synthetic executable", target.read_bytes())
            self.assertTrue(target.stat().st_mode & 0o111)
            download.assert_called_once()
            self.assertEqual(2, validate.call_count)

    def test_the_download_runs_only_after_its_file_is_closed(self) -> None:
        # Linux refuses to run a file that a descriptor holds open for writing
        # (ETXTBSY), so validation must start after the write is closed.
        archive = archive_with_binary(b"#!/bin/sh\nexit 0\n")
        digest = hashlib.sha256(archive).hexdigest()
        writers: list[int] = []

        def count_writers(_root: Path, *, executable: str) -> None:
            identity = Path(executable).stat()
            for entry in Path("/dev/fd").iterdir():
                descriptor = int(entry.name)
                try:
                    found = os.fstat(descriptor)
                    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                except OSError:
                    continue
                if (found.st_dev, found.st_ino) == (
                    identity.st_dev,
                    identity.st_ino,
                ) and flags & os.O_ACCMODE != os.O_RDONLY:
                    writers.append(descriptor)

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch(
                    "first_commit.scanner_install._archive",
                    return_value=("fixture", digest),
                ),
                patch("first_commit.scanner_install._download", return_value=archive),
                patch(
                    "first_commit.scanner_install.validate_scanner",
                    side_effect=count_writers,
                ),
            ):
                self.assertTrue(install_scanner(Path(directory)))
        self.assertEqual([], writers)

    def test_bad_archive_digest_leaves_no_binary(self) -> None:
        archive = archive_with_binary(b"synthetic executable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch(
                    "first_commit.scanner_install._archive",
                    return_value=("fixture", "0" * 64),
                ),
                patch("first_commit.scanner_install._download", return_value=archive),
            ):
                with self.assertRaisesRegex(DependencyError, "checksum"):
                    install_scanner(root)
            self.assertFalse((root / ".local/bin/gitleaks").exists())

    def test_missing_binary_and_failed_calibration_leave_no_target(self) -> None:
        for archive in (
            archive_with_binary(b"other", "not-gitleaks"),
            archive_with_binary(b"bad"),
        ):
            with (
                self.subTest(archive=archive[:8]),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                digest = hashlib.sha256(archive).hexdigest()
                with (
                    patch(
                        "first_commit.scanner_install._archive",
                        return_value=("fixture", digest),
                    ),
                    patch(
                        "first_commit.scanner_install._download", return_value=archive
                    ),
                    patch(
                        "first_commit.scanner_install.validate_scanner",
                        side_effect=DependencyError("Synthetic calibration failure."),
                    ),
                ):
                    with self.assertRaises(DependencyError):
                        install_scanner(root)
                self.assertFalse((root / ".local/bin/gitleaks").exists())

    def test_failed_download_hint_does_not_name_setup_itself(self) -> None:
        archive = archive_with_binary(b"#!/bin/sh\necho 9.0.0\n")
        digest = hashlib.sha256(archive).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch(
                    "first_commit.scanner_install._archive",
                    return_value=("fixture", digest),
                ),
                patch("first_commit.scanner_install._download", return_value=archive),
                self.assertRaises(DependencyError) as failure,
            ):
                install_scanner(root)
            self.assertFalse((root / ".local/bin/gitleaks").exists())
        self.assertEqual(
            "Downloaded Gitleaks 8.30.0 failed validation "
            "(Installed Gitleaks is incompatible) and was removed; "
            "install trusted Gitleaks 8.30.0 at .local/bin/gitleaks, "
            "then run setup again.",
            str(failure.exception),
        )
        self.assertNotIn(TOOL_SETUP_COMMAND, str(failure.exception))

    def test_the_reason_is_data_so_a_semicolon_inside_it_stays(self) -> None:
        error = DependencyError(
            "Gitleaks at a; b failed; run setup again.",
            reason="Gitleaks at a; b failed",
        )
        self.assertEqual(
            "Local Gitleaks at .local/bin/gitleaks failed validation (Gitleaks at a; "
            "b failed); delete .local/bin/gitleaks and run setup again, or replace it "
            "with trusted Gitleaks 8.30.0.",
            str(local_scanner_failed(error)),
        )
        self.assertEqual(
            "Gitleaks timed out after 5 seconds",
            ScannerTimeoutError("Gitleaks timed out after 5 seconds.").reason,
        )

    def test_download_timeout_advises_a_retry_first(self) -> None:
        archive = archive_with_binary(b"synthetic executable")
        digest = hashlib.sha256(archive).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch(
                    "first_commit.scanner_install._archive",
                    return_value=("fixture", digest),
                ),
                patch("first_commit.scanner_install._download", return_value=archive),
                patch(
                    "first_commit.scanner_install.validate_scanner",
                    side_effect=ScannerTimeoutError("Gitleaks timed out"),
                ),
                self.assertRaises(DependencyError) as failure,
            ):
                install_scanner(root)
            self.assertFalse((root / ".local/bin/gitleaks").exists())
        self.assertEqual(
            "Downloaded Gitleaks 8.30.0 failed validation (Gitleaks timed out) "
            "and was removed; run setup again; if it times out again, "
            "install trusted Gitleaks 8.30.0 at .local/bin/gitleaks, "
            "then run setup again.",
            str(failure.exception),
        )

    def test_existing_binary_is_preserved_when_incompatible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / ".local/bin/gitleaks"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"existing")
            for error, reason, advice in (
                (
                    DependencyError(
                        "Synthetic calibration failure; advice.",
                        reason="Synthetic calibration failure",
                    ),
                    "Synthetic calibration failure",
                    "",
                ),
                (
                    ScannerTimeoutError("Gitleaks timed out"),
                    "Gitleaks timed out",
                    "run setup again; if it times out again, ",
                ),
            ):
                with (
                    self.subTest(reason=reason),
                    patch(
                        "first_commit.scanner_install.validate_scanner",
                        side_effect=error,
                    ),
                    self.assertRaises(DependencyError) as failure,
                ):
                    install_scanner(root)
                self.assertEqual(
                    f"Local Gitleaks at .local/bin/gitleaks failed validation "
                    f"({reason}); {advice}delete .local/bin/gitleaks and run "
                    "setup again, or replace it with trusted Gitleaks 8.30.0.",
                    str(failure.exception),
                )
            self.assertEqual(b"existing", target.read_bytes())

    def test_existing_symlink_binary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / ".local/bin/gitleaks"
            target.parent.mkdir(parents=True)
            target.symlink_to(root / "missing")
            with self.assertRaisesRegex(DependencyError, "regular"):
                install_scanner(root)

    def test_symlinked_local_directory_is_rejected(self) -> None:
        archive = archive_with_binary(b"synthetic executable")
        digest = hashlib.sha256(archive).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external"
            external.mkdir()
            (root / ".local").symlink_to(external, target_is_directory=True)
            with (
                patch(
                    "first_commit.scanner_install._archive",
                    return_value=("fixture", digest),
                ),
                patch("first_commit.scanner_install._download", return_value=archive),
            ):
                with self.assertRaisesRegex(DependencyError, "unsafe"):
                    install_scanner(root)
            self.assertEqual([], list(external.iterdir()))
