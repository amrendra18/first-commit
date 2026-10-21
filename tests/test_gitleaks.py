import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from first_commit.gitleaks import REPORT_NAME, scan_history, scan_staged
from first_commit.gitleaks_scanner import (
    CALIBRATION_INPUT,
    DependencyError,
    ScannerTimeoutError,
    validate_scanner,
)
from first_commit.setup_hooks import hook_bytes
from tests.gitleaks_support import (
    needs_real_scanner,
    recorded_report_folders,
    trusted_local_scanner,
)
from tests.support import initialize_repository, run_git


class GitleaksTest(unittest.TestCase):
    def test_scans_prefer_verified_repository_local_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            executable = root / ".local/bin/gitleaks"
            executable.parent.mkdir(parents=True)
            fake = (
                b"#!/bin/sh\n"
                b'if [ "$1" = version ]; then echo 8.30.0; exit 0; fi\n'
                b'if [ "$1" = stdin ]; then exit 10; fi\n'
                b"exit 0\n"
            )
            executable.write_bytes(fake)
            executable.chmod(0o755)
            with (
                mock.patch.dict("os.environ", {"PATH": "/usr/bin:/bin"}),
                trusted_local_scanner(fake),
            ):
                self.assertEqual((), scan_staged(root, max_findings=1))

    @needs_real_scanner
    def test_real_scanner_reads_index_without_worktree_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            value = root / "value.txt"
            value.write_bytes(CALIBRATION_INPUT)
            run_git(root, "add", "--", "value.txt")
            value.write_bytes(b"safe\n")
            self.assertEqual(
                "secrets.gitleaks", scan_staged(root, max_findings=1)[0].rule_id
            )
            run_git(root, "add", "--", "value.txt")
            self.assertEqual((), scan_staged(root, max_findings=1))

    def test_rejects_version_suffixes_and_numeric_prefixes(self) -> None:
        for version in (
            "8.30.0-beta",
            "8.30.0+modified",
            "18.30.0",
            "8.30.01",
            "1.8.30.0",
        ):
            completed = subprocess.CompletedProcess(
                ["gitleaks"], 0, stdout=version.encode(), stderr=b""
            )
            with (
                self.subTest(version=version),
                mock.patch(
                    "first_commit.gitleaks_scanner.run_scanner",
                    side_effect=(
                        completed,
                        subprocess.CompletedProcess(["gitleaks"], 10),
                    ),
                ),
            ):
                with self.assertRaisesRegex(DependencyError, "incompatible"):
                    validate_scanner(Path("/repository"), executable="/gitleaks")

    def test_calibration_uses_exact_github_token_shape(self) -> None:
        prefix = b"ghp_"
        token = CALIBRATION_INPUT.split(prefix, 1)[1].split(b'"', 1)[0]

        self.assertEqual(36, len(token))
        self.assertTrue(token.isalnum())

    def test_validate_scanner_reports_missing_and_failed_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(DependencyError, "unavailable"):
                validate_scanner(root, executable="missing-gitleaks")

            executable = root / "gitleaks"
            executable.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            executable.chmod(0o755)
            with self.assertRaisesRegex(DependencyError, "determined"):
                validate_scanner(root, executable=str(executable))

    def test_scans_report_operational_failure_for_staged_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                "exit 1\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            with self.assertRaisesRegex(DependencyError, "scan failed"):
                scan_staged(root, max_findings=1, executable=str(executable))

    def test_staged_scan_uses_official_pre_commit_interface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "arguments"
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                'printf \'%s\\n\' "$*" > "$FIRST_COMMIT_TEST_LOG"\n',
                encoding="utf-8",
            )
            executable.chmod(0o755)

            with recorded_report_folders() as directories:
                findings = scan_staged(
                    root,
                    max_findings=1,
                    executable=str(executable),
                    environment={"FIRST_COMMIT_TEST_LOG": str(log)},
                )

            self.assertEqual((), findings)
            self.assertEqual(
                "git --pre-commit --redact --staged --verbose --exit-code=10 "
                "--ignore-gitleaks-allow --gitleaks-ignore-path .gitleaksignore "
                f"--report-format=json --report-path={directories[0] / REPORT_NAME}",
                log.read_text(encoding="utf-8").strip(),
            )
            self.assertFalse(directories[0].exists())

    def test_scan_passes_without_returning_scanner_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "arguments"
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo 'gitleaks version 8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                'printf \'%s\\n\' "$*" > "$FIRST_COMMIT_TEST_LOG"\n'
                "echo '"
                "ghp_"
                "should_never_be_returned_1234567890'\n"
                "exit 0\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            with recorded_report_folders() as directories:
                findings = scan_history(
                    root,
                    max_findings=1,
                    executable=str(executable),
                    environment={"FIRST_COMMIT_TEST_LOG": str(log)},
                )

            self.assertEqual((), findings)
            self.assertEqual(
                "git --redact --no-banner --exit-code=10 "
                "--ignore-gitleaks-allow --gitleaks-ignore-path .gitleaksignore "
                "--log-opts=--exclude=refs/stash --all "
                f"--report-format=json --report-path={directories[0] / REPORT_NAME} {root}",
                log.read_text(encoding="utf-8").strip(),
            )
            self.assertFalse(directories[0].exists())

    def test_removes_external_configuration_from_scanner_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "environment"
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                "printf '%s|%s\\n' \"${GITLEAKS_CONFIG-unset}\" "
                '"${GITLEAKS_CONFIG_TOML-unset}" > "$FIRST_COMMIT_TEST_LOG"\n',
                encoding="utf-8",
            )
            executable.chmod(0o755)

            scan_history(
                root,
                max_findings=1,
                executable=str(executable),
                environment={
                    "FIRST_COMMIT_TEST_LOG": str(log),
                    "GITLEAKS_CONFIG": "private-config-canary",
                    "GITLEAKS_CONFIG_TOML": "private-config-content-canary",
                },
            )

            self.assertEqual("unset|unset", log.read_text(encoding="utf-8").strip())

    def test_rejects_incompatible_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\necho 'gitleaks version 1.0.0'\n", encoding="utf-8"
            )
            executable.chmod(0o755)

            with self.assertRaisesRegex(DependencyError, "incompatible"):
                scan_history(root, max_findings=1, executable=str(executable))

    def test_findings_exit_returns_redacted_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                "echo '"
                "ghp_"
                "should_never_be_returned_1234567890' >&2\n"
                "exit 10\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            findings = scan_history(root, max_findings=1, executable=str(executable))

        self.assertEqual("secrets.gitleaks", findings[0].rule_id)
        self.assertEqual(".git", findings[0].path)
        self.assertNotIn("ghp_", repr(findings))

    def test_staged_findings_exit_returns_redacted_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                "exit 10\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            findings = scan_staged(root, max_findings=1, executable=str(executable))

        self.assertEqual("secrets.gitleaks", findings[0].rule_id)
        self.assertEqual("<staged-content>", findings[0].path)

    def test_operational_failure_is_not_reported_as_a_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                "echo 'private operational output' >&2\n"
                "exit 1\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            with self.assertRaisesRegex(DependencyError, "scan failed") as context:
                scan_history(root, max_findings=1, executable=str(executable))

        self.assertNotIn("private operational output", str(context.exception))

    def test_rejects_repository_scanner_overrides_without_reading_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canary = "private-scanner-configuration-canary"
            (root / ".gitleaks.toml").write_text(canary, encoding="utf-8")

            with self.assertRaisesRegex(DependencyError, "configuration") as context:
                scan_history(root, max_findings=1, executable="/gitleaks")

        self.assertNotIn(canary, str(context.exception))

    def test_capability_check_requires_detection_of_synthetic_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "gitleaks"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then '
                "grep -q 'ghp_' && exit 10; exit 0; fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)

            validate_scanner(root, executable=str(executable))

            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DependencyError, "capability"):
                validate_scanner(root, executable=str(executable))

    def test_unavailable_explicit_executable_is_redacted(self) -> None:
        with mock.patch(
            "first_commit.gitleaks_scanner.subprocess.run",
            side_effect=OSError("private-operating-system-canary"),
        ):
            with self.assertRaisesRegex(DependencyError, "unavailable") as context:
                validate_scanner(Path("/repository"), executable="/gitleaks")

        self.assertNotIn("private-operating-system-canary", str(context.exception))

    def test_timeout_returns_redacted_dependency_error(self) -> None:
        with mock.patch(
            "first_commit.gitleaks_scanner.subprocess.run",
            side_effect=subprocess.TimeoutExpired("private-command", 1),
        ):
            with self.assertRaisesRegex(ScannerTimeoutError, "timed out") as context:
                scan_history(
                    Path("/repository"), max_findings=1, executable="/gitleaks"
                )

        self.assertIsInstance(context.exception, DependencyError)
        self.assertNotIn("private-command", str(context.exception))

    def test_dependency_messages_name_the_setup_command_that_works_here(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".pre-commit-config.yaml").write_bytes(hook_bytes("1" * 40))
            with self.assertRaises(DependencyError) as missing:
                validate_scanner(root, executable="missing-gitleaks")

        self.assertEqual(
            "Gitleaks 8.30.0 is unavailable; "
            "run 'pre-commit run first-commit-setup --hook-stage manual' in this checkout, "
            "or install Gitleaks 8.30.0 on PATH.",
            str(missing.exception),
        )

        version = subprocess.CompletedProcess(
            ["gitleaks"], 0, stdout=b"9.0.0", stderr=b""
        )
        with mock.patch(
            "first_commit.gitleaks_scanner.run_scanner",
            side_effect=(version, subprocess.CompletedProcess(["gitleaks"], 10)),
        ):
            with self.assertRaises(DependencyError) as incompatible:
                validate_scanner(Path("/repository"), executable="/gitleaks")

        self.assertEqual(
            "Installed Gitleaks is incompatible; "
            "run 'first-commit setup' in this checkout, "
            "or install Gitleaks 8.30.0 on PATH.",
            str(incompatible.exception),
        )

        supported = subprocess.CompletedProcess(
            ["gitleaks"], 0, stdout=b"8.30.0", stderr=b""
        )
        with mock.patch(
            "first_commit.gitleaks_scanner.run_scanner",
            side_effect=(supported, subprocess.CompletedProcess(["gitleaks"], 0)),
        ):
            with self.assertRaises(DependencyError) as capability:
                validate_scanner(Path("/repository"), executable="/gitleaks")

        self.assertEqual(
            "Installed Gitleaks failed its capability check; "
            "run 'first-commit setup' in this checkout, "
            "or install Gitleaks 8.30.0 on PATH.",
            str(capability.exception),
        )

        with mock.patch(
            "first_commit.gitleaks_scanner.subprocess.run",
            side_effect=OSError("private-operating-system-canary"),
        ):
            with self.assertRaises(DependencyError) as unrunnable:
                validate_scanner(
                    Path("/private-repository"),
                    executable="/private-gitleaks",
                )

        self.assertEqual(
            "Gitleaks is unavailable; "
            "run 'first-commit setup' in this checkout, "
            "or install the pinned Gitleaks version on PATH.",
            str(unrunnable.exception),
        )

        for message in (
            str(missing.exception),
            str(incompatible.exception),
            str(capability.exception),
            str(unrunnable.exception),
        ):
            with self.subTest(message=message):
                self.assertNotIn("\n", message)
                self.assertNotIn("/", message)
                self.assertLess(message.index("'"), message.index("install "))

    def test_scanner_is_validated_once_per_process_until_its_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            log = root.parent / f"{root.name}-calls.log"
            self.addCleanup(log.unlink, missing_ok=True)
            executable = root.parent / f"{root.name}-gitleaks"
            self.addCleanup(executable.unlink, missing_ok=True)
            script = (
                "#!/bin/sh\n"
                f"echo \"$1\" >> '{log}'\n"
                "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
                'if [ "$1" = stdin ]; then exit 10; fi\n'
                "exit 0\n"
            )
            executable.write_text(script, encoding="utf-8")
            executable.chmod(0o755)

            validate_scanner(root, executable=str(executable))
            scan_staged(root, max_findings=1, executable=str(executable))
            scan_history(root, max_findings=1, executable=str(executable))
            first = log.read_text("utf-8").split()
            executable.write_text(script + "# changed\n", encoding="utf-8")
            validate_scanner(root, executable=str(executable))

        self.assertEqual(["version", "stdin", "git", "git"], first)
        self.assertEqual([*first, "version", "stdin"], log.read_text("utf-8").split())


if __name__ == "__main__":
    unittest.main()
