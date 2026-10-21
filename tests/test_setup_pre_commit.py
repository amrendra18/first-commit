import json
import os
import shlex
import shutil
import subprocess
import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock, patch

from first_commit.checks.identity import IDENTITY_KEYS
from first_commit.contributor import (
    CONTRIBUTOR_PATH,
)
from first_commit.gitleaks_scanner import DependencyError
from first_commit.hooks import hook_ready
from first_commit.models import SetupError
from first_commit.pre_commit_runner import (
    progress_heartbeat,
    run_pre_commit,
    validate_schema,
)
from first_commit.setup import SetupRequest, _git_snapshot, setup_repository
from first_commit.setup_files import restore_git_config
from tests.setup_support import (
    REVISION,
    SetupFixture,
)
from tests.support import run_git


class PreCommitSetupTest(SetupFixture):
    def test_pre_commit_runner_uses_fixed_arguments_and_redacts_failures(self) -> None:
        complete = subprocess.CompletedProcess[bytes]([], 0)
        with patch(
            "first_commit.pre_commit_runner.subprocess.run", return_value=complete
        ) as call:
            run_pre_commit(self.root, ("install-hooks",))
        self.assertEqual(
            [sys.executable, "-I", "-m", "pre_commit", "install-hooks"],
            call.call_args.args[0],
        )
        self.assertNotIn("shell", call.call_args.kwargs)
        self.assertEqual(subprocess.DEVNULL, call.call_args.kwargs["stdin"])
        self.assertEqual(300, call.call_args.kwargs["timeout"])
        for error in (
            OSError("private-canary"),
            subprocess.TimeoutExpired("private-canary", 300),
        ):
            with patch(
                "first_commit.pre_commit_runner.subprocess.run", side_effect=error
            ):
                with self.assertRaisesRegex(
                    DependencyError,
                    "^Hook environment install failed: pre-commit could not run",
                ) as context:
                    run_pre_commit(self.root, ("install-hooks",))
                self.assertNotIn("private-canary", str(context.exception))
        with patch(
            "first_commit.pre_commit_runner.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            with self.assertRaisesRegex(
                DependencyError,
                "^Hook environment install failed: pre-commit exited 1;",
            ):
                run_pre_commit(self.root, ("install-hooks",))
            with self.assertRaisesRegex(
                DependencyError, "^Hook script install failed: pre-commit exited 1;"
            ):
                run_pre_commit(self.root, ("install",))

    def hook_environment_failure(self, *, offer_rerun: bool = False) -> str:
        with (
            patch(
                "first_commit.pre_commit_runner.subprocess.run",
                return_value=subprocess.CompletedProcess([], 1),
            ),
            self.assertRaises(DependencyError) as context,
        ):
            run_pre_commit(self.root, ("install-hooks",), offer_rerun=offer_rerun)
        return str(context.exception)

    def test_hook_environment_failure_names_the_log_before_any_rerun(self) -> None:
        home = str(self.root / "home")
        for variables, log in (
            ({"PRE_COMMIT_HOME": "/pc"}, "/pc/pre-commit.log"),
            (
                {"PRE_COMMIT_HOME": "", "XDG_CACHE_HOME": "/xdg"},
                "/xdg/pre-commit/pre-commit.log",
            ),
            (
                {"PRE_COMMIT_HOME": "", "XDG_CACHE_HOME": "", "HOME": home},
                f"{home}/.cache/pre-commit/pre-commit.log",
            ),
        ):
            with self.subTest(log=log), patch.dict(os.environ, variables):
                message = self.hook_environment_failure()
                self.assertIn(
                    f"\nfix: read `{log}` before you rerun anything: it holds "
                    "pre-commit's own error, and the next pre-commit error "
                    "replaces it.",
                    message,
                )
                self.assertNotIn("install-hooks`", message)
        command = f"{shlex.quote(sys.executable)} -m pre_commit install-hooks"
        message = self.hook_environment_failure(offer_rerun=True)
        self.assertLess(
            message.index("before you rerun anything"),
            message.index(
                f"To see the error again, run `{command}` in the project folder."
            ),
        )

    def failed_setup_message(self) -> str:
        def run(
            root: Path,
            arguments: tuple[str, ...],
            progress: Callable[[str], None] | None = None,
            *,
            offer_rerun: bool = False,
        ) -> None:
            if arguments[0] != "install-hooks":
                run_pre_commit(root, arguments, progress)
                return
            failed = subprocess.CompletedProcess[bytes]([], 1)
            with patch(
                "first_commit.pre_commit_runner.subprocess.run", return_value=failed
            ):
                run_pre_commit(root, arguments, progress, offer_rerun=offer_rerun)

        with (
            patch("first_commit.setup_apply.run_pre_commit", side_effect=run),
            patch("first_commit.setup._preflight_source"),
            self.assertRaises(DependencyError) as context,
        ):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, confirmed=True),
                contributor=self.person,
            )
        return str(context.exception)

    def test_setup_offers_the_rerun_only_when_config_and_git_stay(self) -> None:
        rerun = "To see the error again, run "
        self.initialized_with_hooks()
        self.assertIn(rerun, self.failed_setup_message())
        (self.root / ".pre-commit-config.yaml").unlink()
        self.assertNotIn(rerun, self.failed_setup_message())
        shutil.rmtree(self.root / ".git")
        self.local_hooks()
        self.assertNotIn(rerun, self.failed_setup_message())
        self.assertFalse((self.root / ".git").exists())

    def test_pre_commit_reports_bounded_redacted_progress(self) -> None:
        messages: list[str] = []
        complete = subprocess.CompletedProcess[bytes]([], 0)
        with patch(
            "first_commit.pre_commit_runner.subprocess.run", return_value=complete
        ):
            run_pre_commit(self.root, ("install-hooks",), progress=messages.append)
        self.assertEqual(
            ["Installing hook environment...", "Installing hook environment: done"],
            messages,
        )
        for detail, expected in (
            (
                "dependency work or cache lock",
                (
                    "Installing hook environment... 30s elapsed; "
                    "dependency work or cache lock"
                ),
            ),
            ("", "Installing hook environment... 30s elapsed"),
        ):
            with self.subTest(detail=detail):
                done = Mock()
                done.wait.side_effect = (False, True)
                messages = []
                progress_heartbeat(
                    messages.append, "Installing hook environment", detail, done
                )
                self.assertEqual([expected], messages)

    def test_schema_process_is_isolated_read_only_and_failure_redacted(self) -> None:
        complete = subprocess.CompletedProcess[bytes]([], 0)
        with patch(
            "first_commit.pre_commit_runner.subprocess.run", return_value=complete
        ) as call:
            validate_schema(b"{}")
        self.assertEqual([sys.executable, "-I", "-B", "-c"], call.call_args.args[0][:4])
        self.assertEqual(b"{}", call.call_args.kwargs["input"])
        self.assertNotIn("shell", call.call_args.kwargs)
        for error in (
            OSError("private-canary"),
            subprocess.TimeoutExpired("private-canary", 300),
        ):
            with patch(
                "first_commit.pre_commit_runner.subprocess.run", side_effect=error
            ):
                with self.assertRaises(DependencyError) as context:
                    validate_schema(b"{}")
                self.assertNotIn("private-canary", str(context.exception))
        with patch(
            "first_commit.pre_commit_runner.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1),
        ):
            with self.assertRaisesRegex(SetupError, "failed validation"):
                validate_schema(b"{}")

    def test_managed_hook_requires_valid_wrapper_and_live_interpreter(self) -> None:
        base = (
            b"# File generated by pre-commit:\n"
            b"--hook-type=pre-commit --config=.pre-commit-config.yaml\n"
        )
        executable = Path(sys.executable)
        live = base + ("INSTALL_PYTHON=" + repr(sys.executable) + "\n").encode()
        self.assertTrue(hook_ready(executable, live, "pre-commit"))
        not_executable = self.root / "hook"
        not_executable.write_bytes(live)
        self.assertFalse(hook_ready(not_executable, live, "pre-commit"))
        for raw in (
            b"custom",
            base,
            base + b"INSTALL_PYTHON='\n",
            base + b"INSTALL_PYTHON=/not-present\n",
            base + b"\xff",
        ):
            with self.subTest(raw=raw):
                self.assertFalse(hook_ready(executable, raw, "pre-commit"))
        self.assertFalse(hook_ready(executable, live, "pre-push"))

    def test_config_restore_preserves_later_edits_and_original_permissions(
        self,
    ) -> None:
        path = self.root / "config-fixture"
        path.write_bytes(b"later")
        restore_git_config(path, b"owned", b"original")
        self.assertEqual(b"later", path.read_bytes())
        path.write_bytes(b"owned")
        path.chmod(0o600)
        restore_git_config(path, b"owned", b"original")
        self.assertEqual(b"original", path.read_bytes())
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        restore_git_config(path, b"original", None)
        self.assertFalse(path.exists())

    def test_git_snapshot_rejects_special_entries(self) -> None:
        self.assertIsNotNone(_git_snapshot(self.root))
        self.assertIsNone(_git_snapshot(self.root / "missing"))
        (self.root / "link").symlink_to(self.root / "missing")
        self.assertIsNone(_git_snapshot(self.root))

    def test_blank_setup_preserves_git_if_metadata_changes(self) -> None:
        self.local_hooks()

        def concurrent_change(root, _arguments, **_options):
            (root / ".git" / "concurrent-note").write_text(
                "unrelated\n", encoding="utf-8"
            )
            raise DependencyError("Synthetic installer failure.")

        with patch(
            "first_commit.setup_apply.run_pre_commit", side_effect=concurrent_change
        ):
            with self.assertRaisesRegex(SetupError, "new .git folder changed"):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, confirmed=True),
                    contributor=self.person,
                )
        self.assertEqual(
            "unrelated\n",
            (self.root / ".git" / "concurrent-note").read_text("utf-8"),
        )

    def test_rollback_preserves_concurrent_edits_and_reports_recovery_failure(
        self,
    ) -> None:
        self.initialized_with_hooks()
        policy = self.root / ".repo-policy.json"

        def edited_failure(root, _arguments, **_options):
            policy.write_text("concurrent edit\n", encoding="utf-8")
            run_git(root, "config", "--local", "fixture.changed", "yes")
            raise DependencyError("Synthetic failure.")

        with patch(
            "first_commit.setup_apply.run_pre_commit", side_effect=edited_failure
        ):
            with self.assertRaises(DependencyError):
                setup_repository(
                    self.root, SetupRequest(revision=REVISION), contributor=self.person
                )
        self.assertEqual("concurrent edit\n", policy.read_text("utf-8"))
        self.assertEqual(
            b"yes\n",
            run_git(self.root, "config", "--local", "--get", "fixture.changed").stdout,
        )
        self.assertFalse((self.root / "README.md").exists())
        self.assertFalse((self.root / CONTRIBUTOR_PATH).exists())
        policy.unlink()
        run_git(self.root, "config", "--local", "--unset", "fixture.changed")
        for key in (*IDENTITY_KEYS, "commit.template"):
            subprocess.run(
                ["git", "-C", str(self.root), "config", "--local", "--unset-all", key],
                check=False,
            )

        def symlink_failure(_root, _arguments, **_options):
            policy.unlink()
            policy.symlink_to(self.root / "target")
            raise DependencyError("Synthetic failure.")

        with patch(
            "first_commit.setup_apply.run_pre_commit", side_effect=symlink_failure
        ):
            with self.assertRaisesRegex(SetupError, "recovery failed"):
                setup_repository(
                    self.root, SetupRequest(revision=REVISION), contributor=self.person
                )

    def test_partial_hook_install_failure_removes_owned_partial_hook(self) -> None:
        self.initialized_with_hooks()

        def failed_install(root, arguments, **_options):
            if arguments[0] == "install":
                (root / ".git/hooks/pre-commit").write_bytes(b"partial wrapper\n")
                raise DependencyError("Synthetic failure.")

        with patch(
            "first_commit.setup_apply.run_pre_commit", side_effect=failed_install
        ):
            with self.assertRaises(DependencyError):
                setup_repository(
                    self.root, SetupRequest(revision=REVISION), contributor=self.person
                )
        self.assertFalse((self.root / ".git/hooks/pre-commit").exists())
        self.assertFalse((self.root / ".repo-policy.json").exists())
        with self.assertRaises(subprocess.CalledProcessError):
            run_git(self.root, "config", "--local", "--get", "user.email")

    def test_invalid_pre_commit_schema_fails_before_writes_including_preview(
        self,
    ) -> None:
        self.initialized_with_hooks()
        path = self.root / ".pre-commit-config.yaml"
        value = json.loads(path.read_text("utf-8"))
        value["repos"].append({"repo": "local", "hooks": [{"id": "consumer-hook"}]})
        path.write_text(json.dumps(value), encoding="utf-8")
        before = self.files()
        for dry_run in (True, False):
            with (
                self.subTest(dry_run=dry_run),
                patch("first_commit.setup_apply.create_exclusive") as create,
            ):
                with self.assertRaisesRegex(SetupError, "validation"):
                    setup_repository(
                        self.root,
                        SetupRequest(revision=REVISION, dry_run=dry_run),
                        contributor=self.person,
                    )
                create.assert_not_called()
                self.assertEqual(before, self.files())

    def test_setup_subprocesses_do_not_import_consumer_modules(self) -> None:
        self.initialized_with_hooks()
        (self.root / "cfgv.py").write_text(
            "raise RuntimeError('consumer-code-canary')\n", encoding="utf-8"
        )
        shadow = self.root / "pre_commit"
        shadow.mkdir()
        (shadow / "__init__.py").write_text(
            "raise RuntimeError('consumer-code-canary')\n", encoding="utf-8"
        )
        before = self.files()
        setup_repository(
            self.root,
            SetupRequest(revision=REVISION, dry_run=True),
            contributor=self.person,
        )
        self.assertEqual(before, self.files())
        actions = setup_repository(
            self.root, SetupRequest(revision=REVISION), contributor=self.person
        )
        self.assertIn("Verification: passed", actions)


if __name__ == "__main__":
    unittest.main()
