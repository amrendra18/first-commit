import json
import os
import subprocess
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

import yaml

from first_commit.git import git_executable
from first_commit.gitleaks_scanner import DependencyError
from first_commit.hooks import GITHUB_REPOSITORY, HTTPS_REPOSITORY, SSH_REPOSITORY
from first_commit.models import SetupError
from first_commit.setup import (
    SetupRequest,
    _preflight_source,
    _revision,
    setup_repository,
)
from first_commit.setup_apply import setup_lock
from first_commit.setup_command import declares_setup_hook
from first_commit.setup_hooks import check_hook_config, hook_bytes
from tests.setup_support import (
    REVISION,
    SetupFixture,
)
from tests.support import run_git
from tests.timing_support import LINEAR_GROWTH_LIMIT, growth


class HookSourceSetupTest(SetupFixture):
    def test_revision_provenance_and_conflicts(self) -> None:
        metadata = Mock()
        with patch(
            "first_commit.hooks.importlib.metadata.distribution",
            return_value=metadata,
        ):
            for repository in (HTTPS_REPOSITORY, SSH_REPOSITORY):
                for suffix in ("", ".git"):
                    with self.subTest(repository=repository, suffix=suffix):
                        metadata.read_text.return_value = json.dumps(
                            {
                                "url": repository + suffix,
                                "vcs_info": {"commit_id": REVISION},
                            }
                        )
                        self.assertEqual((REVISION, HTTPS_REPOSITORY), _revision(None))
                        self.assertEqual(
                            (REVISION, HTTPS_REPOSITORY), _revision(None, "https")
                        )
                        self.assertEqual(
                            (REVISION, SSH_REPOSITORY), _revision(None, "ssh")
                        )
                        with self.assertRaisesRegex(SetupError, "differs"):
                            _revision("2" * 40)
            for repository in (
                "http://github.com/" + GITHUB_REPOSITORY,
                "ssh://other" + "@" + "github.com/" + GITHUB_REPOSITORY,
                "ssh://git" + "@" + "other.example/" + GITHUB_REPOSITORY,
                SSH_REPOSITORY + "/extra",
                "file:///tmp/first-commit",
            ):
                with self.subTest(untrusted=repository):
                    metadata.read_text.return_value = json.dumps(
                        {
                            "url": repository,
                            "vcs_info": {"commit_id": REVISION},
                        }
                    )
                    with self.assertRaisesRegex(SetupError, "immutable Git revision"):
                        _revision(None)
                    self.assertEqual((REVISION, HTTPS_REPOSITORY), _revision(REVISION))
        metadata.read_text.return_value = "{}"
        with patch(
            "first_commit.hooks.importlib.metadata.distribution",
            return_value=metadata,
        ):
            with self.assertRaisesRegex(SetupError, "immutable Git revision"):
                _revision(None)
            self.assertEqual((REVISION, HTTPS_REPOSITORY), _revision(REVISION))
            self.assertEqual((REVISION, SSH_REPOSITORY), _revision(REVISION, "ssh"))
            with self.assertRaisesRegex(SetupError, "Transport"):
                _revision(REVISION, "local")

        metadata.read_text.return_value = json.dumps({"url": SSH_REPOSITORY + ".git"})
        with patch(
            "first_commit.hooks.importlib.metadata.distribution",
            return_value=metadata,
        ):
            self.assertEqual((REVISION, HTTPS_REPOSITORY), _revision(REVISION))
            self.assertEqual((REVISION, SSH_REPOSITORY), _revision(REVISION, "ssh"))
            for revision in ("main", "v0.1.0", "f" * 39, "F" * 40, "private-canary"):
                with self.subTest(revision=revision):
                    with self.assertRaises(SetupError) as context:
                        _revision(revision)
                    self.assertNotIn("private-canary", str(context.exception))

    def test_explicit_transport_selects_new_hook_source(self) -> None:
        actions = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, transport="ssh", dry_run=True),
            contributor=self.person,
        )
        self.assertIn(f"Hook source: SSH ({SSH_REPOSITORY})", actions)

    def test_transport_does_not_rewrite_project_owned_hooks(self) -> None:
        run_git(self.root, "init", "-q")
        hook = self.root / ".pre-commit-config.yaml"
        hook.write_bytes(hook_bytes(REVISION, HTTPS_REPOSITORY))
        original = hook.read_bytes()

        actions = setup_repository(
            self.root,
            SetupRequest(revision=REVISION, transport="ssh", dry_run=True),
            contributor=self.person,
        )

        self.assertIn(
            "Hook source: existing project-owned configuration retained", actions
        )
        self.assertEqual(original, hook.read_bytes())

    def test_ssh_install_still_writes_the_https_address(self) -> None:
        metadata = Mock()
        metadata.read_text.return_value = json.dumps(
            {
                "url": SSH_REPOSITORY + ".git",
                "vcs_info": {"commit_id": REVISION},
            }
        )
        with (
            patch(
                "first_commit.hooks.importlib.metadata.distribution",
                return_value=metadata,
            ),
            patch("first_commit.setup._preflight_source") as preflight,
            patch("first_commit.setup_apply.run_pre_commit") as pre_commit,
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            actions = setup_repository(
                self.root, SetupRequest(confirmed=True), contributor=self.person
            )
        hook_file = (self.root / ".pre-commit-config.yaml").read_text("utf-8")
        self.assertEqual(
            HTTPS_REPOSITORY,
            yaml.safe_load(hook_file)["repos"][0]["repo"],
        )
        self.assertFalse(hook_file.startswith("{"))
        self.assertIn(
            (self.root.resolve(), ("install-hooks",)),
            [call.args for call in pre_commit.call_args_list],
        )
        self.assertIn(f"Hook source: HTTPS ({HTTPS_REPOSITORY})", actions)
        preflight.assert_called_once_with(self.root.resolve(), HTTPS_REPOSITORY)
        self.assertIn("Hook environments: installed or verified", actions)

    def test_hook_configuration_rejects_ambiguous_or_unknown_declarations(self) -> None:
        check_hook_config(hook_bytes(REVISION), REVISION)
        check_hook_config(hook_bytes(REVISION, SSH_REPOSITORY), REVISION)
        with self.assertRaises(SetupError) as error:
            check_hook_config(hook_bytes("2" * 40, SSH_REPOSITORY), REVISION)
        self.assertIn(f"sets rev to {'2' * 40}", str(error.exception))
        self.assertIn(f"rev to {REVISION}", str(error.exception))
        with self.assertRaisesRegex(SetupError, "autoupdate --freeze"):
            check_hook_config(hook_bytes("v0.3.0", SSH_REPOSITORY), REVISION)
        self.local_hooks()
        value = json.loads((self.root / ".pre-commit-config.yaml").read_text("utf-8"))
        value["repos"].append(
            {
                "repo": "https://example.com/untrusted-hooks",
                "rev": REVISION,
                "hooks": [{"id": "first-commit-staged"}],
            }
        )
        with self.assertRaisesRegex(SetupError, "source"):
            check_hook_config(json.dumps(value).encode(), REVISION)
        for raw in (
            b"repos: []\nrepos: []\n",
            b"repos: &one []\nother: *one\n",
            b"repos: invalid\n",
            b"repos: []\n",
            (
                b"repos:\n  - repo: local\n    hooks:\n      - id: first-commit-staged\n"
                b"        stages: [pre-push]\n"
            ),
            b"repos:\n  - repo: local\n    hooks:\n      - id: unknown-staged\n",
        ):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(SetupError):
                    check_hook_config(raw, REVISION)

    def test_existing_local_hooks_cannot_impersonate_first_commit_checks(self) -> None:
        self.local_hooks()
        path = self.root / ".pre-commit-config.yaml"
        original = json.loads(path.read_text("utf-8"))
        for field, replacement in (
            ("entry", "true"),
            ("language", "script"),
            ("always_run", False),
            ("pass_filenames", True),
            ("stages", ["pre-push"]),
        ):
            with self.subTest(field=field):
                value = json.loads(json.dumps(original))
                value["repos"][0]["hooks"][0][field] = replacement
                with self.assertRaisesRegex(SetupError, "hook declaration"):
                    check_hook_config(json.dumps(value).encode(), REVISION)

        remote = yaml.safe_load(hook_bytes(REVISION))
        remote["repos"][0]["hooks"][0]["entry"] = "true"
        with self.assertRaisesRegex(SetupError, "hook declaration"):
            check_hook_config(json.dumps(remote).encode(), REVISION)

    def test_missing_setup_dependency_and_git_metadata_conflicts(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        with patch(
            "first_commit.setup_plan.importlib.util.find_spec", return_value=None
        ):
            with self.assertRaises(DependencyError):
                setup_repository(
                    self.root,
                    SetupRequest(revision=REVISION, dry_run=True),
                    contributor=self.person,
                )
        lock = self.root / ".git/config.lock"
        lock.write_text("other process\n", encoding="utf-8")
        with self.assertRaisesRegex(SetupError, "locked"):
            setup_repository(
                self.root,
                SetupRequest(revision=REVISION, dry_run=True),
                contributor=self.person,
            )
        lock.unlink()
        nested = self.root / "nested"
        nested.mkdir()
        with self.assertRaisesRegex(SetupError, "repository root"):
            setup_repository(
                nested, SetupRequest(revision=REVISION), contributor=self.person
            )

    def test_concurrent_setup_is_rejected_before_mutation(self) -> None:
        run_git(self.root, "init", "-q")
        self.local_hooks()
        with setup_lock(self.root):
            with self.assertRaisesRegex(SetupError, "already running"):
                setup_repository(
                    self.root, SetupRequest(revision=REVISION), contributor=self.person
                )

        self.assertFalse((self.root / ".repo-policy.json").exists())
        self.assertTrue((self.root / ".git/first-commit-setup.lock").is_file())

    def test_three_setups_started_together_run_one_at_a_time(self) -> None:
        run_git(self.root, "init", "-q")
        first = ExitStack()
        first.enter_context(setup_lock(self.root))
        third = ExitStack()
        self.addCleanup(third.close)
        real_fstat = os.fstat
        opened: list[int] = []

        # The second setup has opened the lock file; the first ends and the third
        # starts before the second asks for the lock.
        def between_open_and_lock(descriptor: int) -> os.stat_result:
            if not opened:
                opened.append(descriptor)
                first.close()
                third.enter_context(setup_lock(self.root))
            return real_fstat(descriptor)

        with (
            patch(
                "first_commit.setup_apply.os.fstat", side_effect=between_open_and_lock
            ),
            self.assertRaisesRegex(SetupError, "already running"),
        ):
            with setup_lock(self.root):
                self.fail("two setups ran at once")

    def test_setup_lock_rejects_symlink_and_preserves_mutation_errors(self) -> None:
        run_git(self.root, "init", "-q")
        external = self.root / "external-lock"
        external.write_text("preserve\n", encoding="utf-8")
        lock = self.root / ".git/first-commit-setup.lock"
        lock.symlink_to(external)
        with self.assertRaisesRegex(SetupError, "lock"):
            with setup_lock(self.root):
                self.fail("unsafe lock acquired")
        self.assertEqual("preserve\n", external.read_text("utf-8"))
        lock.unlink()

        with self.assertRaisesRegex(OSError, "mutation failure"):
            with setup_lock(self.root):
                raise OSError("mutation failure")
        self.assertTrue(lock.is_file())

    def test_hook_source_preflight_is_bounded_noninteractive_and_redacted(self) -> None:
        completed = subprocess.CompletedProcess[bytes]([], 0)
        with patch("first_commit.setup.subprocess.run", return_value=completed) as run:
            _preflight_source(self.root, HTTPS_REPOSITORY)

        self.assertEqual(
            [git_executable(), "ls-remote", "--exit-code", HTTPS_REPOSITORY],
            run.call_args.args[0],
        )
        self.assertEqual("0", run.call_args.kwargs["env"]["GIT_TERMINAL_PROMPT"])
        self.assertEqual("Never", run.call_args.kwargs["env"]["GCM_INTERACTIVE"])
        self.assertEqual(subprocess.DEVNULL, run.call_args.kwargs["stdin"])
        self.assertEqual(60, run.call_args.kwargs["timeout"])

        with patch(
            "first_commit.setup.subprocess.run",
            return_value=subprocess.CompletedProcess([], 128),
        ):
            with self.assertRaisesRegex(
                DependencyError, "Git exited 128.*--transport ssh"
            ):
                _preflight_source(self.root, HTTPS_REPOSITORY)
        with patch(
            "first_commit.setup.subprocess.run",
            side_effect=OSError("private-canary"),
        ):
            with self.assertRaises(DependencyError) as context:
                _preflight_source(self.root, SSH_REPOSITORY)
        self.assertNotIn("private-canary", str(context.exception))

        with self.assertRaisesRegex(SetupError, "approved"):
            _preflight_source(self.root, "https://example.com/unapproved")

    def test_setup_hook_declaration_is_read_from_the_hook_file(self) -> None:
        hook_file = self.root / ".pre-commit-config.yaml"
        self.assertFalse(declares_setup_hook(self.root))
        hook_file.write_bytes(hook_bytes(REVISION))
        self.assertTrue(declares_setup_hook(self.root))
        hook_file.write_text(
            "    hooks:\n      - id: 'first-commit-setup'  # kept\n", "utf-8"
        )
        self.assertTrue(declares_setup_hook(self.root))
        self.local_hooks()
        self.assertFalse(declares_setup_hook(self.root))
        for unsupported in (
            "repos: [{repo: local, hooks: [{id: first-commit-setup}]}]\n",
            "    hooks:\n      - name: Setup\n        id: first-commit-setup\n",
        ):
            with self.subTest(layout=unsupported):
                hook_file.write_text(unsupported, "utf-8")
                self.assertFalse(declares_setup_hook(self.root))
        hook_file.unlink()
        (self.root / "elsewhere.yaml").write_bytes(hook_bytes(REVISION))
        hook_file.symlink_to(self.root / "elsewhere.yaml")
        self.assertFalse(declares_setup_hook(self.root))

    def test_hook_file_of_blank_lines_is_read_in_linear_time(self) -> None:
        def read(lines: int) -> None:
            (self.root / ".pre-commit-config.yaml").write_bytes(b"\n" * lines)
            self.assertFalse(declares_setup_hook(self.root))

        self.assertLess(growth(read, 25_000), LINEAR_GROWTH_LIMIT)

    def test_own_hook_file_lets_setup_run_without_a_revision(self) -> None:
        metadata = Mock()
        metadata.read_text.return_value = "{}"
        self.enterContext(
            patch(
                "first_commit.hooks.importlib.metadata.distribution",
                return_value=metadata,
            )
        )
        run_git(self.root, "init", "-q")
        with self.assertRaisesRegex(SetupError, "immutable Git revision"):
            setup_repository(
                self.root, SetupRequest(dry_run=True), contributor=self.person
            )

        self.local_hooks()
        starter = setup_repository(
            self.root, SetupRequest(dry_run=True), contributor=self.person
        )
        self.assertIn("README.md", " ".join(starter))
        policy = self.root / ".repo-policy.json"
        policy.write_text('{"schema_version":1}\n', encoding="utf-8")
        preview = setup_repository(
            self.root, SetupRequest(dry_run=True), contributor=self.person
        )
        self.assertIn(
            "Hook source: existing project-owned configuration retained", preview
        )
        with (
            patch("first_commit.setup_apply.run_pre_commit"),
            patch("first_commit.setup_apply.hook_findings", return_value=[]),
        ):
            applied = setup_repository(
                self.root, SetupRequest(confirmed=True), contributor=self.person
            )
        self.assertIn("Verification: passed", applied)

        policy.unlink()
        (self.root / ".pre-commit-config.yaml").write_bytes(hook_bytes(REVISION))
        preview = setup_repository(
            self.root, SetupRequest(dry_run=True), contributor=self.person
        )
        self.assertIn("Verification: preflight passed; no changes made", preview)


if __name__ == "__main__":
    unittest.main()
