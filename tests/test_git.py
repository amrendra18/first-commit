import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from first_commit.git import (
    GitError,
    _git_folders,
    git_path,
    repository_root,
    run_git,
    sanitized_git_environment,
)
from first_commit.git_settings import effective_git_settings, local_git_settings
from first_commit.gitleaks import scan_staged
from first_commit.hooks import hook_findings
from first_commit.policy import REQUIRED_DOCUMENTS
from first_commit.setup import _repository_exists
from tests.gitleaks_support import commit_fixture
from tests.support import TemporaryRootTest, initialize_repository
from tests.support import run_git as fixture_git

PROJECT = Path(__file__).resolve().parents[1]
PASSING_SCANNER = (
    "#!/bin/sh\n"
    "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
    'if [ "$1" = stdin ]; then exit 10; fi\n'
    "exit 0\n"
)
INDEX_LOGGING_SCANNER = PASSING_SCANNER.removesuffix("exit 0\n") + (
    'printf "%s\\n" "${GIT_INDEX_FILE-unset}" >> "$FIRST_COMMIT_TEST_LOG"\nexit 0\n'
)
CONTROL_CHARACTER = "text.control-character"
INDEX_VARIABLE = "GIT_INDEX_FILE"
COMMIT_FORMS = (("-a",), ("--", "README.md"))


class GitTest(unittest.TestCase):
    def test_effective_config_filters_keys_and_uses_last_value(self) -> None:
        raw = b"private.setting\n\xff\0commit.template\nfirst\0commit.template\nlast\0flag\0"
        with patch("first_commit.git_settings.run_git", return_value=raw):
            self.assertEqual(
                {"commit.template": "last", "flag": ""},
                effective_git_settings(Path(), ("commit.template", "flag")),
            )
        with patch(
            "first_commit.git_settings.run_git", return_value=b"commit.template\n\xff\0"
        ):
            with self.assertRaisesRegex(GitError, "invalid configuration"):
                effective_git_settings(Path(), ("commit.template",))

    def test_run_git_wraps_unavailable_executable(self) -> None:
        with patch("first_commit.git.subprocess.run", side_effect=OSError("private")):
            with self.assertRaisesRegex(GitError, "unavailable"):
                run_git(Path("/repository"), ("status",))

    def test_git_timeout_is_redacted(self) -> None:
        canary = b"private-git-timeout-canary"
        timeout = subprocess.TimeoutExpired(["git"], 120, output=canary)
        with patch("first_commit.git.subprocess.run", side_effect=timeout):
            with self.assertRaisesRegex(GitError, "timed out") as context:
                run_git(Path("/repository"), ("status",))
        self.assertNotIn(canary.decode(), str(context.exception))

    def test_inherited_tracing_does_not_create_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            trace = root / "trace"
            with patch.dict(os.environ, {"GIT_TRACE": str(trace)}, clear=False):
                run_git(root, ("rev-parse", "--show-toplevel"))
            self.assertFalse(trace.exists())

    def test_object_reads_ignore_repository_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            original = run_git(root, ("hash-object", "-w", "--stdin"), b"original")
            replacement = run_git(
                root, ("hash-object", "-w", "--stdin"), b"replacement"
            )
            run_git(
                root,
                ("replace", original.decode().strip(), replacement.decode().strip()),
            )
            self.assertEqual(
                b"original",
                run_git(root, ("cat-file", "blob", original.decode().strip())),
            )

    def test_local_config_ignores_git_failures_and_invalid_encoding(self) -> None:
        with patch(
            "first_commit.git_settings.run_git",
            side_effect=(GitError("failed"), b"\xff"),
        ):
            self.assertEqual(
                {}, local_git_settings(Path("/repository"), ("one", "two"))
            )

    def test_reads_only_local_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            global_config = root / "global-config"
            global_config.write_text(
                "[user]\n\tname = Global Person\n", encoding="utf-8"
            )
            with patch.dict(
                os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}, clear=False
            ):
                values = local_git_settings(root, ("user.name",))

        self.assertEqual({}, values)

    def test_failure_does_not_forward_git_output(self) -> None:
        canary = b"private-git-error-canary"
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=1, stdout=canary, stderr=canary
        )

        with patch("first_commit.git.subprocess.run", return_value=completed):
            with self.assertRaises(GitError) as context:
                run_git(Path(), ("status",))

        self.assertNotIn(canary.decode(), str(context.exception))

    def test_arguments_are_passed_without_a_shell(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout=b"ok", stderr=b""
        )

        with patch("first_commit.git.subprocess.run", return_value=completed) as call:
            result = run_git(Path("repository"), ("show", "value;uname"))

        self.assertEqual(b"ok", result)
        arguments = call.call_args.args[0]
        self.assertEqual("value;uname", arguments[-1])
        self.assertNotIn("shell", call.call_args.kwargs)

    def test_repository_selection_environment_is_removed(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout=b"ok", stderr=b""
        )
        environment = {
            "PATH": "/usr/bin",
            "GIT_DIR": "/private/repository",
            "GIT_WORK_TREE": "/private/worktree",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.hooksPath",
            "GIT_CONFIG_VALUE_0": "/private/hooks",
            "GIT_CONFIG_PARAMETERS": "'user.name=Injected'",
            "GIT_CONFIG_GLOBAL": "/private/config",
            "GIT_CONFIG_SYSTEM": "/private/system-config",
            "GIT_CONFIG": "/private/legacy-config",
            "GIT_REPLACE_REF_BASE": "refs/private/",
            "GIT_NAMESPACE": "private",
            "GIT_TRACE": "/private/trace",
            "GIT_TRACE2_EVENT": "/private/events",
            "GIT_CURL_VERBOSE": "1",
        }

        with patch.dict(os.environ, environment, clear=True):
            with patch(
                "first_commit.git.subprocess.run", return_value=completed
            ) as call:
                run_git(Path("repository"), ("status",))

        selected = call.call_args.kwargs["env"]
        self.assertEqual(120, call.call_args.kwargs["timeout"])
        self.assertEqual("/usr/bin", selected["PATH"])
        for key in environment:
            if key != "PATH":
                self.assertNotIn(key, selected)

    def test_git_environment_disables_interactive_credentials(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout=b"ok", stderr=b""
        )
        with patch.dict(
            os.environ,
            {"GIT_TERMINAL_PROMPT": "1", "GCM_INTERACTIVE": "always"},
            clear=False,
        ):
            with patch(
                "first_commit.git.subprocess.run", return_value=completed
            ) as call:
                run_git(Path("repository"), ("status",))

        selected = call.call_args.kwargs["env"]
        self.assertEqual("0", selected["GIT_TERMINAL_PROMPT"])
        self.assertEqual("Never", selected["GCM_INTERACTIVE"])
        self.assertEqual("1", selected["GIT_NO_LAZY_FETCH"])


class GitPathTest(TemporaryRootTest):
    def test_only_the_final_newline_is_removed(self) -> None:
        self.assertEqual(Path("/work /x "), git_path(self.root, b"/work /x \n"))
        self.assertEqual(self.root / ".git/hooks", git_path(self.root, b".git/hooks\n"))
        with self.assertRaises(GitError):
            git_path(self.root, b"/work/\xff\n")

    def test_a_folder_name_ending_in_a_space_works(self) -> None:
        folder = self.root / "work "
        folder.mkdir()
        initialize_repository(folder)
        self.assertEqual(folder.resolve(), repository_root(str(folder)))
        self.assertTrue(_repository_exists(folder.resolve()))
        self.assertEqual(
            ["hooks.missing"] * 3, [item.rule_id for item in hook_findings(folder)]
        )


# git commit -a and git commit <path> name a temporary index in GIT_INDEX_FILE.
class CommitIndexTest(TemporaryRootTest):
    def repository(self, name: str) -> Path:
        root = self.root / name
        root.mkdir()
        initialize_repository(root)
        for path in REQUIRED_DOCUMENTS:
            (root / path).write_text("# Reviewed\n", encoding="utf-8")
        (root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        (root / ".repo-policy.json").write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
        # A fake scanner runs from PATH: the hook process checks the digest of a
        # .local/bin/gitleaks, and a test patch cannot reach that process.
        scanner = self.root / "scanner-bin/gitleaks"
        scanner.parent.mkdir(exist_ok=True)
        scanner.write_text(PASSING_SCANNER, encoding="utf-8")
        scanner.chmod(0o755)
        commit_fixture(root, *REQUIRED_DOCUMENTS, ".gitignore", ".repo-policy.json")
        hook = root / ".git/hooks/pre-commit"
        hook.write_text(
            "#!/bin/sh\n"
            f"PYTHONPATH={shlex.quote(str(PROJECT / 'src'))} exec "
            f"{shlex.quote(sys.executable)} -m first_commit.cli hook pre-commit\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        return root

    def scanner_path(self) -> str:
        return os.pathsep.join((str(self.root / "scanner-bin"), "/usr/bin", "/bin"))

    def commit(
        self, readme: bytes, arguments: tuple[str, ...], index: str | None = None
    ) -> tuple[int, str]:
        root = self.repository(str(len(list(self.root.iterdir()))))
        (root / "README.md").write_bytes(readme)
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        environment.update(
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
            PATH=self.scanner_path(),
        )
        if index is not None:
            shutil.copyfile(root / ".git/index", root / index)
            environment[INDEX_VARIABLE] = index
            subprocess.run(
                ["git", "add", "README.md"], cwd=root, env=environment, check=True
            )
        result = subprocess.run(
            ["git", "commit", "-q", "-m", "feat: change readme", *arguments],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return result.returncode, result.stdout + result.stderr

    def test_unstaged_defect_blocks_commit_all_and_commit_path(self) -> None:
        for arguments in COMMIT_FORMS:
            with self.subTest(arguments=arguments):
                code, output = self.commit(b"# Reviewed\x7fdefect\n", arguments)
                self.assertEqual(1, code, output)
                self.assertIn(CONTROL_CHARACTER, output)

    def test_clean_change_passes_commit_all_and_commit_path(self) -> None:
        for arguments in COMMIT_FORMS:
            with self.subTest(arguments=arguments):
                code, output = self.commit(b"# Reviewed again\n", arguments)
                self.assertEqual(0, code, output)
                self.assertIn("PASS staged", output)

    def test_defect_in_a_named_index_inside_the_git_folder_blocks(self) -> None:
        code, output = self.commit(b"# Reviewed\x7fdefect\n", (), ".git/alt-index")
        self.assertEqual(1, code, output)
        self.assertIn(CONTROL_CHARACTER, output)

    def test_named_index_outside_the_git_folder_blocks(self) -> None:
        outside = str(self.root / "outside-index")
        code, output = self.commit(b"# Reviewed\x7fdefect\n", (), outside)
        self.assertNotEqual(0, code, output)
        self.assertIn(INDEX_VARIABLE, output)
        self.assertNotIn("PASS staged", output)
        self.assertNotIn(outside, output)

    def run_cli(
        self, cwd: Path, arguments: tuple[str, ...], index: str
    ) -> tuple[int, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        environment.update(
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
            PYTHONPATH=str(PROJECT / "src"),
            PATH=self.scanner_path(),
        )
        environment[INDEX_VARIABLE] = index
        result = subprocess.run(
            [sys.executable, "-m", "first_commit.cli", *arguments],
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return result.returncode, result.stdout + result.stderr

    def test_hook_from_a_subfolder_resolves_a_relative_index_at_the_top(self) -> None:
        root = self.repository("subfolder-run")
        subfolder = root / "docs"
        subfolder.mkdir()
        code, output = self.run_cli(subfolder, ("hook", "pre-commit"), ".git/index")
        self.assertEqual(0, code, output)
        self.assertIn("PASS staged", output)

    def test_refusal_names_the_command_and_the_default_index(self) -> None:
        root = self.repository("refusal")
        outside = str(self.root / "outside-index")
        for arguments in (("hook", "pre-commit"), ("hook", "pre-push"), ("check",)):
            with self.subTest(arguments=arguments):
                code, output = self.run_cli(root, arguments, outside)
                self.assertEqual(4, code, output)
                self.assertIn(
                    f"The first-commit {' '.join(arguments)} command refused to run",
                    output,
                )
                self.assertIn(f"Unsetting {INDEX_VARIABLE} makes Git use", output)
                self.assertIn(".git/index", output)
                self.assertNotIn(outside, output)


class IndexFileEnvironmentTest(TemporaryRootTest):
    def kept(
        self, root: Path, value: str, environment: dict[str, str] | None = None
    ) -> str | None:
        selected = sanitized_git_environment(
            {**(environment or os.environ), INDEX_VARIABLE: value}, root
        )
        return selected.get(INDEX_VARIABLE)

    def test_index_file_inside_the_git_folder_is_kept(self) -> None:
        initialize_repository(self.root)
        git_folder = (self.root / ".git").resolve()
        for name in ("index.lock", "next-index-123.lock"):
            with self.subTest(name=name):
                value = str(git_folder / name)
                self.assertEqual(value, self.kept(self.root, value))

    def test_relative_index_file_resolves_against_the_root(self) -> None:
        initialize_repository(self.root)
        git_folder = (self.root / ".git").resolve()
        for name in ("index", "alt-index"):
            with self.subTest(name=name):
                expected = str(git_folder / name)
                self.assertEqual(expected, self.kept(self.root, f".git/{name}"))

    def test_git_folder_with_line_separator_characters_is_found(self) -> None:
        root = self.root / f"line{chr(0x2028)}separator\x1cfolder"
        root.mkdir()
        initialize_repository(root)
        value = str((root / ".git").resolve() / "index.lock")
        self.assertEqual(value, self.kept(root, value))
        prefix = str(self.root.resolve() / "line" / "index")
        with self.assertRaisesRegex(GitError, INDEX_VARIABLE):
            self.kept(root, prefix)

    def test_failed_folder_lookup_is_not_cached_and_uses_the_given_path(self) -> None:
        value = str(self.root.resolve() / ".git/index.lock")
        with self.assertRaisesRegex(GitError, INDEX_VARIABLE):
            self.kept(self.root, value)
        initialize_repository(self.root)
        without_git = {"PATH": str(self.root / "no-tools")}
        fresh = self.root / "fresh"
        fresh.mkdir()
        initialize_repository(fresh)
        fresh_value = str((fresh / ".git").resolve() / "index.lock")
        with self.assertRaisesRegex(GitError, INDEX_VARIABLE):
            self.kept(fresh, fresh_value, without_git)
        self.assertEqual(value, self.kept(self.root, value))
        self.assertEqual(fresh_value, self.kept(fresh, fresh_value))

    def test_git_folder_path_that_is_not_utf8_is_found(self) -> None:
        folder = b"/repository/\xff/.git"
        with patch("first_commit.git._execute", return_value=folder + b"\n" + folder):
            found = _git_folders(Path("/repository-not-utf8"), {})
        self.assertEqual(2, len(found))
        self.assertTrue(all(os.fsencode(path).endswith(b"\xff/.git") for path in found))

    def test_index_file_in_a_worktree_or_its_common_git_folder_is_kept(self) -> None:
        main = self.root / "main"
        main.mkdir()
        initialize_repository(main)
        (main / "file.txt").write_text("one\n", encoding="utf-8")
        commit_fixture(main, "file.txt")
        linked = self.root / "linked"
        fixture_git(main, "worktree", "add", "-q", str(linked))
        common = (main / ".git").resolve()
        for value in (common / "worktrees/linked/index.lock", common / "index"):
            with self.subTest(value=value):
                self.assertEqual(str(value), self.kept(linked, str(value)))

    def test_index_file_outside_the_git_folder_is_refused(self) -> None:
        initialize_repository(self.root)
        git_folder = (self.root / ".git").resolve()
        outside = self.root / "outside-index"
        outside.write_bytes(b"")
        link = git_folder / "linked-index"
        link.symlink_to(outside)
        for value in (
            str(outside),
            "/private/index",
            "index.lock",
            ".git/../outside-index",
            str(git_folder / ".." / "outside-index"),
            str(link),
            str(git_folder),
            "",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(GitError, INDEX_VARIABLE) as context:
                    self.kept(self.root, value)
                if value:
                    self.assertNotIn(value, str(context.exception))

    def test_staged_scan_reads_the_commit_index_only(self) -> None:
        initialize_repository(self.root)
        log = self.root / "index-log"
        executable = self.root / "gitleaks"
        executable.write_text(INDEX_LOGGING_SCANNER, encoding="utf-8")
        executable.chmod(0o755)
        inside = str((self.root / ".git").resolve() / "index.lock")
        environment = {"FIRST_COMMIT_TEST_LOG": str(log), "PATH": os.environ["PATH"]}
        scan_staged(
            self.root,
            max_findings=1,
            executable=str(executable),
            environment={**environment, INDEX_VARIABLE: inside},
        )
        self.assertEqual(inside, log.read_text("utf-8").splitlines()[-1])
        with self.assertRaisesRegex(GitError, INDEX_VARIABLE):
            scan_staged(
                self.root,
                max_findings=1,
                executable=str(executable),
                environment={**environment, INDEX_VARIABLE: "/private/index"},
            )

    def test_index_file_is_refused_without_a_repository(self) -> None:
        with self.assertRaisesRegex(GitError, INDEX_VARIABLE):
            self.kept(self.root, str(self.root / ".git/index"))

    def test_index_file_is_removed_when_no_repository_is_named(self) -> None:
        selected = sanitized_git_environment({INDEX_VARIABLE: "/private/index"})
        self.assertNotIn(INDEX_VARIABLE, selected)


if __name__ == "__main__":
    unittest.main()
