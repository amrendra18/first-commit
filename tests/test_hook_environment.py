import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from first_commit.git import sanitized_git_environment
from tests.support import initialize_repository, run_git

ROOT = Path(__file__).resolve().parents[1]
# The variables that choose which repository, index, objects or configuration Git
# uses. Git exports GIT_DIR, GIT_INDEX_FILE and GIT_PREFIX to hooks.
REPOSITORY_VARIABLES = (
    *("GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CEILING_DIRECTORIES", "GIT_COMMON_DIR"),
    *("GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR"),
    *("GIT_CONFIG_KEY_0", "GIT_CONFIG_KEY_11", "GIT_CONFIG_VALUE_0"),
    *("GIT_CONFIG_VALUE_11", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_INDEX_FILE"),
    *("GIT_NAMESPACE", "GIT_OBJECT_DIRECTORY", "GIT_PREFIX", "GIT_QUARANTINE_PATH"),
    "GIT_WORK_TREE",
)
# pre-commit exports these to the hooks it runs; a test that runs `hook pre-push`
# without its own push range would read the real push's range.
PUSH_VARIABLES = {
    "PRE_COMMIT": "1",
    "PRE_COMMIT_FROM_REF": "0" * 40,
    "PRE_COMMIT_TO_REF": "1" * 40,
    "PRE_COMMIT_REMOTE_NAME": "origin",
    "PRE_COMMIT_REMOTE_URL": "https://github.com/example/example.git",
    "PRE_COMMIT_REMOTE_BRANCH": "refs/heads/main",
    "PRE_COMMIT_LOCAL_BRANCH": "refs/heads/main",
    "PRE_COMMIT_HOME": "pre-commit-cache",
}
# Both modules write fixture commits, a remote, and a worktree. Under a pre-push
# hook, Git's exported variables would point those writes at the real repository.
FIXTURE_MODULES = ("tests.test_pushed", "tests.test_git")
PRINT_ENVIRONMENT = (
    "import json, os\n\n\n"
    "def main(arguments):\n"
    "    print(json.dumps(dict(os.environ)))\n"
    "    return 0\n"
)
HARNESS_FILES = ("__init__.py", "interpreter.py", "repository_variables.py")


def repository_values(real: Path) -> dict[str, str]:
    git_folder = real / ".git"
    values = {name: str(git_folder) for name in REPOSITORY_VARIABLES}
    values.update(
        GIT_WORK_TREE=str(real),
        GIT_INDEX_FILE=str(git_folder / "index"),
        GIT_PREFIX="",
        GIT_CONFIG_COUNT="1",
    )
    return values


# Every file in the Git folder except objects, which the push may add.
def repository_state(real: Path) -> dict[str, bytes]:
    git_folder = real / ".git"
    return {
        path.relative_to(git_folder).as_posix(): path.read_bytes()
        for path in sorted(git_folder.rglob("*"))
        if path.is_file() and path.relative_to(git_folder).parts[0] != "objects"
    }


def run_printing(command: list[str], environment: dict[str, str]) -> set[str]:
    result = subprocess.run(
        command,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return set(json.loads(result.stdout or "{}"))


class HookEnvironmentTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)
        self.real = self.scratch / "real"
        self.real.mkdir()
        initialize_repository(self.real)
        self.environment = {**os.environ, **repository_values(self.real)}

    def assert_cleared(self, names: set[str]) -> None:
        self.assertTrue(names, "the command printed no environment")
        self.assertEqual(set(), names & set(REPOSITORY_VARIABLES))

    def test_importing_the_test_package_drops_repository_variables(self) -> None:
        code = "import json, os, tests\nprint(json.dumps(dict(os.environ)))"
        self.environment["PYTHONPATH"] = f"{ROOT}{os.pathsep}{ROOT / 'src'}"
        command = [sys.executable, "-c", code]
        self.assert_cleared(run_printing(command, self.environment))

    def test_importing_the_test_package_drops_the_push_variables(self) -> None:
        code = "import json, os, tests\nprint(json.dumps(dict(os.environ)))"
        self.environment.update(PUSH_VARIABLES)
        self.environment["PYTHONPATH"] = f"{ROOT}{os.pathsep}{ROOT / 'src'}"
        names = run_printing([sys.executable, "-c", code], self.environment)
        self.assertIn("PRE_COMMIT_HOME", names)
        self.assertEqual(set(), names & (set(PUSH_VARIABLES) - {"PRE_COMMIT_HOME"}))

    def test_product_git_environment_drops_repository_variables(self) -> None:
        selected = sanitized_git_environment(repository_values(self.real))
        self.assertEqual(set(), set(selected) & set(REPOSITORY_VARIABLES))

    def test_check_scripts_drop_repository_variables_before_they_start(self) -> None:
        project = self.scratch / "project"
        output = self.scratch / "environment.json"
        printer = f"#!/bin/sh\nenv -0 > {shlex.quote(str(output))}\nexit 1\n"
        files = {
            "scripts/check": (ROOT / "scripts/check").read_text("utf-8"),
            "scripts/check-package": (ROOT / "scripts/check-package").read_text(
                "utf-8"
            ),
            "scripts/lint": printer,
            "tools/python3": printer,
        }
        for name, content in files.items():
            path = project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            path.chmod(0o755)
        self.environment.update(
            VIRTUAL_ENV=str(self.scratch),
            PATH=f"{project / 'tools'}{os.pathsep}/usr/bin:/bin",
        )
        for script in ("scripts/check", "scripts/check-package"):
            with self.subTest(script=script):
                output.unlink(missing_ok=True)
                subprocess.run(
                    [str(project / script), "fast"],
                    env=self.environment,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                entries = output.read_bytes().split(b"\0") if output.exists() else []
                names = {entry.split(b"=", 1)[0].decode() for entry in entries if entry}
                self.assert_cleared(names)

    def test_harness_scripts_drop_repository_variables_before_they_start(self) -> None:
        project = self.scratch / "project"
        harness = project / "scripts/verify_lib"
        harness.mkdir(parents=True)
        for name in HARNESS_FILES:
            shutil.copyfile(ROOT / "scripts/verify_lib" / name, harness / name)
        for name in ("cli.py", "rehearsal.py"):
            (harness / name).write_text(PRINT_ENVIRONMENT, encoding="utf-8")
        for script in ("scripts/verify", "scripts/ci-local"):
            with self.subTest(script=script):
                shutil.copyfile(ROOT / script, project / script)
                command = [sys.executable, str(project / script)]
                self.assert_cleared(run_printing(command, self.environment))

    def test_a_pre_push_hook_that_runs_tests_leaves_the_repository_unchanged(
        self,
    ) -> None:
        run_git(self.real, "config", "user.name", "Fixture Author")
        run_git(self.real, "config", "user.email", "fixture@example.invalid")
        (self.real / "README.md").write_text("fixture\n", encoding="utf-8")
        run_git(self.real, "add", "README.md")
        run_git(self.real, "commit", "-q", "-m", "Add the fixture file")
        remote = self.scratch / "remote.git"
        linked = self.scratch / "linked"
        hook_folder = self.scratch / "hook"
        hook_folder.mkdir()
        run_git(self.scratch, "init", "-q", "--bare", str(remote))
        run_git(self.real, "worktree", "add", "-q", "-b", "feature", str(linked))
        python_path = shlex.quote(f"{ROOT}{os.pathsep}{ROOT / 'src'}")
        hook = self.real / ".git/hooks/pre-push"
        hook.write_text(
            f"#!/bin/sh\ncd {shlex.quote(str(hook_folder))} || exit 1\n"
            f"PYTHONPATH={python_path} exec {shlex.quote(sys.executable)} "
            f"-m unittest -q {' '.join(FIXTURE_MODULES)}\n",
            encoding="utf-8",
        )
        hook.chmod(0o755)
        before = repository_state(self.real)

        # A push to a path, not a remote name, updates no remote-tracking branch.
        result = subprocess.run(
            ["git", "-C", str(linked), "push", "-q", str(remote), "HEAD:feature"],
            env=dict(os.environ),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

        self.assertEqual(before, repository_state(self.real))
        self.assertEqual(0, result.returncode, result.stderr[-3000:])


if __name__ == "__main__":
    unittest.main()
