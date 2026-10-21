import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import yaml

from tests.support import initialize_repository, run_git

ROOT = Path(__file__).resolve().parents[1]
HOOKS = {
    hook["id"]: hook["entry"].split()
    for repository in yaml.safe_load(
        (ROOT / ".pre-commit-config.yaml").read_text("utf-8")
    )["repos"]
    for hook in repository["hooks"]
}
# A stand-in for the script a push hook runs: logs where it ran, with what, and
# which checkout and index its Git commands see, appends to the tree's evidence
# folder, then exits with the code in its own tree's status file. A tree whose
# status is "wait" sleeps.
STUB = (
    "#!/bin/bash\n"
    'tree="$(cd "$(dirname "$0")/.." && pwd)"\n'
    'scanner="$(cat "$tree/.local/bin/gitleaks" 2>/dev/null || true)"\n'
    'top="$(git rev-parse --show-toplevel)"\n'
    'index="$(git rev-parse --path-format=absolute --git-path index)"\n'
    'printf \'%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\\n\' "$tree" "$*" "${PRE_COMMIT:-}" '
    '"${VIRTUAL_ENV:-}" "$PATH" "${FIRST_COMMIT_VERIFY_PYTHON:-}" "$scanner" '
    '"$PWD" "$top" "$index" >> "$CHECK_LOG"\n'
    'mkdir -p "$tree/.local/verify"\n'
    'printf \'%s\\n\' "$*" >> "$tree/.local/verify/summary.md"\n'
    'status="$(cat "$tree/status")"\n'
    'if [[ "$status" == wait ]]; then touch "$CHECK_LOG.started"; sleep 30; fi\n'
    'exit "$status"\n'
)


class PushHookHarness(unittest.TestCase):
    hook = ""
    script = ""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "project"
        self.log = Path(temporary.name) / "check.log"
        (self.root / "scripts").mkdir(parents=True)
        self.entry = HOOKS[self.hook]
        if self.entry[0] != self.script:
            shutil.copy2(ROOT / self.entry[0], self.root / self.entry[0])
        stub = self.root / self.script
        stub.write_text(STUB, encoding="utf-8")
        stub.chmod(0o755)
        (self.root / ".gitignore").write_text(".venv/\n.local/\n", encoding="utf-8")
        initialize_repository(self.root)

    def commit(self, status: str) -> str:
        (self.root / "status").write_text(status + "\n", encoding="utf-8")
        run_git(self.root, "add", "-A")
        run_git(
            self.root,
            "-c",
            "user.name=Gate Test",
            "-c",
            "user.email=gate@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "status " + status,
        )
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def environment(self, pushed: str, **variables: str) -> dict[str, str]:
        environment = {**os.environ}
        environment.pop("VIRTUAL_ENV", None)
        environment.pop("FIRST_COMMIT_VERIFY_PYTHON", None)
        return {
            **environment,
            "CHECK_LOG": str(self.log),
            "PRE_COMMIT": "1",
            "PRE_COMMIT_TO_REF": pushed,
            **variables,
        }

    def push_gate(self, pushed: str, **variables: str) -> tuple[int, list[list[str]]]:
        result = subprocess.run(
            [str(self.root / self.entry[0]), *self.entry[1:]],
            cwd=self.root,
            env=self.environment(pushed, **variables),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return result.returncode, self.runs()

    def runs(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [line.split("|") for line in self.log.read_text("utf-8").splitlines()]

    def assert_no_worktree_left(self, runs: list[list[str]]) -> None:
        listed = run_git(self.root, "worktree", "list", "--porcelain").stdout.decode()
        self.assertEqual(1, listed.count("worktree "), listed)
        for run in runs:
            self.assertFalse(run[0] != str(self.root) and Path(run[0]).exists())


class PushedCommitGateTest(PushHookHarness):
    hook = "project-quality"
    script = "scripts/check"

    def test_a_failing_commit_blocks_the_push_despite_an_uncommitted_fix(self) -> None:
        pushed = self.commit("1")
        (self.root / "status").write_text("0\n", encoding="utf-8")

        code, runs = self.push_gate(pushed)

        self.assertEqual(1, code)
        self.assertEqual(1, len(runs))
        self.assertNotEqual(str(self.root), runs[0][0])
        self.assertEqual("full", runs[0][1])
        self.assert_no_worktree_left(runs)

    def test_a_good_commit_passes_despite_an_uncommitted_broken_edit(self) -> None:
        pushed = self.commit("0")
        (self.root / "status").write_text("1\n", encoding="utf-8")

        code, runs = self.push_gate(pushed)

        self.assertEqual(0, code)
        self.assertNotEqual(str(self.root), runs[0][0])
        self.assert_no_worktree_left(runs)

    def test_an_untracked_file_or_another_pushed_commit_uses_a_clean_copy(
        self,
    ) -> None:
        first = self.commit("1")
        self.commit("0")
        code, runs = self.push_gate(first)
        self.assertEqual(1, code)
        self.assertNotEqual(str(self.root), runs[-1][0])

        head = self.commit("1")
        (self.root / "untracked.txt").write_text("x\n", encoding="utf-8")
        code, runs = self.push_gate(head)
        self.assertEqual(1, code)
        self.assertNotEqual(str(self.root), runs[-1][0])
        self.assert_no_worktree_left(runs)

    def test_a_clean_checkout_of_the_pushed_commit_runs_in_place(self) -> None:
        pushed = self.commit("0")
        (self.root / ".venv").mkdir()

        code, runs = self.push_gate(pushed)

        self.assertEqual(0, code)
        self.assertEqual([str(self.root), "full"], runs[0][:2])

    def test_the_clean_copy_uses_this_checkout_s_environment_and_scanner(
        self,
    ) -> None:
        pushed = self.commit("0")
        (self.root / "status").write_text("1\n", encoding="utf-8")
        (self.root / ".local/bin").mkdir(parents=True)
        (self.root / ".local/bin/gitleaks").write_text("pinned\n", encoding="utf-8")
        project = str(self.root)

        code, runs = self.push_gate(pushed, PRE_COMMIT="")
        self.assertEqual(0, code)
        _, _, pre_commit, virtual_env, path, _, scanner = runs[0][:7]
        self.assertEqual("1", pre_commit)
        self.assertEqual(f"{project}/.venv", virtual_env)
        self.assertEqual(f"{project}/.venv/bin", path.split(os.pathsep)[0])
        self.assertEqual("pinned", scanner)

        code, runs = self.push_gate(pushed, VIRTUAL_ENV="/elsewhere/venv")
        self.assertEqual(0, code)
        self.assertEqual("/elsewhere/venv", runs[-1][3])
        self.assertNotIn(f"{project}/.venv/bin", runs[-1][4].split(os.pathsep))

    def test_the_script_runs_in_the_clean_copy_despite_the_hook_s_git_variables(
        self,
    ) -> None:
        pushed = self.commit("0")
        (self.root / "status").write_text("1\n", encoding="utf-8")
        index = self.root / ".git/index"
        staged = run_git(self.root, "ls-files", "--stage").stdout

        code, runs = self.push_gate(
            pushed,
            GIT_DIR=str(self.root / ".git"),
            GIT_WORK_TREE=str(self.root),
            GIT_INDEX_FILE=str(index),
        )

        self.assertEqual(0, code)
        tree, pwd, top, used_index = (Path(runs[0][i]).resolve() for i in (0, 7, 8, 9))
        self.assertNotEqual(self.root, tree)
        self.assertEqual([tree, tree], [pwd, top])
        self.assertNotEqual(index, used_index)
        self.assertEqual(staged, run_git(self.root, "ls-files", "--stage").stdout)
        self.assert_no_worktree_left(runs)

    def push_tracked_local(self) -> tuple[int, list[list[str]]]:
        local = self.root / ".local"
        run_git(self.root, "add", "-f", ".local")
        pushed = self.commit("0")
        if local.is_symlink():
            local.unlink()
        else:
            shutil.rmtree(local)
        self.commit("0")
        return self.push_gate(pushed)

    def test_a_pushed_commit_that_tracks_local_as_a_link_is_refused(self) -> None:
        outside = self.root.parent / "outside"
        outside.mkdir()
        (self.root / ".local").symlink_to(outside)

        code, runs = self.push_tracked_local()

        self.assertEqual(1, code)
        self.assertEqual([], runs)
        self.assertEqual([], list(outside.iterdir()))
        self.assert_no_worktree_left(runs)

    def test_a_pushed_commit_that_tracks_a_local_folder_is_refused(self) -> None:
        (self.root / ".local").mkdir()
        (self.root / ".local/kept").write_text("x\n", encoding="utf-8")

        code, runs = self.push_tracked_local()

        self.assertEqual(1, code)
        self.assertEqual([], runs)
        self.assert_no_worktree_left(runs)

    def test_another_stale_worktree_is_left_registered(self) -> None:
        pushed = self.commit("0")
        self.commit("1")
        stale = self.root.parent / "stale"
        run_git(self.root, "worktree", "add", "-q", "--detach", str(stale))
        shutil.rmtree(stale)

        code, _ = self.push_gate(pushed)

        self.assertEqual(0, code)
        listed = run_git(self.root, "worktree", "list", "--porcelain").stdout.decode()
        self.assertIn(f"worktree {stale}\n", listed)
        self.assertEqual(2, listed.count("worktree "), listed)

    def test_an_interrupted_check_still_removes_the_clean_copy(self) -> None:
        pushed = self.commit("wait")
        (self.root / "status").write_text("0\n", encoding="utf-8")
        for stop in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(stop=stop):
                started = Path(f"{self.log}.started")
                started.unlink(missing_ok=True)
                with subprocess.Popen(
                    [str(self.root / self.entry[0]), *self.entry[1:]],
                    cwd=self.root,
                    env=self.environment(pushed),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                ) as process:
                    deadline = time.monotonic() + 30
                    while process.poll() is None and not started.exists():
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.05)
                    if process.poll() is None:
                        os.killpg(process.pid, stop)
                    code = process.wait(timeout=30)

                self.assertNotEqual(0, code)
                self.assert_no_worktree_left(self.runs())

    def test_a_pushed_value_that_is_not_a_commit_id_is_refused(self) -> None:
        self.commit("0")

        code, runs = self.push_gate("--help")

        self.assertEqual(2, code)
        self.assertEqual([], runs)

    def test_the_all_zero_id_of_a_deleted_ref_is_refused(self) -> None:
        self.commit("0")
        for zeros in ("0" * 40, "0" * 64):
            with self.subTest(length=len(zeros)):
                result = subprocess.run(
                    [str(self.root / self.entry[0]), *self.entry[1:]],
                    cwd=self.root,
                    env=self.environment(zeros),
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

                self.assertEqual(2, result.returncode)
                self.assertIn("all zeros", result.stderr)
                self.assertEqual([], self.runs())

    def test_a_file_hidden_from_git_status_uses_a_clean_copy(self) -> None:
        pushed = self.commit("0")
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                run_git(self.root, "update-index", f"--{flag}", "status")
                (self.root / "status").write_text("1\n", encoding="utf-8")
                status = run_git(self.root, "status", "--porcelain").stdout
                self.assertEqual(b"", status)

                code, runs = self.push_gate(pushed)

                self.assertEqual(0, code)
                self.assertNotEqual(str(self.root), runs[-1][0])
                self.assert_no_worktree_left(runs)
                run_git(self.root, "update-index", f"--no-{flag}", "status")
                run_git(self.root, "checkout", "--", "status")


class PushedCommitJourneysTest(PushHookHarness):
    hook = "project-journeys"
    script = "scripts/verify"

    def test_a_failing_commit_blocks_the_push_despite_an_uncommitted_fix(self) -> None:
        pushed = self.commit("1")
        (self.root / "status").write_text("0\n", encoding="utf-8")

        code, runs = self.push_gate(pushed)

        self.assertEqual(1, code)
        self.assertEqual(1, len(runs))
        self.assertNotEqual(str(self.root), runs[0][0])
        self.assertEqual("fast", runs[0][1])
        self.assert_no_worktree_left(runs)

    def test_a_good_commit_passes_despite_an_uncommitted_broken_edit(self) -> None:
        pushed = self.commit("0")
        (self.root / "status").write_text("1\n", encoding="utf-8")

        code, runs = self.push_gate(pushed)

        self.assertEqual(0, code)
        self.assertNotEqual(str(self.root), runs[0][0])
        self.assert_no_worktree_left(runs)

    def test_the_clean_copy_uses_this_checkout_s_python_and_keeps_its_evidence(
        self,
    ) -> None:
        pushed = self.commit("0")
        (self.root / "status").write_text("1\n", encoding="utf-8")
        (self.root / ".local/bin").mkdir(parents=True)
        (self.root / ".local/bin/gitleaks").write_text("pinned\n", encoding="utf-8")

        code, runs = self.push_gate(pushed)

        self.assertEqual(0, code)
        self.assertEqual(f"{self.root}/.venv/bin/python", runs[0][5])
        self.assertEqual("pinned", runs[0][6])
        evidence = self.root / ".local/verify/summary.md"
        self.assertEqual("fast\n", evidence.read_text("utf-8"))
        self.assert_no_worktree_left(runs)

        code, runs = self.push_gate(pushed, FIRST_COMMIT_VERIFY_PYTHON="/named/python")
        self.assertEqual(0, code)
        self.assertEqual("/named/python", runs[-1][5])


if __name__ == "__main__":
    unittest.main()
