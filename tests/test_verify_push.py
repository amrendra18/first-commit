import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_verify_script import core, harness

push_journey = harness("push_journey")
HOOK = f"""#!/bin/sh
lines=$(cat)
printf 'call %s %s\\n%s\\n' "$1" "$2" "$lines" >> "$0.log"
case "$lines" in
  *refs/heads/second*) echo 'secrets.gitleaks "second-secret.txt"'; exit 1 ;;
  "refs/heads/main "*" {"0" * 40}") ;;
  "refs/heads/main "*)
    pushed=$(echo "$lines" | cut -d ' ' -f 2)
    if [ "$(git log -1 --format=%ct "$pushed")" -lt 1000000000 ]; then
      echo '{core.PUSH_HOOK}.....Passed'
      exit 0
    fi
    commit=$(echo "$pushed" | cut -c 1-12)
    echo 'git.unsigned-commit ".git": Commit '"$commit"' has no signature.'
    exit 1 ;;
esac
echo '{core.PUSH_HOOK}.....Passed'
"""


def _git(project: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=project, capture_output=True, text=True, check=True
    ).stdout.strip()


class VerifyPushTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        (self.work / "home").mkdir()
        self.project = self.work / "project"
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.work / "home"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Verify",
            "GIT_AUTHOR_EMAIL": "verify@example.com",
            "GIT_COMMITTER_NAME": "Verify",
            "GIT_COMMITTER_EMAIL": "verify@example.com",
        }
        subprocess.run(
            ["git", "init", "-q", "-b", "main", str(self.project)], env=env, check=True
        )
        (self.project / "README.md").write_text("project\n", "utf-8")
        subprocess.run(
            ["git", "add", "README.md"], cwd=self.project, env=env, check=True
        )
        subprocess.run(
            ["git", "commit", "-q", "--no-gpg-sign", "-m", "feat: start"],
            cwd=self.project,
            env=env,
            check=True,
        )
        self.hook = self.project / ".git/hooks/pre-push"
        self.hook.write_text(HOOK, "utf-8")
        self.hook.chmod(0o755)
        self.run_state = core.Run(work=self.work, python="python3", environment=env)
        self.run_state.project = self.project

    def test_git_push_runs_the_hook_for_main_and_for_both_new_branches(self) -> None:
        observed = push_journey.feature_push(self.run_state)

        head = _git(self.project, "rev-parse", "HEAD^")
        older = _git(self.project, "rev-parse", "HEAD")
        remote = self.work / "remote.git"
        calls = self.hook.with_name("pre-push.log").read_text("utf-8").split("call ")
        self.assertEqual(5, len(calls))
        first, unsigned, pushed_older, second = (
            call.splitlines() for call in calls[1:]
        )
        self.assertEqual(f"origin {remote}", first[0])
        self.assertEqual(
            [f"refs/heads/main {head} refs/heads/main {'0' * 40}"], first[1:]
        )
        self.assertEqual(["refs/heads/main", head], unsigned[1].split()[2:])
        self.assertEqual(
            [f"refs/heads/main {older} refs/heads/main {head}"], pushed_older[1:]
        )
        self.assertEqual(f"origin {remote}", second[0])
        self.assertEqual(
            ["refs/heads/first", "refs/heads/second"],
            [line.split()[0] for line in second[1:]],
        )
        self.assertEqual(
            [
                "the stash holds a token",
                "git push of main to a local bare remote exited 0",
                f"Git ran the pre-push hook, which printed '{core.PUSH_HOOK}' Passed",
                "the bare remote holds main",
                "git push of main with a commit made with --no-gpg-sign exited 1",
                "git.unsigned-commit named the unsigned commit's short id",
                "the bare remote's main stayed at the last signed commit",
                "git push of main with an unsigned commit older than the setup exited 0",
                "the bare remote's main is the older unsigned commit",
                (
                    "git push of two new branches: first (clean), then second (a "
                    "commit holding a token) exited 1"
                ),
                "secrets.gitleaks reported second-secret.txt",
                "the bare remote received neither branch",
            ],
            observed,
        )
        self.assertEqual("", _git(self.project, "remote"))
        self.assertEqual(
            "main", _git(self.project, "branch", "--format=%(refname:short)")
        )
        self.assertEqual("", _git(self.project, "stash", "list"))

    def test_a_hook_that_blocks_main_fails_the_feature(self) -> None:
        self.hook.write_text("#!/bin/sh\nexit 1\n", "utf-8")
        with self.assertRaisesRegex(
            core.FeatureFailedError,
            "git push of main to a local bare remote exited 1, expected 0",
        ):
            push_journey.feature_push(self.run_state)
        self.assertEqual("", _git(self.project, "remote"))


if __name__ == "__main__":
    unittest.main()
