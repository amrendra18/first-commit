import re
import shlex
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from first_commit.candidates import CandidateError
from first_commit.git import GitError
from first_commit.models import Finding
from first_commit.pushed import PushedScope
from first_commit.pushed_signatures import unsigned_commit_findings
from tests.gitleaks_support import (
    history_cli,
    needs_real_scanner,
    pushed_base_commit,
)
from tests.support import (
    TemporaryRootTest,
    commit_message,
    initialize_repository,
    run_git,
)

RULE = "git.unsigned-commit"
FIX_COMMAND = re.compile(r"git rebase --force-rebase --gpg-sign [0-9a-f]{12}\^")
AMEND_FIX = "git commit --amend --no-edit --gpg-sign"
ROOT_FIX = "git rebase --force-rebase --gpg-sign --root"


def _head(root: Path) -> str:
    return run_git(root, "rev-parse", "HEAD").stdout.decode().strip()


def _commit(root: Path, subject: str, *options: str) -> str:
    run_git(
        root,
        "commit",
        "-q",
        "--allow-empty",
        "--no-verify",
        *options,
        "-m",
        commit_message(subject),
    )
    return _head(root)


def _signed(root: Path, commit: str) -> bool:
    header = run_git(root, "cat-file", "commit", commit).stdout.partition(b"\n\n")[0]
    return any(line.startswith(b"gpgsig") for line in header.split(b"\n"))


def _rebase(root: Path, command: str) -> None:
    run_git(root, *shlex.split(command)[1:])


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is unavailable")
class PushedSignatureTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        self.keys = self.root / "keys"
        self.keys.mkdir()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        subprocess.run(
            [
                *("ssh-keygen", "-q", "-t", "ed25519", "-N", ""),
                *("-C", "scratch key", "-f", str(self.keys / "id_ed25519")),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )

    def sign_commits(self) -> None:
        for key, value in (
            ("gpg.format", "ssh"),
            ("user.signingkey", str(self.keys / "id_ed25519")),
            ("commit.gpgsign", "true"),
        ):
            run_git(self.repository, "config", key, value)

    def run_hook(self) -> tuple[int, str]:
        environment = {
            "PRE_COMMIT_TO_REF": _head(self.repository),
            "PRE_COMMIT_REMOTE_NAME": "origin",
        }
        return history_cli(self.repository, ("hook", "pre-push"), environment)

    def merge_side_branch(self, *options: str) -> str:
        run_git(self.repository, "branch", "side")
        _commit(self.repository, "feat: main work")
        run_git(self.repository, "switch", "-q", "side")
        _commit(self.repository, "feat: side work")
        run_git(self.repository, "switch", "-q", "main")
        run_git(self.repository, "merge", "-q", "--no-edit", *options, "side")
        # A local branch would keep the old commits in the push range after a rebase.
        run_git(self.repository, "branch", "-q", "-d", "side")
        return _head(self.repository)

    @needs_real_scanner
    def test_unsigned_pushed_commit_is_reported(self) -> None:
        pushed_base_commit(self.repository)
        self.sign_commits()
        signed = _commit(self.repository, "feat: signed")
        unsigned = _commit(self.repository, "feat: unsigned", "--no-gpg-sign")
        merge = self.merge_side_branch("--no-gpg-sign")

        code, output = self.run_hook()

        self.assertEqual(1, code, output)
        reported = re.findall(
            rf'^{RULE} "\.git": Commit ([0-9a-f]+) ', output, re.MULTILINE
        )
        self.assertEqual([unsigned[:12], merge[:12]], reported)
        self.assertNotIn(signed[:12], output)
        # A merge follows the first one, so the fix leaves its re-creation to the
        # person: a rebase would flatten the merge.
        self.assertIn("After a merge, re-create those commits by hand", output)

    @needs_real_scanner
    def test_the_printed_rebase_re_signs_a_history_without_merges(self) -> None:
        pushed_base_commit(self.repository)
        self.sign_commits()
        unsigned = _commit(self.repository, "feat: unsigned", "--no-gpg-sign")
        _commit(self.repository, "feat: signed")

        code, output = self.run_hook()

        self.assertEqual(1, code, output)
        (command,) = FIX_COMMAND.findall(output)
        self.assertTrue(command.endswith(f" {unsigned[:12]}^"))
        _rebase(self.repository, command)
        code, output = self.run_hook()
        self.assertEqual(0, code, output)
        new = run_git(self.repository, "rev-list", "main", "--not", "origin/main")
        commits = new.stdout.decode().split()
        self.assertEqual(2, len(commits))
        self.assertTrue(all(_signed(self.repository, item) for item in commits))

    @needs_real_scanner
    def test_the_printed_amend_signs_the_newest_commit(self) -> None:
        pushed_base_commit(self.repository)
        self.sign_commits()
        # An amend of an empty commit needs --allow-empty; a real commit has a change.
        (self.repository / "change.txt").write_text("change\n", "utf-8")
        run_git(self.repository, "add", "change.txt")
        _commit(self.repository, "feat: unsigned", "--no-gpg-sign")

        code, output = self.run_hook()

        self.assertEqual(1, code, output)
        self.assertIn(AMEND_FIX, output)
        _rebase(self.repository, AMEND_FIX)
        self.assertTrue(_signed(self.repository, _head(self.repository)))
        self.assertEqual(0, self.run_hook()[0])

    @needs_real_scanner
    def test_an_unsigned_commit_on_a_second_pushed_branch_is_reported(self) -> None:
        # pre-commit names only the first ref of `git push origin alpha beta`.
        pushed_base_commit(self.repository)
        self.sign_commits()
        _commit(self.repository, "feat: alpha")
        run_git(self.repository, "branch", "-q", "alpha")
        run_git(self.repository, "switch", "-q", "-c", "beta")
        unsigned = _commit(self.repository, "feat: beta", "--no-gpg-sign")
        run_git(self.repository, "switch", "-q", "alpha")

        code, output = self.run_hook()

        self.assertEqual(1, code, output)
        self.assertIn(f'{RULE} ".git": Commit {unsigned[:12]} ', output)

    @needs_real_scanner
    def test_signed_pushed_commits_pass(self) -> None:
        pushed_base_commit(self.repository)
        self.sign_commits()
        _commit(self.repository, "feat: signed")
        merge = self.merge_side_branch()

        code, output = self.run_hook()

        self.assertTrue(_signed(self.repository, merge))
        self.assertEqual(0, code, output)
        self.assertNotIn(RULE, output)

    @needs_real_scanner
    def test_already_pushed_unsigned_commit_is_not_reported(self) -> None:
        base = pushed_base_commit(self.repository)
        on_remote = _commit(self.repository, "feat: pushed", "--no-gpg-sign")
        run_git(self.repository, "update-ref", "refs/remotes/origin/main", on_remote)
        self.sign_commits()
        _commit(self.repository, "feat: signed")

        code, output = self.run_hook()

        self.assertFalse(_signed(self.repository, base))
        self.assertEqual(0, code, output)
        self.assertNotIn(RULE, output)
        self.assertNotIn(on_remote[:12], output)

    @needs_real_scanner
    def test_the_first_push_of_a_new_repository_is_checked(self) -> None:
        # pre-commit names no pushed ref when the push holds a root commit.
        initialize_repository(self.repository)
        (self.repository / ".repo-policy.json").write_text(
            '{"schema_version":1}\n', "utf-8"
        )
        run_git(self.repository, "config", "user.email", "fixture@example.net")
        run_git(self.repository, "config", "user.name", "Fixture Person")
        self.sign_commits()
        _commit(self.repository, "feat: signed")
        unsigned = _commit(self.repository, "feat: unsigned", "--no-gpg-sign")

        code, output = history_cli(
            self.repository,
            ("hook", "pre-push"),
            {"PRE_COMMIT_REMOTE_NAME": "origin"},
        )

        self.assertEqual(1, code, output)
        self.assertIn(f'{RULE} ".git": Commit {unsigned[:12]} ', output)

    @needs_real_scanner
    def test_the_root_commit_fix_form_re_signs_the_first_commit(self) -> None:
        initialize_repository(self.repository)
        (self.repository / ".repo-policy.json").write_text(
            '{"schema_version":1}\n', "utf-8"
        )
        run_git(self.repository, "config", "user.email", "fixture@example.net")
        run_git(self.repository, "config", "user.name", "Fixture Person")
        self.sign_commits()
        first = _commit(self.repository, "feat: first", "--no-gpg-sign")

        code, output = self.run_hook()

        self.assertEqual(1, code, output)
        self.assertIn(f'{RULE} ".git": Commit {first[:12]} ', output)
        self.assertIn(ROOT_FIX, output)
        with self.assertRaises(subprocess.CalledProcessError):
            _rebase(self.repository, FIX_COMMAND.findall(output)[0])
        _rebase(self.repository, ROOT_FIX)
        self.assertTrue(_signed(self.repository, _head(self.repository)))
        self.assertEqual(0, self.run_hook()[0])


class CommitHeaderTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        initialize_repository(self.root)
        tree = run_git(self.root, "write-tree").stdout.decode().strip()
        self.header = (
            f"tree {tree}\nauthor A <a@example.net> 1 +0000\n"
            "committer A <a@example.net> 1 +0000\n"
        )

    def write_commit(self, header: str, message: str) -> str:
        written = subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            input=f"{self.header}{header}\n{message}".encode(),
            check=True,
            capture_output=True,
        )
        commit = written.stdout.decode().strip()
        run_git(self.root, "update-ref", "refs/heads/main", commit)
        return commit

    def findings(self, *, max_bytes: int = 4096) -> list[Finding]:
        scope = PushedScope(_head(self.root), None)
        return unsigned_commit_findings(
            self.root, scope, max_bytes=max_bytes, max_findings=10
        )

    def test_a_sha256_signature_header_counts_as_a_signature(self) -> None:
        self.write_commit("gpgsig-sha256 -----BEGIN SSH SIGNATURE-----\n line\n", "x\n")

        self.assertEqual([], self.findings())

    def test_a_signature_line_in_the_message_is_no_signature(self) -> None:
        commit = self.write_commit("", "gpgsig -----BEGIN SSH SIGNATURE-----\n")

        (finding,) = self.findings()
        self.assertEqual(commit[:12], finding.commit)
        self.assertEqual(f"Commit {commit[:12]} has no signature.", finding.summary)

    def test_a_commit_over_the_size_limit_stops_the_scan(self) -> None:
        self.write_commit("", "x" * 100 + "\n")

        with self.assertRaises(CandidateError):
            self.findings(max_bytes=64)

    def test_no_room_reads_no_commit(self) -> None:
        self.write_commit("", "x\n")
        scope = PushedScope(_head(self.root), None)

        with mock.patch("first_commit.git.run_git") as git:
            found = unsigned_commit_findings(
                self.root, scope, max_bytes=4096, max_findings=0
            )

        self.assertEqual([], found)
        git.assert_not_called()

    def test_a_push_of_commits_the_remote_has_reads_no_commit(self) -> None:
        head = self.write_commit("", "x\n")
        run_git(self.root, "remote", "add", "origin", "https://example.invalid/o")
        run_git(self.root, "update-ref", "refs/remotes/origin/main", head)

        with mock.patch("first_commit.pushed_signatures.cat_file_objects") as read:
            found = unsigned_commit_findings(
                self.root, PushedScope(head, "origin"), max_bytes=4096, max_findings=10
            )

        self.assertEqual([], found)
        read.assert_not_called()

    def child(self, parent: str, message: str, ref: str) -> str:
        tree = run_git(self.root, "write-tree").stdout.decode().strip()
        written = subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            input=(
                f"tree {tree}\nparent {parent}\nauthor A <a@example.net> 1 +0000\n"
                f"committer A <a@example.net> 1 +0000\n\n{message}"
            ).encode(),
            check=True,
            capture_output=True,
        )
        commit = written.stdout.decode().strip()
        run_git(self.root, "update-ref", ref, commit)
        return commit

    def test_history_another_configured_remote_holds_is_not_reported(self) -> None:
        # Another remote's commits, such as a fork's upstream, are not ours to sign.
        upstream = self.write_commit("", "upstream\n")
        for remote in ("upstream", "fork"):
            run_git(self.root, "remote", "add", remote, "https://example.invalid/r")
        run_git(self.root, "update-ref", "refs/remotes/upstream/main", upstream)
        own = self.child(upstream, "own\n", "refs/heads/main")

        found = unsigned_commit_findings(
            self.root, PushedScope(own, "fork"), max_bytes=4096, max_findings=10
        )

        self.assertEqual([own[:12]], [finding.commit for finding in found])

    def test_an_unsigned_commit_on_another_local_branch_is_reported(self) -> None:
        main = self.write_commit("gpgsig-sha256 signature\n", "main\n")
        side = self.child(main, "side\n", "refs/heads/side")

        found = unsigned_commit_findings(
            self.root, PushedScope(main, None), max_bytes=4096, max_findings=10
        )

        self.assertEqual([side[:12]], [finding.commit for finding in found])

    def test_tags_and_notes_that_name_unsigned_commits_are_not_read(self) -> None:
        # The remote may hold a tag already, and a notes commit is never signed; a
        # ref of no configured remote is read, as a push may send it as a later ref.
        tagged = self.write_commit("", "tagged\n")
        run_git(self.root, "update-ref", "refs/tags/v1", tagged)
        noted = self.write_commit("", "noted\n")
        run_git(self.root, "update-ref", "refs/notes/commits", noted)
        other = self.write_commit("", "other\n")
        run_git(self.root, "update-ref", "refs/remotes/private/feature", other)
        main = self.write_commit("gpgsig-sha256 signature\n", "main\n")

        found = unsigned_commit_findings(
            self.root, PushedScope(main, None), max_bytes=4096, max_findings=10
        )

        self.assertEqual([other[:12]], [finding.commit for finding in found])

    # One function in pushed.py chooses the signature check's commits.
    def test_the_signature_check_reads_its_own_revisions(self) -> None:
        signed = self.write_commit("gpgsig-sha256 signature\n", "main\n")
        unsigned = self.child(signed, "side\n", "refs/heads/side")
        scope = PushedScope(signed, None)

        with mock.patch(
            "first_commit.pushed_signatures.signature_revisions",
            return_value=(signed,),
        ) as revisions:
            self.assertEqual(
                [],
                unsigned_commit_findings(
                    self.root, scope, max_bytes=4096, max_findings=10
                ),
            )
        revisions.assert_called_once_with(self.root, scope)
        found = unsigned_commit_findings(
            self.root, scope, max_bytes=4096, max_findings=10
        )
        self.assertEqual([unsigned[:12]], [finding.commit for finding in found])

    def test_git_answers_that_do_not_fit_stop_the_scan(self) -> None:
        head = self.write_commit("", "x\n")
        for answers in (
            (b"not-a-commit\n",),
            (f"{head}\n".encode(), f"{head} tree 10\n".encode()),
        ):
            with (
                self.subTest(answers=answers),
                mock.patch("first_commit.git.run_git", side_effect=answers),
                self.assertRaises(GitError),
            ):
                self.findings()


if __name__ == "__main__":
    unittest.main()
