import subprocess
import tempfile
from pathlib import Path

from first_commit.fixes import fix_for
from first_commit.gitleaks import scan_history, scan_pushed
from first_commit.gitleaks_scanner import CALIBRATION_INPUT
from first_commit.history_messages import MessageScope, history_message_findings
from first_commit.policy import parse_policy
from first_commit.pushed import PushedScope, push_revisions, pushed_scope
from first_commit.pushed_privacy import pushed_privacy_findings, pushed_versions
from first_commit.pushed_signatures import unsigned_commit_findings
from tests.gitleaks_support import commit_fixture, needs_real_scanner
from tests.support import TemporaryRootTest, initialize_repository, run_git

CANARY = "synthetic-push-set-canary"
URL = "https://example.invalid/project.git"
SIGNATURE = "git.unsigned-commit"
PRIVATE = "privacy.private-literal"
BRANCHES = 2000


def _head(root: Path) -> str:
    return run_git(root, "rev-parse", "HEAD").stdout.decode().strip()


class PushSetTest(TemporaryRootTest):
    @needs_real_scanner
    def setUp(self) -> None:
        super().setUp()
        initialize_repository(self.root)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        self.base = self.add("base.txt", "base\n")

    def add(self, path: str, text: str, message: str = "feat: add file") -> str:
        (self.root / path).write_text(text, encoding="utf-8")
        commit_fixture(self.root, path)
        if message != "feat: add file":
            run_git(self.root, "commit", "-q", "--amend", "--no-verify", "-m", message)
        return _head(self.root)

    def remote(self, name: str, target: str | None = None) -> None:
        run_git(self.root, "remote", "add", name, URL)
        if target is not None:
            run_git(self.root, "update-ref", f"refs/remotes/{name}/main", target)

    def reported(
        self, scope: PushedScope, root: Path | None = None
    ) -> dict[str, set[str]]:
        root = root or self.root
        signatures = unsigned_commit_findings(
            root, scope, max_bytes=4096, max_findings=100
        )
        files = pushed_privacy_findings(
            root,
            self.policy,
            pushed_versions(root, scope, self.policy.max_files),
            (CANARY,),
            max_findings=100,
        )
        messages = history_message_findings(
            root, self.policy, (CANARY,), MessageScope(scope), max_findings=100
        )
        self.assertTrue(all(item.pushed for item in (*signatures, *files)))
        return {
            SIGNATURE: {item.commit or "" for item in signatures},
            PRIVATE: {item.commit or "" for item in files},
            "message": {item.summary.split(":")[0][7:] for item in messages},
        }

    def test_a_private_remote_commit_pushed_to_a_new_remote_is_read(self) -> None:
        private = self.add("notes.txt", f"by {CANARY}\n", f"feat: {CANARY}")
        self.remote("origin", private)
        self.remote("public")
        new = self.add("new.txt", "new\n")

        found = self.reported(PushedScope(new, "public"))

        self.assertEqual({private[:12]}, found[PRIVATE])
        self.assertEqual({new[:12]}, found[SIGNATURE])
        self.assertEqual({private[:12]}, found["message"])
        self.assertEqual(
            {new[:12]}, self.reported(PushedScope(new, "origin"))[SIGNATURE]
        )

    def test_history_the_fork_remote_holds_is_not_read(self) -> None:
        upstream = self.add("notes.txt", f"by {CANARY}\n", f"feat: {CANARY}")
        self.remote("origin", upstream)
        self.remote("fork", upstream)
        own = self.add("own.txt", "own\n")

        found = self.reported(PushedScope(own, "fork"))

        self.assertEqual(
            {SIGNATURE: {own[:12]}, PRIVATE: set(), "message": set()}, found
        )

    def test_a_fork_push_of_fetched_upstream_commits_is_not_blocked(self) -> None:
        self.remote("origin", self.base)
        self.remote("upstream", self.base)
        run_git(self.root, "switch", "-q", "--detach")
        upstream = self.add("notes.txt", f"by {CANARY}\n")
        run_git(self.root, "update-ref", "refs/remotes/upstream/main", upstream)
        run_git(self.root, "switch", "-q", "-c", "feature", self.base)
        own = self.add("own.txt", "own\n")

        for pushed in (own, upstream):
            with self.subTest(pushed=pushed):
                found = self.reported(PushedScope(pushed, "origin"))
                self.assertEqual({own[:12]}, found[SIGNATURE])
                self.assertEqual({upstream[:12]}, found[PRIVATE])

    def test_a_ref_of_no_configured_remote_hides_nothing(self) -> None:
        self.remote("origin", self.base)
        new = self.add("notes.txt", f"by {CANARY}\n")
        run_git(self.root, "update-ref", "refs/remotes/stray/x", new)

        for remote in ("origin", "stray"):
            with self.subTest(remote=remote):
                found = self.reported(PushedScope(new, remote))
                self.assertIn(new[:12], found[SIGNATURE])
                self.assertEqual({new[:12]}, found[PRIVATE])

    def test_a_remote_with_many_branches_leaves_all_of_them_out(self) -> None:
        self.remote("origin")
        stream = []
        for number in range(BRANCHES):
            text = f"feat: {CANARY}" if number == 0 else f"feat: change {number}"
            parent = self.base if number == 0 else f":{number}"
            stream.append(
                f"commit refs/remotes/origin/b{number}\nmark :{number + 1}\n"
                f"committer A <a@example.net> {number} +0000\n"
                f"data {len(text)}\n{text}\nfrom {parent}\n\n"
            )
        subprocess.run(
            ["git", "-C", str(self.root), "fast-import", "--quiet"],
            input="".join(stream).encode(),
            check=True,
            capture_output=True,
        )
        run_git(self.root, "switch", "-q", "-C", "main", f"origin/b{BRANCHES - 1}")
        new = self.add("new.txt", "new\n")
        scope = PushedScope(new, "origin")

        revisions = push_revisions(self.root, scope)

        self.assertLess(len(" ".join(revisions)), 200)
        self.assertEqual(
            {SIGNATURE: {new[:12]}, PRIVATE: set(), "message": set()},
            self.reported(scope),
        )

    def test_a_second_pushed_ref_of_another_remote_is_read(self) -> None:
        run_git(self.root, "switch", "-q", "--detach")
        (self.root / "key.txt").write_bytes(CALIBRATION_INPUT)
        run_git(self.root, "add", "--", "key.txt")
        feature = self.add("notes.txt", f"by {CANARY}\n", f"feat: {CANARY}")
        run_git(self.root, "switch", "-q", "main")
        self.remote("private", self.base)
        run_git(self.root, "update-ref", "refs/remotes/private/feature", feature)
        self.remote("public")
        scope = PushedScope(self.base, "public")

        found = self.reported(scope)
        (secret,) = scan_pushed(self.root, scope, max_findings=10)

        self.assertNotIn(feature[:12], found[SIGNATURE])
        self.assertEqual({feature[:12]}, found[PRIVATE])
        self.assertEqual({feature[:12]}, found["message"])
        self.assertEqual(feature[:12], secret.commit)

    def test_a_tag_the_remote_holds_does_not_block_a_push(self) -> None:
        run_git(self.root, "switch", "-q", "-c", "release")
        tagged = self.add("notes.txt", f"by {CANARY}\n", f"chore: {CANARY}")
        run_git(self.root, "tag", "v0.1")
        run_git(self.root, "switch", "-q", "main")
        run_git(self.root, "branch", "-q", "-D", "release")
        folder = Path(self.enterContext(tempfile.TemporaryDirectory()))
        remote, clone = folder / "remote.git", folder / "clone"
        for arguments in (
            ("clone", "-q", "--bare", str(self.root), str(remote)),
            ("clone", "-q", str(remote), str(clone)),
        ):
            subprocess.run(["git", *arguments], check=True, capture_output=True)
        (clone / "new.txt").write_text("new\n", encoding="utf-8")
        commit_fixture(clone, "new.txt")
        new = _head(clone)

        found = self.reported(PushedScope(new, "origin"), clone)

        tags = run_git(clone, "tag", "--points-at", tagged).stdout.decode()
        self.assertEqual("v0.1\n", tags)
        self.assertEqual(
            {SIGNATURE: {new[:12]}, PRIVATE: set(), "message": set()}, found
        )

    def test_refs_outside_branches_and_remotes_are_not_read(self) -> None:
        self.remote("origin", self.base)
        for ref in (
            "refs/original/refs/heads/main",
            "refs/prefetch/remotes/origin/main",
        ):
            with self.subTest(ref=ref):
                run_git(self.root, "switch", "-q", "--detach", self.base)
                kept = self.add("notes.txt", f"by {CANARY}\n", f"feat: {CANARY}")
                run_git(self.root, "update-ref", ref, kept)
                run_git(self.root, "switch", "-q", "-C", "main", self.base)
                new = self.add("new.txt", f"{ref}\n")

                found = self.reported(PushedScope(new, "origin"))
                run_git(self.root, "update-ref", "-d", ref)

                self.assertEqual(
                    {SIGNATURE: {new[:12]}, PRIVATE: set(), "message": set()}, found
                )

    def test_a_first_push_with_no_ref_reads_every_branch(self) -> None:
        self.remote("origin")
        run_git(self.root, "switch", "-q", "-c", "side")
        side = self.add("notes.txt", f"by {CANARY}\n")
        run_git(self.root, "switch", "-q", "main")
        scope = pushed_scope({"PRE_COMMIT_REMOTE_NAME": "origin"})

        found = self.reported(scope)

        self.assertEqual(PushedScope(None, "origin"), scope)
        self.assertEqual({self.base[:12], side[:12]}, found[SIGNATURE])
        self.assertEqual({side[:12]}, found[PRIVATE])

    def test_gitleaks_reads_the_same_commits(self) -> None:
        (self.root / "key.txt").write_bytes(CALIBRATION_INPUT)
        commit_fixture(self.root, "key.txt")
        secret = _head(self.root)
        self.remote("origin", secret)
        self.remote("public")
        run_git(self.root, "update-ref", "refs/remotes/stray/x", secret)
        new = self.add("new.txt", "new\n")

        for remote in ("origin", "stray"):
            with self.subTest(remote=remote):
                scope = PushedScope(new, remote)
                found = scan_pushed(self.root, scope, max_findings=10)
                self.assertEqual(remote == "stray", bool(found))
        (finding,) = scan_pushed(self.root, PushedScope(new, "public"), max_findings=10)
        self.assertEqual(secret[:12], finding.commit)
        self.assertIn("run git fetch <remote>", str(fix_for(finding)))
        (checked,) = scan_history(self.root, max_findings=10)
        self.assertEqual(secret[:12], checked.commit)
        self.assertNotIn("git fetch", str(fix_for(checked)))
