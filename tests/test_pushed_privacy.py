import hashlib
import json
import weakref
from dataclasses import replace
from pathlib import Path
from unittest import mock

from first_commit.candidates import CandidateError
from first_commit.fixes import fix_for
from first_commit.git import GitError
from first_commit.models import Finding
from first_commit.policy import POLICY_PATH, Policy, parse_policy
from first_commit.pushed import PushedScope
from first_commit.pushed_privacy import (
    _commit_rules,
    _findings,
    _Scan,
    _Version,
    _versions,
    pushed_privacy_findings,
    pushed_versions,
)
from tests.gitleaks_support import (
    commit_fixture,
    history_cli,
    needs_real_scanner,
    pushed_base_commit,
)
from tests.support import TemporaryRootTest, run_git

CANARY = "synthetic-pushed-canary"
RULE = "privacy.private-literal"
LINE = f"written by {CANARY}"


def _head(root: Path) -> str:
    return run_git(root, "rev-parse", "HEAD").stdout.decode().strip()


def _approving_policy(path: str, line: int) -> str:
    entry = {
        "path": path,
        "line": line,
        "sha256": hashlib.sha256(LINE.encode()).hexdigest(),
        "reason": "Reviewed fixture line.",
    }
    return (
        json.dumps({"schema_version": 1, "private_literal_exceptions": [entry]}) + "\n"
    )


class PushedPrivacyTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        # test_pushed_signatures covers signing; these commits are unsigned.
        unsigned = mock.patch(
            "first_commit.validation.unsigned_commit_findings", return_value=[]
        )
        unsigned.start()
        self.addCleanup(unsigned.stop)
        self.base = pushed_base_commit(self.root)
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        values = self.root / ".local/first-commit/private-values.txt"
        values.parent.mkdir(parents=True)
        values.write_text(CANARY + "\n", encoding="utf-8")
        values.chmod(0o600)

    def push(self, *options: str, ranged: bool = True) -> tuple[int, str]:
        environment = (
            {"PRE_COMMIT_TO_REF": _head(self.root), "PRE_COMMIT_REMOTE_NAME": "origin"}
            if ranged
            else {}
        )
        return history_cli(self.root, ("hook", "pre-push", *options), environment)

    def add(self, path: str, text: str, *extra: str) -> str:
        (self.root / path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / path).write_text(text, encoding="utf-8")
        commit_fixture(self.root, path, *extra)
        return _head(self.root)

    def remove(self, path: str) -> None:
        run_git(self.root, "rm", "-q", "--", path)
        run_git(self.root, "commit", "-q", "--no-verify", "-m", "fix: remove it")

    def scan(
        self, policy: Policy, scope: PushedScope | None, max_findings: int
    ) -> list[Finding]:
        versions = pushed_versions(self.root, scope, policy.max_files)
        return pushed_privacy_findings(
            self.root, policy, versions, (CANARY,), max_findings=max_findings
        )

    def findings(
        self,
        max_file_bytes: int = 1024,
        max_files: int = 10_000,
        working: str = '{"schema_version":1}',
    ) -> list[Finding]:
        policy = replace(
            parse_policy(working.encode(), self.root),
            max_file_bytes=max_file_bytes,
            max_files=max_files,
        )
        scope = PushedScope(_head(self.root), "origin")
        return self.scan(policy, scope, 10)

    def test_the_oldest_commit_is_named_when_a_later_one_reuses_a_blob(self) -> None:
        self.add("b.txt", LINE + "\n")
        oldest = self.add("a.txt", f"x {LINE}\n")[:12]
        # The same bytes as b.txt, a blob the batch reads before a.txt's first one.
        self.add("a.txt", LINE + "\n")

        found = [(item.path, item.commit) for item in self.findings()]

        self.assertIn(("a.txt", oldest), found)
        self.assertEqual(1, [path for path, _ in found].count("a.txt"))

    def test_more_file_versions_than_the_limit_stop_the_scan(self) -> None:
        self.add("one.txt", "one\n")
        self.add("two.txt", "two\n")

        with self.assertRaisesRegex(CandidateError, "more than 1 file versions"):
            self.findings(max_files=1)
        self.assertEqual([], self.findings(max_files=2))

    def test_a_first_push_past_the_limit_names_no_partial_push(self) -> None:
        self.add("one.txt", "one\n")
        self.add("two.txt", "two\n")
        policy = replace(parse_policy(b'{"schema_version":1}', self.root), max_files=1)

        with self.assertRaisesRegex(
            CandidateError, "names no branch or full commit id"
        ) as error:
            pushed_versions(self.root, None, policy.max_files)
        self.assertIn("git push <remote> <branch>", str(error.exception))
        self.assertNotIn("--no-verify", str(error.exception))

    def test_pushing_the_older_commits_first_gets_past_the_limit(self) -> None:
        older = self.add("one.txt", LINE + "\n")
        self.add("two.txt", "two\n")
        policy = replace(parse_policy(b'{"schema_version":1}', self.root), max_files=1)

        # git push origin <older>:refs/heads/main, as the fix line says: the pushed
        # branch alone fits the limit, so it is read, and its value is still reported.
        found = self.scan(policy, PushedScope(older, "origin"), 10)

        self.assertEqual(
            [(RULE, "one.txt", older[:12])],
            [(item.rule_id, item.path, item.commit) for item in found],
        )

    @needs_real_scanner
    def test_value_added_then_deleted_is_reported(self) -> None:
        added = self.add("notes.txt", f"first line\n{LINE}\n")[:12]
        self.remove("notes.txt")

        code, output = self.push()

        self.assertEqual(1, code, output)
        self.assertIn(
            f'{RULE} "notes.txt":2: Detected a configured private literal in commit '
            f"{added}.",
            output,
        )
        self.assertIn(f"git rebase -i {added}^", output)
        self.assertNotIn(CANARY, output)
        # check reads no file contents of commits; only the push does.
        code, output = history_cli(self.root, ("check",), {})
        self.assertEqual(0, code, output)

    @needs_real_scanner
    def test_value_only_in_pushed_commits_is_masked(self) -> None:
        name = f"docs/{CANARY}-notes.txt"
        added = self.add(name, "public text\n")[:12]
        self.remove(name)

        code, output = self.push()

        self.assertEqual(1, code, output)
        self.assertIn(
            'privacy.private-path "docs/<private value>-notes.txt": The file path '
            f"contains a configured private literal in commit {added}.",
            output,
        )
        self.assertNotIn(CANARY, output)
        code, text = self.push("--format", "json")
        self.assertEqual(1, code, text)
        self.assertNotIn(CANARY, text)
        (history,) = (
            check for check in json.loads(text)["checks"] if check["name"] == "history"
        )
        paths = {finding["path"] for finding in history["findings"]}
        self.assertEqual({"docs/<private value>-notes.txt"}, paths)

    @needs_real_scanner
    def test_clean_push_passes(self) -> None:
        # A commit a remote-tracking branch holds is already public.
        public = self.add("public.txt", f"{LINE}\n")
        run_git(self.root, "update-ref", "refs/remotes/origin/main", public)
        self.add("notes.txt", "clean\n")
        self.remove("notes.txt")

        code, output = self.push()

        self.assertEqual(0, code, output)
        self.assertIn("PASS history", output)

    @needs_real_scanner
    def test_only_the_pushed_commit_policy_approves_a_line(self) -> None:
        (self.root / POLICY_PATH).write_text(
            _approving_policy("approved.txt", 1), encoding="utf-8"
        )
        self.add("approved.txt", f"{LINE}\n", POLICY_PATH)

        self.assertEqual(0, self.push()[0])

        # An exception in the working copy alone approves nothing a push sends.
        (self.root / POLICY_PATH).write_text(
            _approving_policy("other.txt", 1), encoding="utf-8"
        )
        added = self.add("other.txt", f"{LINE}\n")[:12]
        code, output = self.push()
        self.assertEqual(1, code, output)
        self.assertIn(f'{RULE} "other.txt":1: ', output)
        self.assertIn(f"in commit {added}.", output)
        self.assertNotIn('"approved.txt"', output)

    @needs_real_scanner
    def test_a_merge_reports_only_what_it_adds(self) -> None:
        run_git(self.root, "switch", "-q", "-c", "upstream")
        upstream = self.add("upstream.txt", f"{LINE}\n")
        run_git(self.root, "update-ref", "refs/remotes/origin/upstream", upstream)
        run_git(self.root, "switch", "-q", "main")
        run_git(self.root, "merge", "-q", "--no-ff", "--no-commit", "upstream")
        (self.root / "merged.txt").write_text(f"{LINE}\n", encoding="utf-8")
        run_git(self.root, "add", "merged.txt")
        run_git(self.root, "commit", "-q", "--no-verify", "-m", "feat: merge it")

        code, output = self.push()

        self.assertEqual(1, code, output)
        self.assertIn(f'{RULE} "merged.txt":1: ', output)
        self.assertIn(f"in commit {_head(self.root)[:12]}.", output)
        self.assertNotIn("upstream.txt", output)

    @needs_real_scanner
    def test_a_push_with_a_root_commit_reads_every_unpushed_branch(self) -> None:
        run_git(self.root, "update-ref", "-d", "refs/remotes/origin/main")
        run_git(self.root, "switch", "-q", "-c", "side")
        self.add("side.txt", f"{LINE}\n")
        run_git(self.root, "switch", "-q", "main")

        code, output = self.push(ranged=False)

        self.assertEqual(1, code, output)
        self.assertIn(f'{RULE} "side.txt":1: ', output)

    def test_a_blob_over_the_size_limit_is_reported_unread(self) -> None:
        added = self.add("large.txt", "x" * 64 + "\n")[:12]
        self.add("small.txt", "y\n")

        (finding,) = self.findings(max_file_bytes=16)

        self.assertEqual(
            ("files.too-large", "large.txt"), (finding.rule_id, finding.path)
        )
        self.assertEqual(added, finding.commit)
        self.assertIn(f"git rebase -i {added}^", fix_for(finding) or "")

    def test_the_finding_cap_stops_the_scan(self) -> None:
        for number in range(3):
            self.add(f"notes-{number}.txt", f"{LINE}\n")

        findings = self.findings()
        scope = PushedScope(_head(self.root), "origin")
        policy = parse_policy(b'{"schema_version":1}', self.root)
        capped = self.scan(policy, scope, 2)

        self.assertEqual(3, len(findings))
        self.assertEqual(["notes-0.txt", "notes-1.txt"], [item.path for item in capped])
        self.assertEqual(
            [],
            self.scan(policy, scope, 0),
        )

    def test_an_invalid_policy_in_a_pushed_commit_approves_nothing(self) -> None:
        # The policy is fixed in a later commit; the older commit stays pushable and
        # gets no exceptions, so its value is still reported.
        (self.root / POLICY_PATH).write_text("[]\n", encoding="utf-8")
        added = self.add("notes.txt", LINE + "\n", POLICY_PATH)[:12]
        (self.root / POLICY_PATH).write_text('{"schema_version":1}\n', "utf-8")
        self.add("other.txt", "clean\n", POLICY_PATH)

        found = self.findings()

        self.assertEqual(
            [(RULE, "notes.txt", added)],
            [(finding.rule_id, finding.path, finding.commit) for finding in found],
        )

    def test_a_link_or_a_submodule_entry_is_handled(self) -> None:
        (self.root / "link").symlink_to(LINE)
        commit_fixture(self.root, "link")
        run_git(
            self.root,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{self.base},module",
        )
        run_git(self.root, "commit", "-q", "--no-verify", "-m", "feat: add module")

        (finding,) = self.findings()

        self.assertEqual(
            (RULE, "link", 1), (finding.rule_id, finding.path, finding.line)
        )

    def test_a_later_version_repeats_no_finding(self) -> None:
        first = self.add("notes.txt", f"{LINE}\n")[:12]
        self.add("notes.txt", f"{LINE}\nmore\n")
        large = self.add("large.txt", "x" * 2048 + "\n")[:12]
        self.add("large.txt", "y" * 2048 + "\n")

        findings = self.findings()

        self.assertEqual(
            [(RULE, "notes.txt", first), ("files.too-large", "large.txt", large)],
            sorted(
                ((item.rule_id, item.path, item.commit) for item in findings),
                reverse=True,
            ),
        )

    def test_a_policy_that_is_not_a_file_approves_nothing(self) -> None:
        (self.root / POLICY_PATH).unlink()
        added = self.add(f"{POLICY_PATH}/notes.txt", LINE + "\n")[:12]

        found = self.findings()

        self.assertEqual(
            [(RULE, added)], [(finding.rule_id, finding.commit) for finding in found]
        )

    def test_a_first_push_reads_what_the_root_commit_adds(self) -> None:
        run_git(self.root, "update-ref", "-d", "refs/remotes/origin/main")
        run_git(self.root, "switch", "-q", "--orphan", "first")
        added = self.add("notes.txt", LINE + "\n")[:12]
        # Deleted in the next commit, so only the root commit's own change holds it.
        self.remove("notes.txt")
        policy = parse_policy(b'{"schema_version":1}', self.root)

        found = self.scan(policy, None, 10)

        self.assertEqual(
            [(RULE, "notes.txt", added)],
            [(item.rule_id, item.path, item.commit) for item in found],
        )

    def test_a_working_copy_exception_approves_no_pushed_commit(self) -> None:
        working = _approving_policy("notes.txt", 1)
        for name, committed in (("no policy", None), ("an invalid policy", "[]\n")):
            with self.subTest(commit=name):
                extra: tuple[str, ...] = ()
                if committed is not None:
                    (self.root / POLICY_PATH).write_text(committed, encoding="utf-8")
                    extra = (POLICY_PATH,)
                added = self.add("notes.txt", f"{LINE}\n{name}\n", *extra)[:12]

                found = self.findings(working=working)

                self.assertEqual(
                    [(RULE, "notes.txt", 1, added)],
                    [
                        (item.rule_id, item.path, item.line, item.commit)
                        for item in found
                    ],
                )
                run_git(self.root, "update-ref", "refs/remotes/origin/main", "HEAD")

    def test_an_immutable_vendor_file_of_a_pushed_commit_keeps_its_exemption(
        self,
    ) -> None:
        public = b"upstream" + b"@public-source.dev\n"
        entry = {
            "path": "vendor/upstream.txt",
            "sha256": hashlib.sha256(public).hexdigest(),
            "reason": "Reviewed unchanged upstream source.",
        }
        (self.root / POLICY_PATH).write_text(
            json.dumps({"schema_version": 1, "immutable_vendor_files": [entry]}),
            encoding="utf-8",
        )
        for path in ("vendor/upstream.txt", "copy.txt"):
            (self.root / path).parent.mkdir(exist_ok=True)
            (self.root / path).write_bytes(public)
        commit_fixture(self.root, POLICY_PATH, "vendor/upstream.txt", "copy.txt")

        found = self.findings()

        self.assertEqual(
            [("privacy.unapproved-email", "copy.txt")],
            [(item.rule_id, item.path) for item in found],
        )

    def test_a_file_of_exactly_the_size_limit_is_read(self) -> None:
        content = LINE + "\n"
        self.add("notes.txt", content)

        found = self.findings(max_file_bytes=len(content.encode()))

        self.assertEqual([RULE], [item.rule_id for item in found])

    def test_unexpected_git_answers_stop_the_scan(self) -> None:
        commit = self.base
        change = b":100644 100644 " + b"0" * 40 + b" " + b"1" * 40 + b" M"
        for answer in (
            b"not-a-commit\0",
            commit.encode() + b"\0" + b":100644 M\0path\0",
            change + b"\0path\0",
            commit.encode() + b"\0" + change + b"\0",
        ):
            with (
                self.subTest(answer=answer),
                mock.patch("first_commit.pushed_privacy.run_git", return_value=answer),
                self.assertRaises(GitError),
            ):
                _versions(self.root, (commit,))

    def test_reading_holds_one_finding_per_rule_path_and_line(self) -> None:
        commit = self.add("notes.txt", "text\n")
        blob = run_git(self.root, "rev-parse", "HEAD:notes.txt").stdout.decode()
        version = _Version("notes.txt", blob.strip(), "100644", commit)
        lines = 50
        made: list[weakref.ref[Finding]] = []
        held: list[int] = []

        def version_findings(*_arguments: object) -> list[Finding]:
            held.append(sum(item() is not None for item in made))
            found = [
                Finding(rule_id=RULE, path="notes.txt", summary="Seen.", line=number)
                for number in range(lines)
            ]
            made.extend(weakref.ref(item) for item in found)
            return found

        policy = parse_policy(b'{"schema_version":1}', self.root)
        rules = _commit_rules(self.root, policy, (CANARY,), [commit])
        scan = _Scan(self.root, [version] * 20, rules, 1024, lines)
        with mock.patch(
            "first_commit.pushed_privacy._version_findings",
            side_effect=version_findings,
        ):
            found = list(_findings(scan))

        self.assertEqual(list(range(lines)), [item.line for item in found])
        # Each later version repeats every key, so its findings are dropped at once.
        self.assertLess(max(held), 2 * lines)
