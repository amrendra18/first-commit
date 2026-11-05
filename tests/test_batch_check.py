import re
import unittest
from unittest import mock

from first_commit.candidates import CandidateError, object_sizes
from first_commit.git import (
    OBJECT_ID,
    GitError,
    ObjectInfo,
    batch_check,
    listed_commits,
    parse_batch_check,
)
from tests.gitleaks_support import commit_fixture
from tests.support import TemporaryRootTest, initialize_repository, run_git

SHA1 = "a" * 40
SHA256 = "b" * 64


class BatchCheckTest(unittest.TestCase):
    def test_answers_are_parsed_in_order_and_a_missing_name_gives_none(self) -> None:
        raw = (f"{SHA1} blob 3\n:0:docs/a b.txt missing\n{SHA256} tree 0\n").encode()
        self.assertEqual(
            [ObjectInfo(SHA1, "blob", 3), None, ObjectInfo(SHA256, "tree", 0)],
            parse_batch_check(raw, 3),
        )
        self.assertEqual([], parse_batch_check(b"", 0))

    def test_a_wrong_count_or_malformed_answer_is_refused(self) -> None:
        for raw, count in (
            (b"", 1),
            (f"{SHA1} blob 3\n".encode(), 2),
            (f"{SHA1} blob many\n".encode(), 1),
            (f"{SHA1[:39]} blob 3\n".encode(), 1),
            (f"{SHA1} blob 3 extra\n".encode(), 1),
        ):
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(GitError, "inconsistent object"),
            ):
                parse_batch_check(raw, count)

    def test_object_ids_are_full_sha1_or_sha256_hex(self) -> None:
        for value in (SHA1, SHA256):
            self.assertIsNotNone(OBJECT_ID.fullmatch(value))
        for value in ("A" * 40, "a" * 39, "a" * 41, "a" * 63, ""):
            self.assertIsNone(OBJECT_ID.fullmatch(value))

    def test_object_id_match_and_search_take_the_whole_sha256_id(self) -> None:
        for find in (OBJECT_ID.match, OBJECT_ID.search):
            found = find(SHA256)
            self.assertEqual(SHA256, found.group() if found else None)

    def test_object_id_stays_one_unit_inside_a_longer_pattern(self) -> None:
        answer = re.compile(OBJECT_ID.pattern + " blob")
        self.assertIsNone(answer.match(f"{SHA1} tree"))
        self.assertIsNone(answer.match(f"{SHA256} tree"))
        self.assertIsNotNone(answer.fullmatch(f"{SHA256} blob"))


class ObjectHelpersTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        initialize_repository(self.root)
        (self.root / "caf\u00e9.txt").write_text("abc\n", encoding="utf-8")
        commit_fixture(self.root, "caf\u00e9.txt")
        self.commit = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        raw = run_git(self.root, "rev-parse", "HEAD:caf\u00e9.txt").stdout
        self.blob = raw.decode().strip()

    def test_listed_commits_runs_rev_list_and_reads_pathspecs_literally(self) -> None:
        self.assertEqual([self.commit], listed_commits(self.root, ("HEAD", "--")))
        self.assertEqual([], listed_commits(self.root, ("HEAD", "--", "*.txt")))

    def test_listed_commits_refuses_an_answer_that_is_no_object_id(self) -> None:
        for answer in (b"not-a-commit\n", SHA1[:39].encode() + b"\n"):
            with (
                self.subTest(answer=answer),
                mock.patch("first_commit.git.run_git", return_value=answer),
                self.assertRaisesRegex(GitError, "^Git returned an invalid commit.$"),
            ):
                listed_commits(self.root, ("HEAD", "--"))

    def test_batch_check_answers_each_name_and_runs_no_git_for_none(self) -> None:
        self.assertEqual(
            [ObjectInfo(self.blob, "blob", 4), None],
            batch_check(self.root, ["HEAD:caf\u00e9.txt", "HEAD:missing.txt"]),
        )
        with mock.patch("first_commit.git.run_git") as run:
            self.assertEqual([], batch_check(self.root, []))
        run.assert_not_called()

    def test_object_sizes_checks_each_id_kind_and_the_size_limit(self) -> None:
        names = [self.commit, self.blob]
        self.assertEqual(
            {self.blob: 4}, object_sizes(self.root, [self.blob], "blob", 4, "File")
        )
        self.assertEqual({}, object_sizes(self.root, [], "commit", 0, "Commit"))
        for name, kind in ((self.blob, "commit"), (SHA1, "blob")):
            with (
                self.subTest(name=name, kind=kind),
                self.assertRaisesRegex(
                    GitError, "^Git returned an inconsistent object.$"
                ),
            ):
                object_sizes(self.root, [name], kind, None, "File")
        answer = ObjectInfo(SHA1, "blob", 4)
        with (
            mock.patch("first_commit.candidates.batch_check", return_value=[answer]),
            self.assertRaisesRegex(GitError, "^Git returned an inconsistent object.$"),
        ):
            object_sizes(self.root, [self.blob], "blob", None, "File")
        with self.assertRaisesRegex(
            CandidateError,
            f"^Commit message of {self.commit[:12]} exceeds the size limit.$",
        ):
            object_sizes(self.root, names[:1], "commit", 1, "Commit message")
        self.assertEqual(
            {self.blob: 4}, object_sizes(self.root, [self.blob], "blob", None, "File")
        )


if __name__ == "__main__":
    unittest.main()
