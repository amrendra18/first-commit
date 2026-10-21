import re
import unittest

from first_commit.git import OBJECT_ID, GitError, ObjectInfo, parse_batch_check

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


if __name__ == "__main__":
    unittest.main()
