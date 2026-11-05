import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from unittest.mock import patch

from tests.test_verify_script import core, harness

filter_journey = harness("filter_journey")
CANARY = "verify-canary"
HARNESS_POINTER = "pointer\n"
LFS_POINTER = (
    "version https://git-lfs.github.com/spec/v1\n"
    "oid sha256:f52d8e575ed9266e830ac0616c56c904dd43847b10df591227c1e5a927dda32c\n"
    "size 38\n"
)


class FilteredValueTest(unittest.TestCase):
    def observed(self, staged: str) -> list[str]:
        def answer(
            args: Sequence[str | Path], *_: object, **__: object
        ) -> tuple[int, str]:
            words = [str(word) for word in args]
            if words[:2] == ["git", "show"]:
                return 0, staged
            if words[:2] == ["git", "commit"]:
                return 1, 'privacy.private-literal "data.dat":1: found\n'
            return 0, ""

        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            (project / ".git").mkdir()
            run = core.Run(work=project, python="python3", environment={})
            with patch.object(core.Run, "command", side_effect=answer):
                found: list[str] = filter_journey.filtered_value(run, project, CANARY)
        return found

    def test_the_harness_filter_pointer_is_a_pointer(self) -> None:
        self.assertIn(
            "the clean filter stored only a pointer in the index",
            self.observed(HARNESS_POINTER),
        )

    def test_a_real_git_lfs_pointer_is_a_pointer(self) -> None:
        self.assertIn(
            "the clean filter stored only a pointer in the index",
            self.observed(LFS_POINTER),
        )

    def test_anything_else_in_the_index_fails_the_journey(self) -> None:
        for staged in (
            f"written by {CANARY}\n",
            "pointer and more\n",
            "",
            f"{LFS_POINTER}{CANARY}\n",
            "version https://git-lfs.github.com/spec/v1\n",
        ):
            with (
                self.subTest(staged=staged),
                self.assertRaises(core.FeatureFailedError),
            ):
                self.observed(staged)


if __name__ == "__main__":
    unittest.main()
