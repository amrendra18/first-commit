import unittest
from dataclasses import replace
from unittest.mock import patch

from first_commit.candidates import LoadedCandidates
from first_commit.finding_collector import TOO_LARGE_RULE
from first_commit.models import Finding
from first_commit.validation import staged
from tests.validation_support import ValidationFixture


class GeneratedRepeatsTest(ValidationFixture):
    def staged_after(
        self,
        earlier: list[Finding],
        generated: LoadedCandidates,
        markers: list[Finding],
    ) -> list[tuple[str, str, int | None]]:
        with (
            patch("first_commit.validation.staged_candidate_paths", return_value=()),
            patch(
                "first_commit.validation.forbidden_path_findings", return_value=earlier
            ),
            patch(
                "first_commit.validation.staged_candidates",
                return_value=LoadedCandidates(()),
            ),
            patch("first_commit.validation._index_documents", return_value={}),
            patch("first_commit.validation.evaluate"),
            patch("first_commit.validation._add_environment_findings"),
            patch("first_commit.validation.working_candidate_paths", return_value=()),
            patch("first_commit.validation.working_candidates", return_value=generated),
            patch(
                "first_commit.validation.no_commit_findings",
                side_effect=lambda _, *, max_findings: markers[:max_findings],
            ),
            patch("first_commit.validation.run_git", return_value=b"tracked\0"),
            patch("first_commit.validation.is_tracked", return_value=False),
            patch("first_commit.validation.scan_staged", return_value=()),
            patch("first_commit.validation.scan_hidden_staged", return_value=()),
        ):
            result = staged(self.root, replace(self.policy, max_findings=3))
        return [(item.rule_id, item.path, item.line) for item in result.findings]

    def test_a_repeated_generated_too_large_path_leaves_room_for_the_next(
        self,
    ) -> None:
        other = Finding(rule_id="paths.forbidden", path="x", summary="Forbidden.")
        large = Finding(rule_id=TOO_LARGE_RULE, path="A", summary="Big.")
        generated = LoadedCandidates((), oversized=["A", "B"])
        self.assertEqual(
            [
                (TOO_LARGE_RULE, "A", None),
                (TOO_LARGE_RULE, "B", None),
                ("paths.forbidden", "x", None),
            ],
            self.staged_after([other, large], generated, []),
        )

    def test_a_repeated_generated_marker_leaves_room_for_the_next(self) -> None:
        other = Finding(rule_id="paths.forbidden", path="x", summary="Forbidden.")
        second = replace(self.marker, line=2)
        generated = LoadedCandidates((self.candidate,))
        self.assertEqual(
            [
                ("text.no-commit", "draft.txt", 1),
                ("text.no-commit", "draft.txt", 2),
                ("paths.forbidden", "x", None),
            ],
            self.staged_after([other, self.marker], generated, [self.marker, second]),
        )


if __name__ == "__main__":
    unittest.main()
