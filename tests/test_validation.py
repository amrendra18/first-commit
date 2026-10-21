import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from first_commit import validation
from first_commit.candidates import CandidateError, LoadedCandidates
from first_commit.contributor import Contributor
from first_commit.git import GitError, repository_root
from first_commit.models import Candidate, Finding, Origin, Severity
from first_commit.paths import PathError
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from first_commit.validation import (
    doctor,
    history,
    message,
    staged,
    working,
)
from tests.support import commit_message, initialize_repository, run_git
from tests.validation_support import (
    IDENTITY,
    TOKEN,
    ValidationFixture,
    evaluate_candidates,
)


class ValidationTest(ValidationFixture):
    def test_empty_initial_index_has_one_actionable_finding(self) -> None:
        initialize_repository(self.root)
        policy = self.policy
        for path in REQUIRED_DOCUMENTS:
            (self.root / path).write_text("# Reviewed\n", encoding="utf-8")

        with patch("first_commit.validation.scan_staged", return_value=()):
            result = staged(self.root, policy)

        self.assertFalse(result.passed)
        self.assertEqual(
            [("<index>", "git.empty-index")],
            [(item.path, item.rule_id) for item in result.findings],
        )
        self.assertIn("stage the required documents", result.findings[0].summary)

    def test_partial_initial_index_retains_document_findings(self) -> None:
        initialize_repository(self.root)
        policy = self.policy
        first = REQUIRED_DOCUMENTS[0]
        (self.root / first).write_text("# Reviewed\n", encoding="utf-8")
        run_git(self.root, "add", "--", first)

        with patch("first_commit.validation.scan_staged", return_value=()):
            result = staged(self.root, policy)

        rules = {item.rule_id for item in result.findings}
        self.assertIn("documents.required", rules)
        self.assertNotIn("git.empty-index", rules)

    def test_unreadable_index_document_is_reported_as_missing(self) -> None:
        initialize_repository(self.root)
        self.write_documents()
        run_git(self.root, "add", "--", *REQUIRED_DOCUMENTS)
        with (
            patch(
                "first_commit.validation.index_candidate",
                side_effect=CandidateError("synthetic"),
            ),
            patch("first_commit.validation.scan_staged", return_value=()),
        ):
            result = staged(self.root, self.policy)
        self.assertEqual(
            set(REQUIRED_DOCUMENTS),
            {
                item.path
                for item in result.findings
                if item.rule_id == "documents.required"
            },
        )

    def test_forbidden_working_and_staged_paths_are_blocked_before_byte_reads(
        self,
    ) -> None:
        initialize_repository(self.root)
        value = {
            "schema_version": 1,
            "forbidden_paths": [
                {
                    "match": "suffix",
                    "value": ".kdbx",
                    "reason": "Password vaults are private.",
                }
            ],
        }
        policy = replace(
            parse_policy(json.dumps(value).encode(), self.root),
            max_file_bytes=4,
            max_findings=1,
        )
        for path in REQUIRED_DOCUMENTS:
            (self.root / path).write_bytes(b"#\n")
        (self.root / "vault.kdbx").write_bytes(b"12345")
        (self.root / "other.kdbx").write_bytes(b"67890")

        working_result = working(self.root, policy)
        self.assertEqual(
            [("other.kdbx", "privacy.forbidden-path")],
            [(item.path, item.rule_id) for item in working_result.findings],
        )

        run_git(
            self.root,
            "add",
            "--",
            *REQUIRED_DOCUMENTS,
            "vault.kdbx",
            "other.kdbx",
        )
        with patch("first_commit.validation.scan_staged") as scanner:
            staged_result = staged(self.root, policy)
        scanner.assert_not_called()
        self.assertEqual(
            [("other.kdbx", "privacy.forbidden-path")],
            [(item.path, item.rule_id) for item in staged_result.findings],
        )

    def test_doctor_distinguishes_signing_from_local_verification_trust(self) -> None:
        policy = replace(self.policy, contributor_emails=("public@example.net",))
        settings = dict(IDENTITY)
        person = Contributor("Example", "public@example.net", "key.pub")
        (self.root / "key.pub").write_text("ssh-ed25519 AAAA\n", encoding="ascii")
        with (
            patch("first_commit.validation.local_git_settings", return_value=settings),
            patch("first_commit.validation.is_tracked", return_value=False),
            patch("first_commit.validation.validate_scanner") as scanner,
            patch("first_commit.hooks.nested_remote_findings", return_value=[]),
            patch("first_commit.validation.hook_findings", return_value=[]),
            patch("first_commit.validation.template_findings", return_value=[]),
            patch("first_commit.validation.load_contributor", return_value=person),
        ):
            result = doctor(self.root, policy)

        scanner.assert_called_once_with(self.root)

        self.assertTrue(result.passed)
        self.assertEqual(
            ["git.signature-verification-trust"],
            [item.rule_id for item in result.findings],
        )
        self.assertEqual("warning", result.findings[0].severity)

        settings["gpg.ssh.allowedSignersFile"] = ".local/first-commit/allowed-signers"
        signers = self.root / settings["gpg.ssh.allowedSignersFile"]
        signers.parent.mkdir(parents=True)
        signers.write_text("public@example.net ssh-ed25519 AAAA\n", encoding="ascii")
        with (
            patch("first_commit.validation.local_git_settings", return_value=settings),
            patch("first_commit.validation.is_tracked", return_value=False),
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.hooks.nested_remote_findings", return_value=[]),
            patch("first_commit.validation.hook_findings", return_value=[]),
            patch("first_commit.validation.template_findings", return_value=[]),
            patch("first_commit.validation.load_contributor", return_value=person),
        ):
            result = doctor(self.root, policy)
        self.assertEqual((), result.findings)

    def test_doctor_combines_identity_hook_template_and_contributor_findings(
        self,
    ) -> None:
        hook = Finding(
            rule_id="hooks.missing",
            severity=Severity.ERROR,
            path=".git/hooks/pre-commit",
            summary="Missing.",
        )
        template = Finding(
            rule_id="template.missing",
            severity=Severity.ERROR,
            path=".gitmessage",
            summary="Missing.",
        )
        with (
            patch("first_commit.validation.local_git_settings", return_value={}),
            patch("first_commit.validation.is_tracked", return_value=False),
            patch("first_commit.validation.validate_scanner"),
            patch("first_commit.hooks.nested_remote_findings", return_value=[]),
            patch("first_commit.validation.hook_findings", return_value=[hook]),
            patch("first_commit.validation.template_findings", return_value=[template]),
            patch("first_commit.validation.load_contributor", return_value=None),
        ):
            result = doctor(self.root, self.policy)
            limited = doctor(self.root, replace(self.policy, max_findings=2))

        rules = [item.rule_id for item in result.findings]
        self.assertIn("git.local-name", rules)
        self.assertEqual(
            ["hooks.missing", "template.missing", "git.contributor-record"],
            rules[-3:],
        )
        locations = [
            (item.path, item.line or 0, item.rule_id) for item in result.findings
        ]
        self.assertEqual(sorted(locations), locations)
        self.assertEqual(
            ["git.local-email", "git.local-name"],
            [item.rule_id for item in limited.findings],
        )

    def test_staged_marker_is_not_reported_twice(self) -> None:
        staged_findings = (self.marker,)
        with (
            patch("first_commit.validation.staged_candidate_paths", return_value=()),
            patch(
                "first_commit.validation.staged_candidates",
                return_value=LoadedCandidates(()),
            ),
            patch(
                "first_commit.validation.evaluate",
                side_effect=lambda found, *_: found.add(staged_findings),
            ),
            patch("first_commit.validation._add_environment_findings"),
            patch("first_commit.validation.working_candidate_paths", return_value=()),
            patch(
                "first_commit.validation.working_candidates",
                return_value=LoadedCandidates((self.candidate,)),
            ),
            patch(
                "first_commit.validation.no_commit_findings",
                return_value=[self.marker],
            ),
            patch("first_commit.validation.run_git", return_value=b"tracked\0"),
            patch("first_commit.validation.is_tracked", return_value=False),
            patch("first_commit.validation.scan_staged", return_value=()),
        ):
            result = staged(self.root, self.policy)
        self.assertEqual((self.marker,), result.findings)

    def test_staged_budget_stops_visible_marker_scan(self) -> None:
        staged_findings = (self.marker,) * self.policy.max_findings
        with (
            patch("first_commit.validation.staged_candidate_paths", return_value=()),
            patch(
                "first_commit.validation.staged_candidates",
                return_value=LoadedCandidates(()),
            ),
            patch(
                "first_commit.validation.evaluate",
                side_effect=lambda found, *_: found.add(staged_findings),
            ),
            patch("first_commit.validation._add_environment_findings"),
            patch("first_commit.validation.working_candidate_paths", return_value=()),
            patch(
                "first_commit.validation.working_candidates",
                return_value=LoadedCandidates((self.candidate,)),
            ),
            patch("first_commit.validation.no_commit_findings") as marker_scan,
            patch("first_commit.validation.run_git", return_value=b"tracked\0"),
            patch("first_commit.validation.is_tracked", return_value=False),
            patch("first_commit.validation.scan_staged", return_value=()),
        ):
            result = staged(self.root, self.policy)
        marker_scan.assert_not_called()
        self.assertEqual(self.policy.max_findings, len(result.findings))

    def test_git_managed_relative_message_path_is_confined(self) -> None:
        initialize_repository(self.root)
        message_path = self.root / ".git/COMMIT_EDITMSG"
        message_path.write_text(commit_message("feat: add checks"), encoding="utf-8")
        with (
            patch(
                "first_commit.validation.read_explicit_file_bytes",
                side_effect=PathError("synthetic"),
            ),
            patch(
                "first_commit.validation.run_git",
                return_value=b".git/COMMIT_EDITMSG\n",
            ),
            patch("first_commit.validation.local_git_settings", return_value={}),
        ):
            result = message(self.root, self.policy, message_path)
            self.assertEqual("message", result.scope)
            with self.assertRaises(CandidateError):
                message(self.root, self.policy, self.root / "other.txt")

    def test_scanner_findings_are_reported_for_staged_and_history(self) -> None:
        initialize_repository(self.root)
        self.write_documents()
        run_git(self.root, "add", "--", *REQUIRED_DOCUMENTS)
        finding = Finding(
            rule_id="secrets.gitleaks",
            severity=Severity.ERROR,
            path=".git",
            summary="Scanner finding.",
        )
        with patch(
            "first_commit.validation.scan_staged", return_value=(finding,)
        ) as scanner:
            result = staged(self.root, self.policy)
        scanner.assert_called_once_with(
            self.root, max_findings=self.policy.max_findings
        )
        self.assertEqual((finding,), result.findings)
        with patch(
            "first_commit.validation.scan_history", return_value=(finding,)
        ) as scanner:
            self.assertEqual((finding,), history(self.root, self.policy).findings)
        scanner.assert_called_once_with(
            self.root, max_findings=self.policy.max_findings
        )
        with patch("first_commit.validation.scan_history", return_value=()):
            self.assertEqual((), history(self.root, self.policy).findings)

    def test_scanner_locations_are_ordered_and_bounded_in_both_scopes(self) -> None:
        initialize_repository(self.root)
        self.write_documents()
        run_git(self.root, "add", "--", *REQUIRED_DOCUMENTS)
        located = (
            Finding(
                rule_id="secrets.gitleaks",
                severity=Severity.ERROR,
                path="z.py",
                summary="Scanner finding.",
                line=1,
            ),
            Finding(
                rule_id="secrets.gitleaks",
                severity=Severity.ERROR,
                path="a.py",
                summary="Scanner finding.",
                line=9,
            ),
            Finding(
                rule_id="secrets.gitleaks",
                severity=Severity.ERROR,
                path="a.py",
                summary="Scanner finding.",
                line=2,
            ),
        )
        policy = replace(self.policy, max_findings=2)

        def scanner_order(*_: object, max_findings: int) -> tuple[Finding, ...]:
            return located[:max_findings]

        with patch("first_commit.validation.scan_history", side_effect=scanner_order):
            result = history(self.root, policy)
        self.assertEqual(
            [("a.py", 9), ("z.py", 1)],
            [(item.path, item.line) for item in result.findings],
        )
        with patch(
            "first_commit.validation.scan_staged", side_effect=scanner_order
        ) as scanner:
            staged_result = staged(self.root, policy)
        self.assertEqual(
            [("a.py", 9), ("z.py", 1)],
            [(item.path, item.line) for item in staged_result.findings],
        )
        self.assertEqual(
            {"max_findings": policy.max_findings}, scanner.call_args.kwargs
        )

    def test_validation_has_no_project_coverage_scope(self) -> None:
        self.assertFalse(hasattr(validation, "coverage"))
        self.assertFalse(hasattr(self.policy, "coverage_reports"))

    def test_repository_root_uses_exact_path_and_rejects_invalid_git_output(
        self,
    ) -> None:
        intended = self.root / "consumer "
        decoy = self.root / "consumer"
        for root in (intended, decoy):
            root.mkdir()
            initialize_repository(root)
        self.assertEqual(intended.resolve(), repository_root(str(intended)))
        previous = Path.cwd()
        os.chdir(decoy)
        self.addCleanup(os.chdir, previous)
        self.assertEqual(decoy.resolve(), repository_root(None))
        with patch("first_commit.git._execute", return_value=b"\xff"):
            with self.assertRaises(GitError):
                repository_root(str(intended))


class EvaluateCandidatesTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.policy = parse_policy(b'{"schema_version":1}', Path(temporary.name))
        self.documents = {
            name: Candidate(name, b"# Reviewed document\n", Origin.WORKTREE)
            for name in REQUIRED_DOCUMENTS
        }

    def test_missing_and_empty_required_documents_fail(self) -> None:
        documents = dict(self.documents)
        documents.pop("README.md")
        documents["AGENTS.md"] = Candidate("AGENTS.md", b"", Origin.WORKTREE)
        result = evaluate_candidates("working", [], self.policy, documents)
        self.assertEqual(
            [
                ("AGENTS.md", "documents.required", "error"),
                ("README.md", "documents.required", "error"),
            ],
            [(item.path, item.rule_id, item.severity) for item in result.findings],
        )
        self.assertFalse(result.passed)
        limited = replace(self.policy, max_findings=1)
        self.assertEqual(
            1, len(evaluate_candidates("working", [], limited, {}).findings)
        )

    def test_marker_text_and_privacy_findings_are_redacted_and_sorted(self) -> None:
        private = "private@" + "nonexample.dev"
        candidates = [
            Candidate(
                "scratch.txt",
                ("# @no-commit\naddress = " + private + "  \n").encode(),
                Origin.WORKTREE,
            ),
            Candidate("token.txt", (TOKEN + "\n").encode(), Origin.WORKTREE),
        ]
        result = evaluate_candidates("working", candidates, self.policy, self.documents)
        rules = {item.rule_id for item in result.findings}
        self.assertIn("scaffold.no-commit", rules)
        self.assertIn("privacy.unapproved-email", rules)
        self.assertIn("privacy.github-token", rules)
        self.assertFalse(result.passed)
        self.assertNotIn(private, repr(result))
        self.assertNotIn(TOKEN, repr(result))
        self.assertEqual(
            sorted(
                result.findings,
                key=lambda item: (item.path, item.line or 0, item.rule_id),
            ),
            list(result.findings),
        )

    def test_finding_limit_stops_before_candidate_checks(self) -> None:
        limited = replace(self.policy, max_findings=1)
        candidate = Candidate("scratch.txt", b"# @no-commit\n", Origin.WORKTREE)
        with patch("first_commit.finding_collector.no_commit_findings") as marker_check:
            result = evaluate_candidates("working", [candidate], limited, {})
        marker_check.assert_not_called()
        self.assertEqual(1, len(result.findings))

    def test_marker_consumes_budget_before_privacy(self) -> None:
        limited = replace(self.policy, max_findings=1)
        candidate = Candidate("scratch.txt", b"# @no-commit\n", Origin.WORKTREE)
        with patch("first_commit.finding_collector.privacy_findings") as privacy_check:
            result = evaluate_candidates(
                "working", [candidate], limited, self.documents
            )
        privacy_check.assert_not_called()
        self.assertEqual("scaffold.no-commit", result.findings[0].rule_id)

    def test_text_finding_consumes_budget_before_privacy(self) -> None:
        limited = replace(self.policy, max_findings=1)
        candidate = Candidate("scratch.txt", b"trailing space \n", Origin.WORKTREE)
        with patch("first_commit.finding_collector.privacy_findings") as privacy_check:
            result = evaluate_candidates(
                "working", [candidate], limited, self.documents
            )
        privacy_check.assert_not_called()
        self.assertEqual("text.trailing-whitespace", result.findings[0].rule_id)

    def test_privacy_finding_consumes_budget_before_next_candidate(self) -> None:
        limited = replace(self.policy, max_findings=1)
        private = "private@" + "nonexample.dev"
        candidates = [
            Candidate("first.txt", (private + "\n").encode(), Origin.WORKTREE),
            Candidate("second.txt", b"# @no-commit\n", Origin.WORKTREE),
        ]
        with patch("first_commit.finding_collector.no_commit_findings") as marker_check:
            result = evaluate_candidates("working", candidates, limited, self.documents)
        self.assertEqual(1, marker_check.call_count)
        self.assertTrue(result.findings[0].rule_id.startswith("privacy."))
