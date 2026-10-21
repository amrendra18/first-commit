import hashlib
import json
import unittest

from first_commit.models import Candidate, Origin
from first_commit.policy import REQUIRED_DOCUMENTS, parse_policy
from first_commit.policy_fields import PolicyError
from tests.support import TemporaryRootTest
from tests.validation_support import evaluate_candidates


class PolicyExceptionsTest(TemporaryRootTest):
    def test_exact_private_literal_exceptions_and_bounds(self) -> None:
        item = {
            "path": "docs/public.md",
            "line": 2,
            "sha256": "a" * 64,
            "reason": "Reviewed public attribution.",
        }
        value = {"schema_version": 1, "private_literal_exceptions": [item]}
        policy = parse_policy(json.dumps(value).encode(), self.root)
        self.assertEqual("docs/public.md", policy.literal_exceptions[0].path)
        for changed in (
            {**item, "path": "*.md"},
            {**item, "line": 0},
            {**item, "line": True},
            {**item, "sha256": "bad"},
            {**item, "reason": ""},
        ):
            with self.subTest(changed=changed):
                value["private_literal_exceptions"] = [changed]
                with self.assertRaises(PolicyError):
                    parse_policy(json.dumps(value).encode(), self.root)
        value["private_literal_exceptions"] = [item, item]
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            parse_policy(json.dumps(value).encode(), self.root)
        value["private_literal_exceptions"] = [
            {**item, "line": number} for number in range(1, 130)
        ]
        with self.assertRaisesRegex(PolicyError, "count"):
            parse_policy(json.dumps(value).encode(), self.root)

    def test_exact_detector_exceptions_are_rule_and_content_bound(self) -> None:
        token = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
        content = ("contact" + "@private.dev " + token).encode()
        path = "tests/fixtures/export.json"
        item = {
            "path": path,
            "line": 1,
            "rule": "privacy.github-token",
            "sha256": hashlib.sha256(content).hexdigest(),
            "reason": "Synthetic parser fixture.",
        }
        value = {"schema_version": 1, "privacy_detector_exceptions": [item]}
        policy = parse_policy(json.dumps(value).encode(), self.root)
        self.assertEqual("privacy.github-token", policy.detector_exceptions[0].rule)
        documents = {
            path: Candidate(path, b"# Reviewed\n", Origin.WORKTREE)
            for path in REQUIRED_DOCUMENTS
        }

        candidate = Candidate(path, content + b"\n", Origin.WORKTREE)
        findings = evaluate_candidates("working", (candidate,), policy, documents)
        self.assertEqual(
            ["privacy.unapproved-email"],
            [finding.rule_id for finding in findings.findings],
        )
        later = Candidate(path, content + b"\n" + token.encode() + b"\n", Origin.INDEX)
        findings = evaluate_candidates("staged", (later,), policy, documents)
        github = [
            finding
            for finding in findings.findings
            if finding.rule_id == "privacy.github-token"
        ]
        self.assertEqual([2], [finding.line for finding in github])
        for changed in (
            Candidate(path, content + b" \n", Origin.WORKTREE),
            Candidate(path, content + b"\n", Origin.MESSAGE),
        ):
            with self.subTest(changed=changed):
                findings = evaluate_candidates("working", (changed,), policy, documents)
                self.assertIn(
                    "privacy.github-token",
                    {finding.rule_id for finding in findings.findings},
                )

        for edited in (
            {**item, "path": "*.json"},
            {**item, "line": 0},
            {**item, "rule": "privacy.unknown"},
            {**item, "sha256": "bad"},
            {**item, "reason": ""},
            {**item, "extra": True},
        ):
            with self.subTest(changed=edited):
                value["privacy_detector_exceptions"] = [edited]
                with self.assertRaises(PolicyError):
                    parse_policy(json.dumps(value).encode(), self.root)
        value["privacy_detector_exceptions"] = [item, item]
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            parse_policy(json.dumps(value).encode(), self.root)
        value["privacy_detector_exceptions"] = [
            {**item, "line": number} for number in range(1, 130)
        ]
        with self.assertRaisesRegex(PolicyError, "count"):
            parse_policy(json.dumps(value).encode(), self.root)

    def test_forbidden_paths_use_bounded_explicit_match_kinds(self) -> None:
        items = [
            {
                "match": "exact",
                "value": "private/customer-export.csv",
                "reason": "Customer exports are private.",
            },
            {
                "match": "prefix",
                "value": "exports/",
                "reason": "Generated exports are private.",
            },
            {
                "match": "suffix",
                "value": ".kdbx",
                "reason": "Password vaults do not belong in Git.",
            },
        ]
        value = {"schema_version": 1, "forbidden_paths": items}
        policy = parse_policy(json.dumps(value).encode(), self.root)
        self.assertEqual(
            [
                ("exact", "private/customer-export.csv"),
                ("prefix", "exports/"),
                ("suffix", ".kdbx"),
            ],
            [(item.match, item.value) for item in policy.forbidden_paths],
        )

        invalid = (
            {**items[0], "match": "glob"},
            {**items[0], "match": []},
            {**items[0], "value": "../outside"},
            {**items[0], "value": "private/*.csv"},
            {**items[1], "value": "exports"},
            {**items[1], "value": "/exports/"},
            {**items[2], "value": "kdbx"},
            {**items[2], "value": ".vault/kdbx"},
            {**items[2], "value": ".*"},
            {**items[2], "value": ".."},
            {**items[2], "value": "." + "x" * 1024},
            {**items[2], "reason": ""},
            {**items[2], "reason": "unsafe\noutput"},
            {**items[2], "reason": "x" * 501},
            {**items[2], "extra": True},
        )
        for item in invalid:
            with self.subTest(item=item):
                value["forbidden_paths"] = [item]
                with self.assertRaises(PolicyError):
                    parse_policy(json.dumps(value).encode(), self.root)

        value["forbidden_paths"] = [items[0], items[0]]
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            parse_policy(json.dumps(value).encode(), self.root)
        value["forbidden_paths"] = [
            {**items[0], "value": f"private/export-{number}.csv"}
            for number in range(129)
        ]
        with self.assertRaisesRegex(PolicyError, "count"):
            parse_policy(json.dumps(value).encode(), self.root)


if __name__ == "__main__":
    unittest.main()
