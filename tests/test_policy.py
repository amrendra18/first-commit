import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from first_commit.contributor import Contributor, ContributorError
from first_commit.models import Candidate, Origin
from first_commit.policy import REQUIRED_DOCUMENTS, load_policy, parse_policy
from first_commit.policy_fields import PolicyError
from tests.support import TemporaryRootTest
from tests.validation_support import evaluate_candidates


class PolicyTest(TemporaryRootTest):
    def test_minimal_policy_enables_universal_checks_without_switches(self) -> None:
        policy = parse_policy(b'{"schema_version":1}', self.root)
        self.assertFalse(hasattr(policy, "gitleaks_version"))
        self.assertEqual(
            ".local/first-commit/private-values.txt", policy.private_values_file
        )
        self.assertEqual((), policy.contributor_emails)
        self.assertEqual((), policy.detector_exceptions)
        self.assertEqual((), policy.forbidden_paths)
        self.assertFalse(hasattr(policy, "coverage_reports"))

    def test_required_documents_are_fixed_and_cannot_be_extended(self) -> None:
        self.assertEqual(("README.md", "AGENTS.md"), REQUIRED_DOCUMENTS)
        policy = parse_policy(b'{"schema_version":1}', self.root)
        self.assertFalse(hasattr(policy, "required_documents"))
        with self.assertRaises(PolicyError):
            parse_policy(
                b'{"schema_version":1,"additional_documents":["docs/extra.md"]}',
                self.root,
            )

    def test_retired_fields_are_refused_as_unknown_fields(self) -> None:
        canary = "docs/private-upgrade-canary.md"
        for extra in (
            {"additional_documents": [canary]},
            {"coverage": {"path": canary}},
            {"additional_documents": [canary], "coverage_reports": [canary]},
            {"coverage_reports": [canary]},
        ):
            with self.subTest(fields=sorted(extra)):
                value = {"schema_version": 1, **extra}
                with self.assertRaises(PolicyError) as context:
                    parse_policy(json.dumps(value).encode(), self.root)
                self.assertEqual(
                    "The project policy file .repo-policy.json has unknown fields.",
                    str(context.exception),
                )
                self.assertNotIn(canary, str(context.exception))

    def test_project_facts_add_environment_exceptions(self) -> None:
        value = {
            "schema_version": 1,
            "public_environment_files": [
                {"path": "tests/fixtures/.env", "reason": "Synthetic fixture."}
            ],
        }
        policy = parse_policy(json.dumps(value).encode(), self.root)
        self.assertEqual("tests/fixtures/.env", policy.environment_exceptions[0].path)

    def test_local_contributor_supplies_only_public_email_exception(self) -> None:
        address = "public@" + "example.net"
        person = Contributor("Example", address, "key.pub")
        policy = parse_policy(b'{"schema_version":1}', self.root, person)
        self.assertEqual((address,), policy.contributor_emails)

    def test_public_emails_are_content_facts_not_author_identity(self) -> None:
        domain = "@" + "first-commit-project.dev"
        addresses = ["maintainers" + domain, "security" + domain]
        person = Contributor("Example", "public@" + "example.net", "key.pub")
        value = {"schema_version": 1, "public_emails": addresses}
        policy = parse_policy(json.dumps(value).encode(), self.root, person)
        self.assertEqual(tuple(addresses), policy.public_emails)
        self.assertEqual((person.email,), policy.contributor_emails)
        minimal = parse_policy(b'{"schema_version":1}', self.root)
        self.assertEqual((), minimal.public_emails)
        for addresses in (
            [],
            [f"user{number}{domain}" for number in range(32)],
            ["a" * (254 - len(domain)) + domain],
            ["first.last+tag%x" + domain],
        ):
            with self.subTest(count=len(addresses)):
                value = {"schema_version": 1, "public_emails": addresses}
                policy = parse_policy(json.dumps(value).encode(), self.root)
                self.assertEqual(tuple(addresses), policy.public_emails)

    def test_public_emails_reject_invalid_values_without_echo(self) -> None:
        canary = "private-email-canary"
        domain = "@" + "first-commit-project.dev"
        valid = canary + domain
        cases = (
            valid,
            {"address": valid},
            None,
            [None],
            [1],
            [True],
            [[valid]],
            [""],
            ["   "],
            [canary],
            [" " + valid],
            [valid + " "],
            [valid + "\n"],
            [canary + "\t" + domain],
            [valid + " " + valid],
            [valid + "," + valid],
            ["<" + valid + ">"],
            ["mailto:" + valid],
            ["Name " + valid],
            [canary + "@localhost"],
            [canary + "@first-commit-project.d"],
            [canary + "@fïrst-commit-project.dev"],
            [valid, valid],
            ["a" * (255 - len(domain)) + domain],
            [f"{canary}{number}{domain}" for number in range(33)],
        )
        for index, emails in enumerate(cases):
            with self.subTest(case=index):
                value = {"schema_version": 1, "public_emails": emails}
                with self.assertRaises(PolicyError) as caught:
                    parse_policy(json.dumps(value).encode(), self.root)
                self.assertNotIn(canary, str(caught.exception))
                self.assertIn("public_emails", str(caught.exception))
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            parse_policy(
                b'{"schema_version":1,"public_emails":[],"public_emails":[]}',
                self.root,
            )

    def test_commit_body_sections_is_an_optional_boolean(self) -> None:
        minimal = parse_policy(b'{"schema_version":1}', self.root)
        self.assertIsInstance(minimal.commit_body_sections, bool)
        self.assertTrue(minimal.commit_body_sections)
        for enabled in (True, False):
            with self.subTest(setting=enabled):
                value = {"schema_version": 1, "commit_body_sections": enabled}
                policy = parse_policy(json.dumps(value).encode(), self.root)
                self.assertIs(enabled, policy.commit_body_sections)
        canary = "private-sections-canary"
        settings: tuple[object, ...] = (0, 1, "false", "true", None, [], {}, [False])
        for setting in (*settings, canary):
            with self.subTest(setting=setting):
                invalid = {"schema_version": 1, "commit_body_sections": setting}
                with self.assertRaisesRegex(
                    PolicyError, "commit_body_sections must be true or false"
                ) as caught:
                    parse_policy(json.dumps(invalid).encode(), self.root)
                self.assertNotIn(canary, str(caught.exception))

    def test_email_scan_remains_enabled_without_a_local_contributor(self) -> None:
        address = "private@" + "personal.dev"
        candidate = Candidate("source.txt", (address + "\n").encode(), Origin.WORKTREE)
        policy = parse_policy(b'{"schema_version":1}', self.root)
        findings = evaluate_candidates("working", (candidate,), policy, {})
        self.assertIn(
            "privacy.unapproved-email", {item.rule_id for item in findings.findings}
        )
        person = Contributor("Example", address, "key.pub")
        policy = parse_policy(b'{"schema_version":1}', self.root, person)
        findings = evaluate_candidates("working", (candidate,), policy, {})
        self.assertNotIn(
            "privacy.unapproved-email", {item.rule_id for item in findings.findings}
        )

    def test_rejects_old_schema_unknown_fields_duplicates_and_unsafe_paths(
        self,
    ) -> None:
        for raw in (
            b'{"schema_version":1,"project":{"name":"old"}}',
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":true}',
            b'{"schema_version":2}',
            b'["schema_version"]',
            (
                b'{"schema_version":1,"public_environment_files":'
                b'[{"path":"../outside","reason":"escapes"}]}'
            ),
            (
                b'{"schema_version":1,"public_environment_files":'
                b'[{"path":"*.env","reason":"too broad"}]}'
            ),
        ):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(PolicyError):
                    parse_policy(raw, self.root)

    def test_rejections_are_strict_and_do_not_echo_input(self) -> None:
        canary = "private-configuration-canary"
        environment = '{"path":"fixtures/.env","reason":"Synthetic fixture."}'
        cases = [
            '{"schema_version":1,' + json.dumps(canary) + ":true}",
            (
                '{"schema_version":1,"forbidden_paths":[{"match":"exact",'
                '"value":"report","value":"report","reason":"Generated."}]}'
            ),
            '{"schema_version":1,"public_environment_files":[{"path":"a.env",'
            '"path":' + json.dumps(canary) + ',"reason":"Synthetic fixture."}]}',
            '{"schema_version":1,"public_environment_files":['
            + environment
            + ","
            + environment
            + "]}",
            (
                '{"schema_version":1,"public_environment_files":'
                '[{"path":"fixtures/test.env","reason":"   "}]}'
            ),
        ]
        cases.extend(
            json.dumps({"schema_version": version})
            for version in (1.0, "1", None, False)
        )
        cases.extend(
            json.dumps(
                {
                    "schema_version": 1,
                    "public_environment_files": [
                        {"path": path, "reason": "Synthetic fixture."}
                    ],
                }
            )
            for path in (
                ".",
                "docs//" + canary,
                "docs/./" + canary,
                "docs/" + canary + "/",
                "/" + canary,
                "~/" + canary,
                "docs\\" + canary,
                canary + "\0",
                canary + "\n",
            )
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(PolicyError) as context:
                    parse_policy(raw.encode(), self.root)
                self.assertNotIn(canary, str(context.exception))

    def test_loader_reads_only_confined_regular_policy(self) -> None:
        path = self.root / ".repo-policy.json"
        path.write_text('{"schema_version":1}\n', encoding="utf-8")
        policy = load_policy(path, self.root)
        self.assertEqual((), policy.environment_exceptions)
        path.unlink()
        path.symlink_to(self.root / "missing")
        with self.assertRaises(PolicyError):
            load_policy(path, self.root)
        with tempfile.TemporaryDirectory() as outside:
            external = Path(outside) / "external.json"
            external.write_text('{"schema_version":1}\n', encoding="utf-8")
            path.unlink()
            path.symlink_to(external)
            with self.assertRaisesRegex(PolicyError, "regular file"):
                load_policy(path, self.root)

    def test_other_invalid_shapes_and_confined_paths(self) -> None:
        cases = (
            {"schema_version": 1, "forbidden_paths": [{"match": "exact"}]},
            {"schema_version": 1, "forbidden_paths": "not-a-list"},
            {
                "schema_version": 1,
                "public_environment_files": [
                    {"path": "", "reason": "Synthetic fixture."}
                ],
            },
            {
                "schema_version": 1,
                "public_environment_files": [{"path": "x", "reason": ""}],
            },
            {
                "schema_version": 1,
                "public_environment_files": [
                    {"path": "fixtures/.env", "reason": "one"},
                    {"path": "fixtures/.env", "reason": "two"},
                ],
            },
            {"schema_version": 1, "private_literal_exceptions": [{"path": "x"}]},
        )
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(PolicyError):
                    parse_policy(json.dumps(value).encode(), self.root)
        with self.assertRaises(PolicyError):
            parse_policy(b"\xff", self.root)
        with self.assertRaisesRegex(PolicyError, "size limit"):
            parse_policy(b"x" * (1024 * 1024 + 1), self.root)
        with tempfile.TemporaryDirectory() as outside:
            (self.root / "outside-link").symlink_to(outside, target_is_directory=True)
            value = {
                "schema_version": 1,
                "public_environment_files": [
                    {"path": "outside-link/doc.md", "reason": "Synthetic fixture."}
                ],
            }
            with self.assertRaisesRegex(PolicyError, "escapes"):
                parse_policy(json.dumps(value).encode(), self.root)

    def test_deeply_nested_policy_is_invalid_json(self) -> None:
        nested = b"[" * 200_000 + b"]" * 200_000
        with self.assertRaisesRegex(PolicyError, "not valid UTF-8 JSON"):
            parse_policy(nested, self.root)

    def test_loader_names_a_missing_policy_and_keeps_the_record_cause(self) -> None:
        path = self.root / ".repo-policy.json"
        with self.assertRaisesRegex(PolicyError, r"\.repo-policy\.json does not exist"):
            load_policy(path, self.root)
        path.write_text('{"schema_version":1}\n', encoding="utf-8")
        with patch(
            "first_commit.policy.load_contributor",
            side_effect=ContributorError("synthetic-canary"),
        ):
            with self.assertRaises(ContributorError) as error:
                load_policy(path, self.root)
        self.assertEqual(
            "synthetic-canary\nfix: delete .local/first-commit/contributor.json and "
            "run `first-commit setup`.",
            str(error.exception),
        )

    def test_invalid_entry_fields_name_the_accepted_fields(self) -> None:
        readme_shaped = {"exact": "secrets.txt", "reason": "Private notes."}
        value = {"schema_version": 1, "forbidden_paths": [readme_shaped]}
        with self.assertRaises(PolicyError) as context:
            parse_policy(json.dumps(value).encode(), self.root)
        self.assertEqual(
            "forbidden_paths[0] has invalid fields; use exactly match, reason, value.",
            str(context.exception),
        )
