import json

from first_commit.policy import parse_policy
from first_commit.policy_fields import PolicyError
from tests.support import TemporaryRootTest

DIGEST = "0" * 64
REASON = "Synthetic fixture."
VALID_ENTRIES: dict[str, dict[str, object]] = {
    "public_environment_files": {"path": "fixtures/.env", "reason": REASON},
    "private_literal_exceptions": {
        "path": "docs/public.md",
        "line": 1,
        "sha256": DIGEST,
        "reason": REASON,
    },
    "privacy_detector_exceptions": {
        "path": "docs/public.md",
        "line": 1,
        "rule": "privacy.github-token",
        "sha256": DIGEST,
        "reason": REASON,
    },
    "forbidden_paths": {"match": "exact", "value": "secret.txt", "reason": REASON},
    "immutable_vendor_files": {
        "path": "vendor/lib.js",
        "sha256": DIGEST,
        "reason": REASON,
    },
}
# A change to each valid entry that keeps it valid and makes it a new entry.
OTHER_ENTRY: dict[str, dict[str, object]] = {
    "public_environment_files": {"path": "fixtures/other.env"},
    "private_literal_exceptions": {"path": "docs/other.md"},
    "privacy_detector_exceptions": {"path": "docs/other.md"},
    "forbidden_paths": {"value": "other.txt"},
    "immutable_vendor_files": {"path": "vendor/other.js"},
}
REASON_RULE = (
    "must be one line of at most 500 characters, without control characters or "
    "surrounding spaces."
)


class PolicyLabelTest(TemporaryRootTest):
    def refusal(self, value: dict[str, object]) -> str:
        with self.assertRaises(PolicyError) as caught:
            parse_policy(json.dumps({"schema_version": 1, **value}).encode(), self.root)
        return str(caught.exception)

    def second_entry(self, field: str, **change: object) -> dict[str, object]:
        return {field: [VALID_ENTRIES[field], {**VALID_ENTRIES[field], **change}]}

    def test_each_error_names_the_field_path_of_its_entry(self) -> None:
        env, literal, detector, forbidden, vendor = VALID_ENTRIES
        cases: tuple[tuple[dict[str, object], str], ...] = (
            (
                self.second_entry(env, path="fixtures/*.env"),
                f"{env}[1].path must be an exact path without glob characters.",
            ),
            (
                self.second_entry(env, path="../outside"),
                (
                    f"{env}[1].path must be a normalized repository-relative path: "
                    "it has a '..' part."
                ),
            ),
            (
                {env: [{"path": "a"}]},
                f"{env}[0] has invalid fields; use exactly path, reason.",
            ),
            ({env: {}}, f"{env} must be an array."),
            (
                self.second_entry(literal, line=0),
                f"{literal}[1].line must be a line number from 1 to 10485760.",
            ),
            (
                self.second_entry(literal, sha256="A" * 64),
                (
                    f"{literal}[1].sha256 must be a SHA-256 digest of 64 lowercase hex "
                    "digits."
                ),
            ),
            (
                self.second_entry(detector, rule="privacy.other"),
                f"{detector}[1].rule must name a supported privacy rule.",
            ),
            (
                self.second_entry(forbidden, match="glob"),
                f"{forbidden}[1].match must be exact, prefix, or suffix.",
            ),
            (
                self.second_entry(forbidden, match="prefix", value="build"),
                f"{forbidden}[1].value must be a path ending in '/'.",
            ),
            (
                self.second_entry(forbidden, match="suffix", value="pem"),
                f"{forbidden}[1].value must be a normalized extension.",
            ),
            (
                self.second_entry(vendor, path="lib/x.js"),
                f"{vendor}[1].path must be exact and under vendor/.",
            ),
            (
                {"public_emails": ["a@example.org", "not-an-address"]},
                "public_emails[1] must be a single email address.",
            ),
            (
                {"public_emails": ["a" * 243 + "@example.org"]},
                "public_emails[0] is longer than 254 characters.",
            ),
        )
        for value, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, self.refusal(value))

    def test_a_duplicate_names_the_later_entry(self) -> None:
        for field, key in (
            ("public_environment_files", "path"),
            ("private_literal_exceptions", "path and line"),
            ("privacy_detector_exceptions", "path, line, and rule"),
            ("forbidden_paths", "match and value"),
            ("immutable_vendor_files", "path"),
        ):
            with self.subTest(field=field):
                entry = VALID_ENTRIES[field]
                entries = [
                    entry,
                    {**entry, **OTHER_ENTRY[field]},
                    {**entry, "reason": "Other."},
                ]
                self.assertEqual(
                    f"{field}[2] duplicates the {key} of an earlier entry.",
                    self.refusal({field: entries}),
                )
        self.assertEqual(
            "public_emails[1] duplicates the address of an earlier entry.",
            self.refusal({"public_emails": ["a@example.org", "a@example.org"]}),
        )

    def test_a_count_over_the_limit_names_the_field_and_the_limit(self) -> None:
        for field, limit in (
            ("public_emails", 32),
            ("private_literal_exceptions", 128),
            ("privacy_detector_exceptions", 128),
            ("forbidden_paths", 128),
            ("immutable_vendor_files", 10_000),
        ):
            with self.subTest(field=field):
                self.assertEqual(
                    f"{field} count exceeds the limit of {limit}.",
                    self.refusal({field: [None] * (limit + 1)}),
                )

    def test_every_reason_is_bounded_single_line_text(self) -> None:
        for field in VALID_ENTRIES:
            for reason in (
                "x" * 501,
                "Approved\x1b[31m fixture.",
                "Approved\nfixture.",
                " Approved fixture.",
            ):
                with self.subTest(field=field, reason=reason[:12]):
                    self.assertEqual(
                        f"{field}[1].reason {REASON_RULE}",
                        self.refusal(self.second_entry(field, reason=reason)),
                    )
            with self.subTest(field=field, reason="500 characters"):
                longest = self.second_entry(
                    field, reason="x" * 500, **OTHER_ENTRY[field]
                )
                parse_policy(
                    json.dumps({"schema_version": 1, **longest}).encode(), self.root
                )
