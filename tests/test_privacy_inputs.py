import hashlib
import re
import unittest
from collections.abc import Callable
from functools import partial

from first_commit.checks.privacy import PrivacyPolicy, privacy_findings
from first_commit.checks.text import text_findings
from first_commit.contributor import EMAIL, email_spans
from first_commit.models import Candidate, Origin
from first_commit.policy_fields import DetectorExceptionEntry
from tests.timing_support import LINEAR_GROWTH_LIMIT, growth

LINE_CHARACTERS = 15_000
OLD_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
TOKEN = "ghp_" + "A" * 36
HOME = "/Users/" + "someone/"
ADDRESS = "person@" + "corp.net"


def _rules(content: bytes, policy: PrivacyPolicy | None = None) -> list[str]:
    candidate = Candidate("data.bin", content, Origin.INDEX)
    return [
        item.rule_id
        for item in privacy_findings(
            candidate, policy or PrivacyPolicy(), max_findings=1000
        )
    ]


def _search(line: Callable[[int], str], size: int) -> None:
    text = line(size)
    candidate = Candidate("long.txt", text.encode() + b"\n", Origin.INDEX)
    privacy_findings(candidate, PrivacyPolicy(), max_findings=1000)
    EMAIL.fullmatch(text)


class LinearAddressSearchTest(unittest.TestCase):
    def test_long_lines_are_searched_in_linear_time(self) -> None:
        lines: tuple[tuple[str, Callable[[int], str]], ...] = (
            ("letters", lambda size: "a" * size),
            ("dotted", lambda size: "a." * (size // 2)),
            ("at signs", lambda size: "a@" * (size // 2)),
            ("long domain", lambda size: "a@" + "b" * size),
        )
        for name, line in lines:
            with self.subTest(name=name):
                self.assertLess(
                    growth(partial(_search, line), LINE_CHARACTERS),
                    LINEAR_GROWTH_LIMIT,
                )

    def test_spans_match_the_address_pattern(self) -> None:
        at = "@"
        for text in (
            "",
            "plain text",
            f"a{at}b.com",
            f"x a{at}b.com.x{at}c.org y",
            f"a{at}b{at}c.com",
            f"first.last+tag{at}sub.example.co.uk, second{at}host.io",
            f"{at}leading.com trailing{at} end{at}x.y",
            f"%odd%{at}domain-with-dash.example",
            f"a{at}b.c a{at}b.cd",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    [match.span() for match in OLD_EMAIL.finditer(text)],
                    list(email_spans(text)),
                )

    def test_full_match_still_validates_one_address(self) -> None:
        self.assertIsNotNone(EMAIL.fullmatch("person@example.com"))
        self.assertIsNone(EMAIL.fullmatch("person@example"))
        self.assertIsNone(EMAIL.fullmatch("person example.com"))


class HomePathTest(unittest.TestCase):
    def test_a_home_path_followed_by_punctuation_is_detected(self) -> None:
        name = "/Users/" + "someone"
        for text in (
            '{"cwd": "' + name + '"}',
            "HOME=" + name + ";",
            "see " + name + ", then",
            "alice:x:1000:1000::/home/" + "alice:/bin/bash",
            name + "/project",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    ["privacy.user-home-path"], _rules(text.encode() + b"\n")
                )


class RawBytePrivacyTest(unittest.TestCase):
    def test_one_nul_byte_keeps_every_privacy_rule_active(self) -> None:
        content = (
            b"\0header\n"
            + TOKEN.encode()
            + b"\n"
            + HOME.encode()
            + b"\n"
            + ADDRESS.encode()
            + b"\nprivate-canary\n"
        )
        rules = _rules(content, PrivacyPolicy(private_values=("private-canary",)))

        self.assertEqual(
            [
                "privacy.github-token",
                "privacy.user-home-path",
                "privacy.unapproved-email",
                "privacy.private-literal",
            ],
            rules,
        )

    def test_invalid_utf8_content_keeps_privacy_rules_active(self) -> None:
        self.assertEqual(
            ["privacy.github-token"], _rules(b"\xff\xfe " + TOKEN.encode() + b"\n")
        )

    def test_text_rules_still_skip_binary_content(self) -> None:
        candidate = Candidate("data.bin", b"\0 trailing \n", Origin.INDEX)

        self.assertEqual([], text_findings(candidate, max_findings=1000))

    def test_exceptions_hash_the_raw_line_bytes(self) -> None:
        line = b"\xff " + HOME.encode()
        policy = PrivacyPolicy(
            detector_exceptions=(
                DetectorExceptionEntry(
                    path="data.bin",
                    line=2,
                    rule="privacy.user-home-path",
                    sha256=hashlib.sha256(line).hexdigest(),
                    reason="Synthetic fixture.",
                ),
            )
        )

        self.assertEqual([], _rules(b"\0\n" + line + b"\n", policy))
        self.assertEqual(["privacy.user-home-path"], _rules(b"\0\n" + line + b"\n"))

    def test_findings_never_hold_the_matched_bytes(self) -> None:
        candidate = Candidate("data.bin", b"\0" + TOKEN.encode(), Origin.INDEX)

        self.assertNotIn(
            TOKEN, repr(privacy_findings(candidate, PrivacyPolicy(), max_findings=1000))
        )


def _exception(rule: str, line: int, digest: bytes) -> PrivacyPolicy:
    return PrivacyPolicy(
        detector_exceptions=(
            DetectorExceptionEntry(
                path="data.bin",
                line=line,
                rule=rule,
                sha256=hashlib.sha256(digest).hexdigest(),
                reason="Synthetic fixture.",
            ),
        )
    )


class Utf16PrivacyTest(unittest.TestCase):
    def test_utf16_content_with_a_byte_order_mark_is_checked(self) -> None:
        text = f"{TOKEN}\n{HOME}\n{ADDRESS}\n"
        for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
            content = text.encode(encoding)
            if encoding != "utf-16":
                content = "\ufeff".encode(encoding) + content
            with self.subTest(encoding=encoding):
                self.assertEqual(
                    [
                        "privacy.github-token",
                        "privacy.user-home-path",
                        "privacy.unapproved-email",
                    ],
                    _rules(content),
                )

    def test_a_byte_order_mark_does_not_hide_utf8_content(self) -> None:
        self.assertEqual(["privacy.github-token"], _rules(b"\xfe\xff" + TOKEN.encode()))

    def test_utf16_exceptions_hash_the_decoded_line_as_utf8(self) -> None:
        content = f"note\n{HOME}\n".encode("utf-16")
        policy = _exception("privacy.user-home-path", 2, HOME.encode())

        self.assertEqual([], _rules(content, policy))


class PrivateKeyExceptionTest(unittest.TestCase):
    # Split so this file holds no private-key block.
    HEADER = b"-----BEGIN RSA " + b"PRIVATE KEY-----"

    def key(self, fill: bytes) -> bytes:
        return b"before\n" + self.HEADER + b"\n" + fill * 64 + b"\n"

    def test_a_private_key_exception_binds_the_whole_file(self) -> None:
        reviewed = self.key(b"A")
        rule = "privacy.private-key"

        self.assertEqual([], _rules(reviewed, _exception(rule, 2, reviewed)))
        self.assertEqual([rule], _rules(self.key(b"B"), _exception(rule, 2, reviewed)))
        # Every key of one type starts with the same line, so its digest approves none.
        self.assertEqual([rule], _rules(reviewed, _exception(rule, 2, self.HEADER)))
        self.assertEqual([rule], _rules(reviewed, _exception(rule, 1, reviewed)))


if __name__ == "__main__":
    unittest.main()
