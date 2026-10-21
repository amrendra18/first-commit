import json
from pathlib import Path
from unittest.mock import patch

from first_commit.hooks import HTTPS_REPOSITORY, push_check_findings
from first_commit.models import SetupError, Severity
from first_commit.setup_hooks import check_hook_config, configured_source, hook_bytes
from tests.setup_support import REVISION
from tests.support import TemporaryRootTest, initialize_repository

PROJECT = Path(__file__).resolve().parents[1]
STAGED = b"      - id: first-commit-staged\n"
MESSAGE = b"      - id: first-commit-message\n"
STAGED_RULE = "hooks.staged-check"
MESSAGE_RULE = "hooks.message-check"
SHIPPED = hook_bytes(REVISION)


def _local_staged_hook(**changes: object) -> bytes:
    hook = {
        "id": "first-commit-staged",
        "name": "staged",
        "entry": "first-commit hook pre-commit",
        "language": "system",
        "always_run": True,
        "pass_filenames": False,
        "stages": ["pre-commit"],
        **changes,
    }
    local = {"repo": "local", "hooks": [hook]}
    return SHIPPED.replace(STAGED, b"") + f"  - {json.dumps(local)}\n".encode()


def _after(hook: bytes, lines: bytes) -> bytes:
    return SHIPPED.replace(hook, hook + lines)


CASES: tuple[tuple[str, bytes, set[str]], ...] = (
    ("the shipped hook file", SHIPPED, set()),
    ("the old stage name commit", _after(STAGED, b"        stages: [commit]\n"), set()),
    ("a local staged hook", _local_staged_hook(), set()),
    ("no first-commit-staged", SHIPPED.replace(STAGED, b""), {STAGED_RULE}),
    ("no first-commit-message", SHIPPED.replace(MESSAGE, b""), {MESSAGE_RULE}),
    ("staged with args", _after(STAGED, b"        args: [--help]\n"), {STAGED_RULE}),
    (
        "message with an entry",
        _after(MESSAGE, b"        entry: 'true'\n"),
        {MESSAGE_RULE},
    ),
    (
        "staged at pre-push",
        _after(STAGED, b"        stages: [pre-push]\n"),
        {STAGED_RULE},
    ),
    ("staged twice", _after(STAGED, STAGED), {STAGED_RULE}),
    (
        "a local hook with another entry",
        _local_staged_hook(entry="true"),
        {STAGED_RULE},
    ),
)


class HookDeclarationDoctorTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        initialize_repository(self.root)

    def doctor_rules(self, raw: bytes) -> set[str]:
        (self.root / ".pre-commit-config.yaml").write_bytes(raw)
        findings = [
            item
            for item in push_check_findings(self.root)
            if item.rule_id in {STAGED_RULE, MESSAGE_RULE}
        ]
        self.assertTrue(all(item.severity is Severity.WARNING for item in findings))
        return {item.rule_id for item in findings}

    def test_doctor_warns_exactly_where_setup_refuses_the_declaration(self) -> None:
        for label, raw, expected in CASES:
            with self.subTest(label):
                self.assertEqual(expected, self.doctor_rules(raw))
                if expected:
                    with self.assertRaises(SetupError):
                        check_hook_config(raw, REVISION)
                else:
                    check_hook_config(raw, REVISION)

    def test_an_unapproved_source_or_a_malformed_file_gets_both_warnings(self) -> None:
        fork = SHIPPED.replace(
            json.dumps(HTTPS_REPOSITORY).encode(), b'"https://example.com/fork"'
        )
        self.assertNotEqual(SHIPPED, fork)
        for raw in (fork, b"repos: [\n", b"repos: {}\n"):
            with self.subTest(raw=raw[:40]):
                self.assertEqual({STAGED_RULE, MESSAGE_RULE}, self.doctor_rules(raw))

    def test_this_repositorys_own_hook_file_gets_no_warning(self) -> None:
        raw = (PROJECT / ".pre-commit-config.yaml").read_bytes()
        self.assertEqual(set(), self.doctor_rules(raw))


class HookFileDefectTest(TemporaryRootTest):
    def test_a_code_defect_in_the_hook_file_checks_is_not_called_malformed(
        self,
    ) -> None:
        (self.root / ".pre-commit-config.yaml").write_bytes(SHIPPED)
        with (
            patch(
                "first_commit.setup_hooks.approved_source",
                side_effect=TypeError("defect"),
            ),
            self.assertRaisesRegex(TypeError, "defect"),
        ):
            configured_source(self.root)
