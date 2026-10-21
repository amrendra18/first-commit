import importlib
import json
from pathlib import Path
from typing import Any
from unittest import mock

from first_commit.hooks import HOOK_IDS, push_check_findings
from first_commit.models import SetupError
from first_commit.setup_hooks import HooksMissingError, check_hook_config, hook_bytes
from tests.setup_support import REVISION
from tests.support import TemporaryRootTest, initialize_repository, run_git

ROOT = Path(__file__).resolve().parents[1]
PUSH_HOOK = b"      - id: first-commit-push\n"
CHECK = {
    "id": "project-push",
    "name": "push checks",
    "entry": "first-commit hook pre-push",
    "language": "system",
    "always_run": True,
    "pass_filenames": False,
    "stages": ["pre-push"],
}
REFUSED: tuple[tuple[str, dict[str, Any]], ...] = (
    ("no always_run", {"always_run": None}),
    ("a files filter", {"always_run": False, "files": "^nothing$"}),
    ("--help", {"args": ["--help"]}),
    ("-h", {"args": ["-h"]}),
    ("pygrep", {"language": "pygrep", "pass_filenames": None}),
    ("types", {"types": ["python"]}),
    ("types_or", {"types_or": ["python"]}),
    ("exclude", {"exclude": "^src/"}),
    ("file names", {"pass_filenames": True}),
    ("manual stage", {"stages": ["manual"]}),
    ("--root", {"args": ["--root", "../other"]}),
    ("--format without a value", {"args": ["--format"]}),
    ("an unknown --format value", {"args": ["--format", "xml"]}),
    ("an extra argument", {"args": ["--format", "json", "extra"]}),
    ("check", {"entry": "first-commit check"}),
    ("no stages", {"stages": None}),
)
ACCEPTED: tuple[tuple[str, dict[str, Any]], ...] = (
    ("the plain hook", {}),
    ("bin/ with --format", {"entry": "bin/first-commit hook pre-push --format json"}),
    ("--format in args", {"args": ["--format", "human"]}),
    ("the old stage name push", {"stages": ["push"]}),
)


def pre_commit_stage(name: str) -> str:
    clientlib = importlib.import_module("pre_commit.clientlib")
    return str(clientlib.transform_stage(name))


def _shaped(changes: dict[str, Any]) -> dict[str, Any]:
    hook = {**CHECK, **changes}
    return {key: value for key, value in hook.items() if value is not None}


def _with_local_hook(hook: dict[str, Any]) -> bytes:
    raw = hook_bytes(REVISION).replace(PUSH_HOOK, b"")
    local = {"repo": "local", "hooks": [hook]}
    return raw + f"  - {json.dumps(local)}\n".encode()


def _hook_at_stage(hook_stage: str, name: str) -> tuple[tuple[str, bytes], ...]:
    identifier = HOOK_IDS[hook_stage]
    line = f"      - id: {identifier}\n".encode()
    shipped = hook_bytes(REVISION).replace(
        line, line + f"        stages: [{name}]\n".encode()
    )
    local = {
        "id": identifier,
        "name": identifier,
        "entry": f"first-commit hook {hook_stage}",
        "language": "system",
        "always_run": True,
        "pass_filenames": False,
        "stages": [name],
    }
    without = hook_bytes(REVISION).replace(line, b"")
    entry = {"repo": "local", "hooks": [local]}
    return (
        ("shipped", shipped),
        ("local", without + f"  - {json.dumps(entry)}\n".encode()),
    )


class PushHookShapeTest(TemporaryRootTest):
    def setUp(self) -> None:
        super().setUp()
        initialize_repository(self.root)

    def doctor_warns(self, raw: bytes) -> bool:
        (self.root / ".pre-commit-config.yaml").write_bytes(raw)
        return any(
            item.rule_id == "hooks.push-check"
            for item in push_check_findings(self.root)
        )

    def test_only_a_hook_that_always_runs_exactly_the_push_hook_counts(self) -> None:
        for label, changes in REFUSED:
            with self.subTest(refused=label):
                raw = _with_local_hook(_shaped(changes))
                self.assertTrue(self.doctor_warns(raw))
                with self.assertRaises(HooksMissingError):
                    check_hook_config(raw, REVISION)
        for label, changes in ACCEPTED:
            with self.subTest(accepted=label):
                raw = _with_local_hook(_shaped(changes))
                self.assertFalse(self.doctor_warns(raw))
                check_hook_config(raw, REVISION)

    def test_a_hook_without_stages_takes_stages_that_may_skip_the_push(self) -> None:
        default_stages = _with_local_hook(_shaped({"stages": None})).replace(
            b"repos:\n", b"default_stages: [pre-commit]\nrepos:\n"
        )
        check_hook = b"      - id: first-commit-check\n"
        overridden = (
            hook_bytes(REVISION)
            .replace(PUSH_HOOK, b"")
            .replace(
                check_hook,
                check_hook.rstrip(b"\n")
                + b"\n        entry: first-commit hook pre-push\n"
                + b"        language: system\n        always_run: true\n"
                + b"        pass_filenames: false\n",
            )
        )
        for label, raw in (
            ("default_stages: [pre-commit]", default_stages),
            ("the check hook with the push entry", overridden),
        ):
            with self.subTest(label):
                self.assertTrue(self.doctor_warns(raw))
                with self.assertRaises(HooksMissingError):
                    check_hook_config(raw, REVISION)

    def test_the_push_hook_id_counts_only_where_it_runs_at_pre_push(self) -> None:
        local_true = {**CHECK, "id": "first-commit-push", "entry": "true"}

        def shipped(extra: bytes) -> bytes:
            return hook_bytes(REVISION).replace(PUSH_HOOK, PUSH_HOOK + extra)

        fork = hook_bytes(REVISION).replace(PUSH_HOOK, b"") + (
            b'  - {"repo": "https://example.invalid/fork", "rev": "'
            + REVISION.encode()
            + b'", "hooks": [{"id": "first-commit-push"}]}\n'
        )
        for label, raw in (
            ("a local hook that runs true", _with_local_hook(local_true)),
            (
                "the shipped hook at the manual stage",
                shipped(b"        stages: [manual]\n"),
            ),
            ("the shipped hook running true", shipped(b'        entry: "true"\n')),
            (
                "the shipped hook with a files filter",
                shipped(b'        always_run: false\n        files: "^nothing$"\n'),
            ),
            ("the shipped hook with --help", shipped(b'        args: ["--help"]\n')),
            ("the push hook from an unapproved fork", fork),
        ):
            with self.subTest(label):
                self.assertTrue(self.doctor_warns(raw))

    def test_the_shipped_hook_counts_at_the_old_stage_name_push(self) -> None:
        raw = hook_bytes(REVISION).replace(
            PUSH_HOOK, PUSH_HOOK + b"        stages: [push]\n"
        )
        self.assertFalse(self.doctor_warns(raw))
        check_hook_config(raw, REVISION)

    def test_every_old_stage_name_counts_as_its_new_name(self) -> None:
        for old, new, hook_stage, counts in (
            ("commit", "pre-commit", "pre-commit", True),
            ("merge-commit", "pre-merge-commit", "pre-commit", False),
            ("push", "pre-push", "pre-push", True),
        ):
            self.assertEqual(new, pre_commit_stage(old))
            for name in (old, new):
                for label, raw in _hook_at_stage(hook_stage, name):
                    with self.subTest(old=old, stages=[name], hook=label):
                        if counts:
                            check_hook_config(raw, REVISION)
                        else:
                            with self.assertRaises(SetupError):
                                check_hook_config(raw, REVISION)

    def test_the_shipped_push_hook_at_another_revision_gets_its_own_warning(
        self,
    ) -> None:
        (self.root / ".pre-commit-config.yaml").write_bytes(hook_bytes(REVISION))
        other = "c" * 40
        for installed, rules in (
            (None, []),
            (REVISION, []),
            (other, ["hooks.push-revision"]),
        ):
            with (
                self.subTest(installed=installed),
                mock.patch(
                    "first_commit.hooks.installed_revision",
                    return_value=installed,
                ),
            ):
                findings = push_check_findings(self.root)
                self.assertEqual(rules, [item.rule_id for item in findings])
        self.assertEqual(
            "The first-commit-push hook is pinned to another first-commit revision, "
            "so pre-push runs that version's checks.",
            findings[0].summary,
        )

    def test_the_installed_revision_is_read_only_for_the_shipped_push_hook(
        self,
    ) -> None:
        raw = _with_local_hook(_shaped({}))
        with mock.patch(
            "first_commit.hooks.installed_revision", return_value="c" * 40
        ) as installed:
            self.assertFalse(self.doctor_warns(raw))
        installed.assert_not_called()

    def test_a_remote_nested_under_another_gets_its_own_warning(self) -> None:
        nested = []
        for names in (("origin", "origin-x"), ("origin", "origin-x", "origin/x")):
            for name in names:
                if name not in nested:
                    run_git(
                        self.root, "remote", "add", name, "https://example.invalid/x"
                    )
                    nested.append(name)
            with self.subTest(names=names):
                rules = [item.rule_id for item in push_check_findings(self.root)]
                self.assertEqual(
                    ["hooks.nested-remote"] if "origin/x" in names else [], rules
                )

    def test_a_remote_nested_in_other_case_gets_the_warning(self) -> None:
        for name in ("origin", "Origin/x"):
            run_git(self.root, "remote", "add", name, "https://example.invalid/x")
        rules = [item.rule_id for item in push_check_findings(self.root)]
        self.assertEqual(["hooks.nested-remote"], rules)

    def test_remotes_that_differ_only_in_case_get_the_case_warning(self) -> None:
        for name in ("origin", "ORIGIN", "upstream"):
            run_git(self.root, "remote", "add", name, "https://example.invalid/x")
        findings = push_check_findings(self.root)
        self.assertEqual(["hooks.remote-case"], [item.rule_id for item in findings])
        self.assertEqual(
            "Two remotes' names differ only in letter case; on a case-insensitive "
            "disk they share refs, so pre-commit may skip the pre-push hooks for a "
            "new branch the other remote has.",
            findings[0].summary,
        )

    def test_the_shipped_hook_and_this_repositorys_hook_file_count(self) -> None:
        for raw in (
            hook_bytes(REVISION),
            (ROOT / ".pre-commit-config.yaml").read_bytes(),
        ):
            self.assertFalse(self.doctor_warns(raw))
