import ast
import re
import unittest
from collections.abc import Iterator
from pathlib import Path

from first_commit import __version__
from first_commit.generated_files import HOOK_PROPOSAL
from first_commit.hooks import HTTPS_REPOSITORY
from first_commit.models import SetupError
from first_commit.setup import SetupRequest, hook_proposal_error, setup_repository
from first_commit.setup_hooks import HooksMissingError
from tests.setup_support import REVISION, SetupFixture

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "first_commit"
HOOK_DECLARATIONS = PACKAGE.parents[1] / ".pre-commit-hooks.yaml"
USER_FACING_KEYWORDS = ("summary", "help", "description")
# Tool-internal words a user cannot act on: name the file, setting, or step instead.
INTERNAL_WORDS = re.compile(
    r"\bcandidates?\b|\bblobs?\b|\bgitlinks?\b|\bpreserve (?:and \w+ )?it\b",
    re.IGNORECASE,
)
PLACEHOLDER = "{}"
# A leading value, then ": ", " ", or a new line, then the message's own text.
LEADING_PLACEHOLDER = re.compile(r"\{\}(?::? |\n)")


def _text(node: ast.expr, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
            else PLACEHOLDER
            for part in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _text(node.left, constants), _text(node.right, constants)
        return left + right if left is not None and right is not None else None
    return None


def _constants(trees: dict[Path, ast.Module]) -> dict[str, str]:
    constants: dict[str, str] = {}
    for tree in trees.values():
        for statement in tree.body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                text = _text(statement.value, constants)
                if isinstance(target, ast.Name) and text is not None:
                    constants[target.id] = text
    return constants


def _class_name(call: ast.Call) -> str:
    function = call.func
    if isinstance(function, ast.Attribute):
        return function.attr
    return function.id if isinstance(function, ast.Name) else ""


def _trees() -> dict[Path, ast.Module]:
    return {
        path: ast.parse(path.read_text("utf-8"), str(path))
        for path in sorted(PACKAGE.rglob("*.py"))
    }


def error_messages() -> Iterator[tuple[str, str]]:
    trees = _trees()
    constants = _constants(trees)
    for path, tree in trees.items():
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not call.args:
                continue
            name = _class_name(call)
            if not (name[:1].isupper() and name.endswith("Error")):
                continue
            message = _text(call.args[0], constants)
            if message is not None:
                yield f"{path.relative_to(PACKAGE)}:{call.lineno}", message


# Finding summaries, help and description text, and hook descriptions also reach users.
def user_facing_texts() -> Iterator[tuple[str, str]]:
    yield from error_messages()
    trees = _trees()
    constants = _constants(trees)
    for path, tree in trees.items():
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            for keyword in call.keywords:
                if keyword.arg in USER_FACING_KEYWORDS:
                    text = _text(keyword.value, constants)
                    if text is not None:
                        yield f"{path.relative_to(PACKAGE)}:{call.lineno}", text
    for number, line in enumerate(HOOK_DECLARATIONS.read_text("utf-8").split("\n"), 1):
        if line.strip().startswith("description:"):
            yield f"{HOOK_DECLARATIONS.name}:{number}", line


# A value at the start needs a separator and words of its own, so a bare value fails.
def follows_style(message: str) -> bool:
    if re.search(r"[A-Za-z]{2}", message.replace(PLACEHOLDER, "")) is None:
        return False
    if message.startswith(PLACEHOLDER):
        starts = LEADING_PLACEHOLDER.match(message) is not None
    else:
        starts = message[:1].isupper()
    ends = message.endswith((".", PLACEHOLDER))
    return starts and ends


class ErrorMessageStyleTest(unittest.TestCase):
    def test_every_error_message_is_a_sentence(self) -> None:
        messages = list(error_messages())
        self.assertGreater(len(messages), 150)
        unlike = [
            f"{where}: {message}"
            for where, message in messages
            if not follows_style(message)
        ]
        self.assertEqual([], unlike)

    def test_the_style_check_refuses_fragments(self) -> None:
        for message in (
            "Git timed out",
            "file cannot be read.",
            "no period",
            "{}",
            "{}.",
            "{}{}",
            "{}: {}",
            "{}fragment.",
        ):
            with self.subTest(message=message):
                self.assertFalse(follows_style(message))
        for message in ("Git timed out.", "{} must be an array.", "Set {}, then {}"):
            with self.subTest(message=message):
                self.assertTrue(follows_style(message))

    def test_user_facing_text_uses_no_internal_words(self) -> None:
        texts = list(user_facing_texts())
        self.assertGreater(len(texts), 250)
        internal = [
            f"{where}: {text}" for where, text in texts if INTERNAL_WORDS.search(text)
        ]
        self.assertEqual([], internal)

    def test_the_internal_word_check_refuses_each_word(self) -> None:
        for text in (
            "Candidate cannot be read.",
            "Staged candidates exceed the limit.",
            "Staged file has no index blob.",
            "Staged path is a submodule gitlink.",
            "Lock path is unsafe; preserve it.",
            "Lock path is unsafe; preserve and inspect it.",
        ):
            with self.subTest(text=text):
                self.assertIsNotNone(INTERNAL_WORDS.search(text))
        for text in ("Staged file cannot be read.", "Preserve unrelated work."):
            with self.subTest(text=text):
                self.assertIsNone(INTERNAL_WORDS.search(text))


class SetupRefusalFixTest(SetupFixture):
    def refusal(self, request: SetupRequest) -> str:
        with self.assertRaises(SetupError) as refusal:
            setup_repository(self.root, request, contributor=self.person)
        return str(refusal.exception)

    def test_a_different_license_names_how_to_continue(self) -> None:
        (self.root / "LICENSE").write_text("Own license\n", encoding="utf-8")
        request = SetupRequest(revision=REVISION, license_choice="apache-2.0")
        self.assertEqual(
            "Existing LICENSE differs from the Apache-2.0 text, so setup leaves it "
            "unchanged.\n"
            "fix: keep your LICENSE and rerun setup without --license apache-2.0, or "
            "delete LICENSE and rerun setup to write the Apache-2.0 text.",
            self.refusal(request),
        )

    def test_a_missing_revision_names_the_command_that_finds_it(self) -> None:
        self.assertEqual(
            "Setup needs an immutable Git revision; use --revision FULL_SHA.\n"
            f"fix: run `git ls-remote {HTTPS_REPOSITORY} 'v{__version__}^{{}}'` to "
            "print the release tag's commit, then rerun setup with --revision and "
            "that 40-character SHA.",
            self.refusal(SetupRequest(dry_run=True)),
        )

    def test_a_hook_proposal_without_a_revision_names_the_command_that_finds_it(
        self,
    ) -> None:
        missing = HooksMissingError(("first-commit-push",))
        refusal = hook_proposal_error(self.root, missing, dry_run=False)
        self.assertEqual(
            f"{missing}\n"
            f"fix: run `git ls-remote {HTTPS_REPOSITORY} 'v{__version__}^{{}}'` to "
            "print the release tag's commit, then rerun setup with --revision and "
            f"that 40-character SHA to write the block to merge to {HOOK_PROPOSAL}.",
            str(refusal),
        )
        self.assertFalse((self.root / HOOK_PROPOSAL).exists())


if __name__ == "__main__":
    unittest.main()
