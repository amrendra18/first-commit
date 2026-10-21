import json
import tempfile
import unittest
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from first_commit.contributor import Contributor
from first_commit.finding_collector import FindingCollector, evaluate
from first_commit.models import Candidate, Finding, Origin, Result, Severity
from first_commit.policy import REQUIRED_DOCUMENTS, Policy, parse_policy
from first_commit.reporting import json_value
from tests.support import initialize_repository, run_git

TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
PUBLIC_EMAIL = "maintainers@" + "first-commit-project.dev"
IDENTITY = {
    "user.name": "Example",
    "user.email": "public@example.net",
    "user.signingkey": "key.pub",
    "gpg.format": "ssh",
    "commit.gpgsign": "true",
    "tag.gpgsign": "true",
    "user.useConfigOnly": "true",
}


def evaluate_candidates(
    scope: str,
    candidates: Iterable[Candidate],
    policy: Policy,
    documents: Mapping[str, Candidate],
    private_values: Sequence[str] = (),
) -> Result:
    found = FindingCollector(policy.max_findings)
    evaluate(found, candidates, policy, documents, private_values)
    return found.result(scope)


def render_json(result: Result, *, setup_hook: bool = True) -> str:
    value = json_value(result, setup_hook=setup_hook)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@contextmanager
def commit_identity(
    author: str = IDENTITY["user.email"], committer: str = IDENTITY["user.email"]
) -> Iterator[None]:
    with mock.patch.dict(
        "os.environ",
        {
            "GIT_AUTHOR_NAME": IDENTITY["user.name"],
            "GIT_AUTHOR_EMAIL": author,
            "GIT_COMMITTER_NAME": IDENTITY["user.name"],
            "GIT_COMMITTER_EMAIL": committer,
        },
    ):
        yield


class ValidationFixture(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = parse_policy(b'{"schema_version":1}', self.root)
        self.marker = Finding(
            rule_id="text.no-commit",
            severity=Severity.ERROR,
            path="draft.txt",
            summary="Review marker remains.",
            line=1,
        )
        self.candidate = Candidate("draft.txt", b"# @no-commit\n", Origin.WORKTREE)

    def public_email_repository(self) -> tuple[Path, Contributor]:
        initialize_repository(self.root)
        self.write_documents()
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        (self.root / "SECURITY.txt").write_text(
            "Report issues to " + PUBLIC_EMAIL + ".\n", encoding="utf-8"
        )
        run_git(
            self.root,
            "add",
            "--",
            *REQUIRED_DOCUMENTS,
            ".gitignore",
            "SECURITY.txt",
        )
        message_path = self.root / ".local/message"
        message_path.parent.mkdir()
        person = Contributor("Example", IDENTITY["user.email"], "key.pub")
        return message_path, person

    def write_documents(self) -> None:
        for path in REQUIRED_DOCUMENTS:
            (self.root / path).write_text("# Reviewed\n", encoding="utf-8")

    def private_repository(self, canary: str) -> tuple[str, ...]:
        initialize_repository(self.root)
        self.write_documents()
        (self.root / ".gitignore").write_text(".local/\n", encoding="utf-8")
        private = self.root / self.policy.private_values_file
        private.parent.mkdir(parents=True)
        private.write_text(canary + "\n", encoding="utf-8")
        private.chmod(0o600)
        return (canary.casefold(),)
