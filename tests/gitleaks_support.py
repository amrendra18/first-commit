import contextlib
import functools
import hashlib
import io
import os
import shutil
import tempfile
import unittest
from collections.abc import Callable, Mapping
from contextlib import redirect_stdout
from pathlib import Path
from typing import TypeVar
from unittest import mock

from first_commit import cli
from first_commit.executables import find_executable
from first_commit.gitleaks import REPORT_FOLDER_PREFIX, REPORT_NAME
from first_commit.gitleaks_ignore_format import IGNORE_PATH
from first_commit.gitleaks_scanner import CALIBRATION_INPUT, scanner_platform
from first_commit.models import Result
from tests.support import initialize_repository, run_git

TOKEN = CALIBRATION_INPUT.decode("utf-8").split('"')[1]
SLACK_TOKEN = "xoxb-" + "1234567890123-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"
SLACK_LINE = f'slack = "{SLACK_TOKEN}"\n'
REPORTING_SCANNER = (
    "#!/bin/sh\n"
    "if [ \"$1\" = version ]; then echo '8.30.0'; exit 0; fi\n"
    'if [ "$1" = stdin ]; then exit 10; fi\n'
    "path=\n"
    'for argument in "$@"; do\n'
    '  case "$argument" in\n'
    '    --report-path=*) path="${argument#--report-path=}" ;;\n'
    "  esac\n"
    "done\n"
    'if [ "${FIRST_COMMIT_TEST_MODE-}" = missing ]; then\n'
    '  rm -f "$path"\n'
    "else\n"
    '  cp "$FIRST_COMMIT_TEST_REPORT" "$path"\n'
    "fi\n"
    "exit 10\n"
)
SCANNER_PATH = "/usr/bin:/bin"
ALLOW_NO_SCANNER = "FIRST_COMMIT_TEST_ALLOW_NO_GITLEAKS"
NO_SCANNER = (
    "install the pinned Gitleaks 8.30.0 as .local/bin/gitleaks (setup does) and put "
    ".local/bin on PATH, as scripts/check does; or set "
    f"{ALLOW_NO_SCANNER}=1 to skip this test."
)
Case = TypeVar("Case", bound=unittest.TestCase)


def _require_real_scanner() -> None:
    if os.environ.get(ALLOW_NO_SCANNER) == "1":
        raise unittest.SkipTest(f"Gitleaks is not on PATH and {ALLOW_NO_SCANNER}=1")
    raise AssertionError(NO_SCANNER)


def needs_real_scanner(test: Callable[[Case], None]) -> Callable[[Case], None]:
    @functools.wraps(test)
    def run(case: Case) -> None:
        if shutil.which("gitleaks") is None:
            _require_real_scanner()
        test(case)

    return run


def stop_at_missing_scanner(test_path: str | None) -> Callable[..., str | None]:
    def find(name: str, environment: Mapping[str, str] | None = None) -> str | None:
        found = find_executable(name, environment)
        # A test that changes PATH hides the scanner on purpose and expects the
        # product error, so only a lookup on the unchanged test PATH stops the test.
        if (
            found is None
            and name == "gitleaks"
            and environment is None
            and os.environ.get("PATH") == test_path
        ):
            _require_real_scanner()
        return found

    return find


def stop_tests_at_missing_scanner() -> None:
    if shutil.which("gitleaks") is None:
        mock.patch(
            "first_commit.gitleaks_scanner.find_executable",
            stop_at_missing_scanner(os.environ.get("PATH")),
        ).start()


@contextlib.contextmanager
def trusted_local_scanner(content: bytes):
    digest = hashlib.sha256(content).hexdigest()
    with mock.patch.dict(
        "first_commit.gitleaks_scanner.BINARY_DIGESTS", {scanner_platform(): digest}
    ):
        yield


@contextlib.contextmanager
def recorded_report_folders():
    folders = []
    create = tempfile.mkdtemp

    def record(*arguments, **keywords):
        folder = create(*arguments, **keywords)
        if Path(folder).name.startswith(REPORT_FOLDER_PREFIX):
            folders.append(Path(folder))
        return folder

    with mock.patch("first_commit.gitleaks.tempfile.mkdtemp", side_effect=record):
        yield folders


@contextlib.contextmanager
def captured_reports():
    reports = []
    remove = shutil.rmtree

    def capture(path, *arguments, **keywords):
        if Path(path).name.startswith(REPORT_FOLDER_PREFIX):
            try:
                reports.append((Path(path) / REPORT_NAME).read_bytes())
            except OSError:
                reports.append(b"")
        return remove(path, *arguments, **keywords)

    with mock.patch("first_commit.gitleaks.shutil.rmtree", side_effect=capture):
        yield reports


def write_reporting_scanner(root: Path) -> Path:
    executable = root / "gitleaks"
    executable.write_text(REPORTING_SCANNER, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def commit_fixture(root: Path, *paths: str) -> None:
    run_git(root, "config", "user.email", "fixture@example.net")
    run_git(root, "config", "user.name", "Fixture Person")
    run_git(root, "config", "commit.gpgsign", "false")
    run_git(root, "add", "--", *paths)
    run_git(root, "commit", "-q", "--no-verify", "-m", "feat(fixture): add fixture")


def history_cli(
    root: Path, arguments: tuple[str, ...], environment: dict[str, str]
) -> tuple[int, str]:
    passed = Result("test", ())
    output = io.StringIO()
    with (
        mock.patch.dict("os.environ", environment),
        mock.patch("first_commit.validation.doctor", return_value=passed),
        mock.patch("first_commit.validation.working", return_value=passed),
        mock.patch("first_commit.validation.staged", return_value=passed),
        redirect_stdout(output),
    ):
        code = cli.main((*arguments, "--root", str(root)))
    return code, output.getvalue()


def pushed_base_commit(root: Path) -> str:
    initialize_repository(root)
    (root / ".repo-policy.json").write_text('{"schema_version":1}\n', "utf-8")
    (root / "base.txt").write_text("base\n", encoding="utf-8")
    commit_fixture(root, "base.txt")
    head = run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
    run_git(root, "update-ref", "refs/remotes/origin/main", head)
    return head


def stage_allowed_slack_token(root: Path) -> None:
    (root / "config.txt").write_text(SLACK_LINE, encoding="utf-8")
    digest = hashlib.sha256(SLACK_LINE.encode()).hexdigest()
    (root / IGNORE_PATH).write_text(
        f"# reason: Synthetic fixture token.\n# file-sha256: {digest}\n"
        "config.txt:slack-bot-token:1\n",
        encoding="utf-8",
    )
    run_git(root, "add", "--", "config.txt", IGNORE_PATH)
