import re
from dataclasses import dataclass

from first_commit.characters import has_control_characters
from first_commit.git import OBJECT_ID
from first_commit.paths import MEBIBYTE, relative_path_problem
from first_commit.policy_fields import PolicyError

IGNORE_PATH = ".gitleaksignore"
MAX_IGNORE_BYTES = MEBIBYTE
MAX_IGNORE_ENTRIES = 1000
REASON_PREFIX = "# reason:"
FILE_DIGEST_PREFIX = "# file-sha256:"
DIGEST = re.compile(r"[0-9a-f]{64}")
RULE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
LINE_NUMBER = re.compile(r"[0-9]{1,10}")
GLOBAL_FIELDS = 3
COMMIT_FIELDS = 4
FORMAT_HELP = (
    "'Gitleaks exceptions' in the first-commit ARCHITECTURE.md shows the format"
)
FINGERPRINT_HELP = (
    "use the fingerprint Gitleaks prints with --verbose: <path>:<rule>:<line> for "
    "staged content, or <commit>:<path>:<rule>:<line> for one history commit"
)


class IgnoreFileError(PolicyError):
    pass


@dataclass(frozen=True)
class IgnoreEntry:
    number: int
    commit: str | None
    path: str
    rule: str
    line: int
    sha256: str

    @property
    def source(self) -> str:
        return f"{self.commit}:{self.path}" if self.commit else f":0:{self.path}"


def ignore_file_error(
    problem: str, fix: str, number: int | None = None
) -> IgnoreFileError:
    where = IGNORE_PATH if number is None else f"{IGNORE_PATH} line {number}"
    return IgnoreFileError(f"{where}: {problem}\n  fix: {fix}")


def digest_command(source: str) -> str:
    return f"git show {source} | shasum -a 256"


def _entry(fingerprint: str, number: int, sha256: str) -> IgnoreEntry:
    fields = fingerprint.split(":")
    commit = fields.pop(0) if len(fields) == COMMIT_FIELDS else None
    if (
        len(fields) != GLOBAL_FIELDS
        or (commit is not None and OBJECT_ID.fullmatch(commit) is None)
        or relative_path_problem(fields[0]) is not None
        or RULE.fullmatch(fields[1]) is None
        or LINE_NUMBER.fullmatch(fields[2]) is None
        or int(fields[2]) <= 0
    ):
        raise ignore_file_error(
            "the fingerprint is not a Gitleaks fingerprint", FINGERPRINT_HELP, number
        )
    return IgnoreEntry(number, commit, fields[0], fields[1], int(fields[2]), sha256)


class _FingerprintComments:
    def __init__(self) -> None:
        self.reason = False
        self.sha256: str | None = None

    def read(self, line: str, number: int) -> None:
        lower = line.lower()
        if lower.startswith(REASON_PREFIX):
            self.reason = bool(line[len(REASON_PREFIX) :].strip())
        elif lower.startswith(FILE_DIGEST_PREFIX):
            value = line[len(FILE_DIGEST_PREFIX) :].strip()
            if self.sha256 is not None:
                raise ignore_file_error(
                    "the fingerprint has two file-sha256 lines",
                    "keep one.",
                    number,
                )
            if DIGEST.fullmatch(value) is None:
                raise ignore_file_error(
                    "the file-sha256 value is not 64 lowercase hex digits",
                    "write the SHA-256 of the whole file; " + FORMAT_HELP + ".",
                    number,
                )
            self.sha256 = value

    @property
    def pending(self) -> bool:
        return self.reason or self.sha256 is not None


# Reads lines as Gitleaks does and refuses characters Go and Python read differently.
def _lines(content: bytes) -> list[str]:
    try:
        raw_lines = content.decode("utf-8").removesuffix("\n").split("\n")
    except UnicodeDecodeError as error:
        raise ignore_file_error(
            "the file is not UTF-8 text", "save it as UTF-8 text."
        ) from error
    lines = []
    for number, raw in enumerate(raw_lines, 1):
        line = raw.removesuffix("\r")
        if has_control_characters(line, "\t") or any(
            character.isspace() and character not in " \t" for character in line
        ):
            raise ignore_file_error(
                "the line holds a control character or a space other than space "
                "and tab, which Gitleaks reads differently",
                "delete that character.",
                number,
            )
        lines.append(line.strip(" \t"))
    return lines


def parse_ignore(content: bytes) -> tuple[IgnoreEntry, ...]:
    lines = _lines(content)
    entries: dict[str, IgnoreEntry] = {}
    block = _FingerprintComments()
    for number, line in enumerate(lines, 1):
        if not line:
            block = _FingerprintComments()
        elif line.startswith("#"):
            block.read(line, number)
        elif not block.reason or block.sha256 is None:
            raise ignore_file_error(
                "the fingerprint has no '# reason:' and '# file-sha256:' lines "
                "directly above it",
                "add '# reason: <why this is not a secret>' and '# file-sha256: "
                "<digest of the whole file>' above it; " + FORMAT_HELP + ".",
                number,
            )
        elif line in entries:
            raise ignore_file_error(
                "the fingerprint is a duplicate", "delete one copy.", number
            )
        else:
            entries[line] = _entry(line, number, block.sha256)
            block = _FingerprintComments()
        if len(entries) > MAX_IGNORE_ENTRIES:
            raise ignore_file_error(
                f"the file has more than {MAX_IGNORE_ENTRIES} fingerprints",
                "remove fixed or duplicate exceptions.",
                number,
            )
    if block.pending:
        raise ignore_file_error(
            "the last reason or digest line has no fingerprint below it",
            "add the fingerprint below it, or delete the comment.",
            len(lines),
        )
    return tuple(entries.values())
