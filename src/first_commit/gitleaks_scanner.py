import hashlib
import os
import platform
import re
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from first_commit.executables import find_executable, path_inside_repository
from first_commit.git import GitError, is_tracked, sanitized_git_environment
from first_commit.paths import MEBIBYTE
from first_commit.setup_command import declares_setup_hook, setup_command


class DependencyError(RuntimeError):
    # The message may add setup advice after the reason; scanner_install names
    # only the reason, inside its own advice.
    def __init__(self, message: str, *, reason: str = "") -> None:
        super().__init__(message)
        self.reason = reason or message.removesuffix(".")


class ScannerTimeoutError(DependencyError):
    pass


SCANNER_VERSION = "8.30.0"
FINDINGS_EXIT = 10
SCAN_TIMEOUT_SECONDS = 120
HISTORY_TIMEOUT_SECONDS = 600
UNTRUSTED_ENVIRONMENT_KEYS = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")
LOCAL_SCANNER_PATH = ".local/bin/gitleaks"
UNSAFE_REASON = (
    f"Local Gitleaks at {LOCAL_SCANNER_PATH} is a link or not a regular file"
)
UNSAFE_LOCAL_SCANNER = UNSAFE_REASON + "; delete it and run setup again."
TRACKED_REASON = (
    f"Local Gitleaks at {LOCAL_SCANNER_PATH} is tracked by Git, so repository "
    "content would choose the scanner"
)
TRACKED_LOCAL_SCANNER = (
    TRACKED_REASON
    + f"; run git rm --cached {LOCAL_SCANNER_PATH}, delete the file, and run setup "
    "again."
)
UNTRUSTED_REASON = (
    f"Local Gitleaks at {LOCAL_SCANNER_PATH} does not match the pinned Gitleaks "
    f"{SCANNER_VERSION} release binary"
)
UNTRUSTED_LOCAL_SCANNER = UNTRUSTED_REASON + "; delete it and run setup again."
UNSUPPORTED_REASON = (
    f"Local Gitleaks at {LOCAL_SCANNER_PATH} cannot be checked on this platform"
)
UNSUPPORTED_LOCAL_SCANNER = (
    UNSUPPORTED_REASON + f"; delete it and install Gitleaks {SCANNER_VERSION} on PATH."
)
MAX_SCANNER_BYTES = 64 * MEBIBYTE
ARCHITECTURES = {"aarch64": "arm64", "arm64": "arm64", "amd64": "x64", "x86_64": "x64"}
# SHA-256 of the gitleaks binary inside each pinned 8.30.0 release archive.
BINARY_DIGESTS = {
    (
        "darwin",
        "arm64",
    ): "095bc4be1624239f52ebb90ff91668d1d3e78e0f8c5286e2d981887905c27561",
    (
        "darwin",
        "x64",
    ): "f478677e8858ec3129153dec6e3f8dab5b5f674c120245e7878f89582444d06f",
    (
        "linux",
        "arm64",
    ): "3957ad3e168b6633307c1d8ea43bffa17557f825027504b13b574899212e635a",
    (
        "linux",
        "x64",
    ): "8b6fd684fcd5b4ebe39b68abb072ce59e1063ce7ed4abd556157697845f1f088",
}
STDIN_ARGUMENTS = (
    "stdin",
    "--redact",
    "--no-banner",
    f"--exit-code={FINDINGS_EXIT}",
    "--ignore-gitleaks-allow",
)
CALIBRATION_INPUT = (
    b'token = "' + b"ghp_" + b"skxSJ9z5EMBO3vXNo2" + b"Ga7qDBKsBMuOsI2XOq" + b'"\n'
)
MAX_VALIDATED = 16
CHECK_FOLDER_PREFIX = "first-commit-scanner-check-"
INSTALL_HINT = f"or install Gitleaks {SCANNER_VERSION} on PATH."
_VALIDATED: set[tuple[object, ...]] = set()


@dataclass(frozen=True)
class Scanner:
    executable: str
    environment: Mapping[str, str] | None


def scanner_platform() -> tuple[str, str]:
    machine = platform.machine().lower()
    return platform.system().lower(), ARCHITECTURES.get(machine, "")


def _environment(value: Mapping[str, str] | None, root: Path) -> dict[str, str]:
    environment = sanitized_git_environment(
        dict(value) if value is not None else os.environ.copy(), root
    )
    for key in UNTRUSTED_ENVIRONMENT_KEYS:
        environment.pop(key, None)
    return environment


def _file_digest(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            if os.fstat(stream.fileno()).st_size > MAX_SCANNER_BYTES:
                raise DependencyError(UNTRUSTED_LOCAL_SCANNER, reason=UNTRUSTED_REASON)
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as error:
        raise DependencyError(
            UNTRUSTED_LOCAL_SCANNER, reason=UNTRUSTED_REASON
        ) from error


def _verify_local_scanner(root: Path) -> None:
    try:
        tracked = is_tracked(root, LOCAL_SCANNER_PATH)
    except GitError as error:
        raise DependencyError(
            f"Git state of {LOCAL_SCANNER_PATH} cannot be determined; run the check "
            "inside its Git repository.",
            reason=f"Git state of {LOCAL_SCANNER_PATH} cannot be determined",
        ) from error
    if tracked:
        raise DependencyError(TRACKED_LOCAL_SCANNER, reason=TRACKED_REASON)
    expected = BINARY_DIGESTS.get(scanner_platform())
    if expected is None:
        raise DependencyError(UNSUPPORTED_LOCAL_SCANNER, reason=UNSUPPORTED_REASON)
    if _file_digest(root / LOCAL_SCANNER_PATH) != expected:
        raise DependencyError(UNTRUSTED_LOCAL_SCANNER, reason=UNTRUSTED_REASON)


def _path_scanner(root: Path, executable: str) -> str:
    found = find_executable(executable)
    if found is None:
        return executable
    inside = path_inside_repository(found, root)
    if inside is not None:
        raise DependencyError(
            f"Gitleaks on PATH is {inside} inside this repository, so repository "
            f"content would choose the scanner; remove the folder that holds {inside} "
            f"from PATH, and {_setup_hint(root)}."
        )
    return found


def _select_executable(root: Path, executable: str) -> str:
    if os.path.sep in executable:
        return executable
    local = root / LOCAL_SCANNER_PATH
    if executable != "gitleaks" or not os.path.lexists(local):
        return _path_scanner(root, executable)
    if local.is_symlink() or not local.is_file():
        raise DependencyError(UNSAFE_LOCAL_SCANNER, reason=UNSAFE_REASON)
    return str(local)


class RunOptions(NamedTuple):
    capture_output: bool = True
    input_bytes: bytes | None = None
    timeout: int = SCAN_TIMEOUT_SECONDS
    folder: Path | None = None


CAPTURE = RunOptions()


def run_scanner(
    arguments: Sequence[str],
    root: Path,
    environment: Mapping[str, str] | None,
    options: RunOptions = CAPTURE,
) -> subprocess.CompletedProcess[bytes]:
    capture_output, input_bytes, timeout, folder = options
    try:
        return subprocess.run(
            arguments,
            cwd=str(root if folder is None else folder),
            env=_environment(environment, root),
            input=input_bytes,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise ScannerTimeoutError(
            f"Gitleaks timed out after {timeout} seconds."
        ) from error
    except OSError as error:
        raise DependencyError(
            f"Gitleaks is unavailable; {_setup_hint(root)}, "
            "or install the pinned Gitleaks version on PATH.",
            reason="Gitleaks is unavailable",
        ) from error


def _setup_hint(root: Path) -> str:
    command = setup_command(setup_hook=declares_setup_hook(root))
    return f"run '{command}' in this checkout"


def _validation_key(
    executable: str, environment: Mapping[str, str] | None
) -> tuple[object, ...] | None:
    try:
        info = Path(executable).stat()
    except OSError:
        return None
    return (
        executable,
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        None if environment is None else tuple(sorted(environment.items())),
    )


def validate_scanner(
    root: Path,
    executable: str = "gitleaks",
    environment: Mapping[str, str] | None = None,
) -> str:
    executable = _select_executable(root, executable)
    if executable == str(root / LOCAL_SCANNER_PATH):
        _verify_local_scanner(root)
    if os.path.sep not in executable:
        raise DependencyError(
            f"Gitleaks {SCANNER_VERSION} is unavailable; {_setup_hint(root)}, {INSTALL_HINT}"
        )
    key = _validation_key(executable, environment)
    if key is not None and key in _VALIDATED:
        return executable
    # Gitleaks reads .gitleaksignore and .gitleaks.toml from its working folder, so
    # the check runs in an empty private folder that no repository file can enter.
    with tempfile.TemporaryDirectory(prefix=CHECK_FOLDER_PREFIX) as folder:
        _check_release(root, executable, environment, Path(folder))
    if key is not None:
        if len(_VALIDATED) >= MAX_VALIDATED:
            _VALIDATED.clear()
        _VALIDATED.add(key)
    return executable


def _check_release(
    root: Path, executable: str, environment: Mapping[str, str] | None, folder: Path
) -> None:
    result = run_scanner(
        [executable, "version"], root, environment, RunOptions(folder=folder)
    )
    if result.returncode != 0:
        raise DependencyError("Gitleaks version cannot be determined.")
    output = result.stdout.decode("utf-8", errors="ignore")
    version_pattern = (
        rf"(?<![A-Za-z0-9_.])v?{re.escape(SCANNER_VERSION)}(?![A-Za-z0-9_.+-])"
    )
    if re.search(version_pattern, output) is None:
        raise DependencyError(
            f"Installed Gitleaks is incompatible; {_setup_hint(root)}, {INSTALL_HINT}",
            reason="Installed Gitleaks is incompatible",
        )
    capability = run_scanner(
        [executable, *STDIN_ARGUMENTS],
        root,
        environment,
        RunOptions(capture_output=False, input_bytes=CALIBRATION_INPUT, folder=folder),
    )
    if capability.returncode != FINDINGS_EXIT:
        raise DependencyError(
            f"Installed Gitleaks failed its capability check; {_setup_hint(root)}, "
            f"{INSTALL_HINT}",
            reason="Installed Gitleaks failed its capability check",
        )
