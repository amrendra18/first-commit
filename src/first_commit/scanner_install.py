import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from first_commit.executables import (
    find_executable,
    path_inside_repository,
    repository_program_message,
)
from first_commit.gitleaks_scanner import (
    LOCAL_SCANNER_PATH,
    SCANNER_VERSION,
    UNSAFE_LOCAL_SCANNER,
    DependencyError,
    ScannerTimeoutError,
    scanner_platform,
    validate_scanner,
)
from first_commit.paths import MEBIBYTE

MAX_ARCHIVE_BYTES = 24 * MEBIBYTE
MAX_BINARY_BYTES = 64 * MEBIBYTE
PYTHON_DOWNLOAD_ATTEMPTS = 2
PYTHON_DOWNLOAD_TIMEOUT_SECONDS = 10
CURL_DOWNLOAD_TIMEOUT_SECONDS = 120
MAX_ARCHIVE_ENTRIES = 32
RETRY_AFTER_TIMEOUT = "run setup again; if it times out again, "
ARCHIVE_DIGESTS = {
    (
        "darwin",
        "arm64",
    ): "b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7",
    (
        "darwin",
        "x64",
    ): "ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5",
    (
        "linux",
        "arm64",
    ): "b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f",
    (
        "linux",
        "x64",
    ): "79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e",
}


def _retry_advice(error: DependencyError) -> str:
    return RETRY_AFTER_TIMEOUT if isinstance(error, ScannerTimeoutError) else ""


def local_scanner_failed(error: DependencyError) -> DependencyError:
    return DependencyError(
        f"Local Gitleaks at {LOCAL_SCANNER_PATH} failed validation ({error.reason}); "
        f"{_retry_advice(error)}delete {LOCAL_SCANNER_PATH} and run setup again, "
        f"or replace it with trusted Gitleaks {SCANNER_VERSION}."
    )


def _download_failed(error: DependencyError) -> DependencyError:
    return DependencyError(
        f"Downloaded Gitleaks {SCANNER_VERSION} failed validation ({error.reason}) "
        f"and was removed; {_retry_advice(error)}install trusted Gitleaks "
        f"{SCANNER_VERSION} at {LOCAL_SCANNER_PATH}, then run setup again."
    )


def _archive() -> tuple[str, str]:
    system, architecture = scanner_platform()
    digest = ARCHIVE_DIGESTS.get((system, architecture))
    if digest is None:
        raise DependencyError("Gitleaks installation does not support this platform.")
    filename = f"gitleaks_{SCANNER_VERSION}_{system}_{architecture}.tar.gz"
    return (
        f"https://github.com/gitleaks/gitleaks/releases/download/v{SCANNER_VERSION}/{filename}",
        digest,
    )


def _curl_download(url: str, root: Path) -> bytes | None:
    executable = find_executable("curl")
    if executable is None:
        return None
    inside = path_inside_repository(executable, root)
    if inside is not None:
        raise DependencyError(repository_program_message("curl", inside))
    with tempfile.TemporaryDirectory(prefix="first-commit-download-") as folder:
        target = Path(folder) / "archive"
        try:
            result = subprocess.run(
                (
                    executable,
                    "--disable",
                    "--fail",
                    "--location",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--silent",
                    "--show-error",
                    "--connect-timeout",
                    str(PYTHON_DOWNLOAD_TIMEOUT_SECONDS),
                    "--max-time",
                    str(CURL_DOWNLOAD_TIMEOUT_SECONDS),
                    "--max-filesize",
                    str(MAX_ARCHIVE_BYTES),
                    "--output",
                    str(target),
                    url,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=CURL_DOWNLOAD_TIMEOUT_SECONDS + 5,
            )
            if result.returncode != 0 or target.is_symlink() or not target.is_file():
                return None
            with target.open("rb") as stream:
                return stream.read(MAX_ARCHIVE_BYTES + 1)
        except (OSError, subprocess.TimeoutExpired):
            return None


def _download(url: str, root: Path) -> bytes:
    archive = _curl_download(url, root)
    if archive is None:
        for _attempt in range(PYTHON_DOWNLOAD_ATTEMPTS):
            try:
                with urllib.request.urlopen(  # noqa: S310 - the URL is the pinned HTTPS release
                    url, timeout=PYTHON_DOWNLOAD_TIMEOUT_SECONDS
                ) as response:
                    archive = response.read(MAX_ARCHIVE_BYTES + 1)
                break
            except (OSError, TimeoutError):
                continue
    if archive is None:
        raise DependencyError(
            "Pinned Gitleaks download failed; check GitHub Releases access or "
            f"install trusted Gitleaks {SCANNER_VERSION} at {LOCAL_SCANNER_PATH}, then "
            "retry setup."
        )
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise DependencyError("Pinned Gitleaks archive exceeds the size limit.")
    return archive


def _binary(archive_bytes: bytes) -> bytes:
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            return _binary_member(archive)
    except (tarfile.TarError, OSError, EOFError) as error:
        raise DependencyError("Pinned Gitleaks archive is invalid.") from error


def _binary_member(archive: tarfile.TarFile) -> bytes:
    members = archive.getmembers()
    if len(members) > MAX_ARCHIVE_ENTRIES:
        raise DependencyError("Pinned Gitleaks archive has too many entries.")
    matches = [member for member in members if member.name == "gitleaks"]
    if len(matches) != 1 or not matches[0].isfile():
        raise DependencyError("Pinned Gitleaks archive lacks one regular binary.")
    member = matches[0]
    if member.size <= 0 or member.size > MAX_BINARY_BYTES:
        raise DependencyError("Pinned Gitleaks binary exceeds the size limit.")
    stream = archive.extractfile(member)
    if stream is None:
        raise DependencyError("Pinned Gitleaks binary cannot be read.")
    binary = stream.read(MAX_BINARY_BYTES + 1)
    if len(binary) != member.size:
        raise DependencyError("Pinned Gitleaks binary is incomplete.")
    return binary


def install_scanner(root: Path) -> bool:
    target = root / LOCAL_SCANNER_PATH
    if os.path.lexists(target):
        if target.is_symlink() or not target.is_file():
            raise DependencyError(UNSAFE_LOCAL_SCANNER)
        try:
            validate_scanner(root, executable=str(target))
        except DependencyError as error:
            raise local_scanner_failed(error) from error
        return False

    url, digest = _archive()
    archive_bytes = _download(url, root)
    if hashlib.sha256(archive_bytes).hexdigest() != digest:
        raise DependencyError("Pinned Gitleaks archive checksum does not match.")
    binary = _binary(archive_bytes)
    local = root / ".local"
    tools = local / "bin"
    for path in (local, tools):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise DependencyError("Local tool folder is unsafe.")
        path.mkdir(exist_ok=True)
    descriptor, name = tempfile.mkstemp(dir=tools)
    temporary = Path(name)
    try:
        # Linux refuses to run a file still open for writing, so it closes first.
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(binary)
        temporary.chmod(0o700)
        try:
            validate_scanner(root, executable=str(temporary))
        except DependencyError as error:
            raise _download_failed(error) from error
        try:
            os.link(temporary, target)
        except FileExistsError as error:
            raise DependencyError(
                f"A file appeared at {LOCAL_SCANNER_PATH} while setup installed "
                "Gitleaks, so setup left it in place.\n"
                f"fix: if you did not put it there, delete {LOCAL_SCANNER_PATH}, "
                "then rerun setup; setup checks the file before it uses it."
            ) from error
    finally:
        temporary.unlink(missing_ok=True)
    return True
