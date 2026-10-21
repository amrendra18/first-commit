import os
import re
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from verify_lib.core import (
    GIT_HOOKS,
    HTTPS,
    IDENTITY,
    FeatureFailedError,
    Run,
    exited,
    require,
)
from verify_lib.journeys import preview_setup, setup_journey

# The values setup must write, kept here as an independent copy of the product's.
SIGNING_SETTINGS = {
    "gpg.format": "ssh",
    "commit.gpgsign": "true",
    "tag.gpgsign": "true",
    "user.useConfigOnly": "true",
}
CONTRIBUTOR = ".local/first-commit/contributor.json"
SIGNERS = ".local/first-commit/allowed-signers"
TRUST_SETTING = "gpg.ssh.allowedSignersFile"
SCANNER = ".local/bin/gitleaks"
HOOK_STAGES = ("pre-commit", "commit-msg", "pre-push")
ANNOUNCES = re.compile(r"\bwould\b")


def announced_actions(output: str) -> list[tuple[str, str]]:
    pairs = []
    for line in output.splitlines():
        label, _, detail = line.partition(": ")
        if detail and ANNOUNCES.search(detail):
            pairs.append((label, detail))
    return pairs


class Effects:
    def __init__(self, run: Run, project: Path) -> None:
        self.run = run
        self.project = project

    def setting(self, key: str) -> str:
        code, value = self.run.command(
            ["git", "config", "--local", "--get", key], self.project
        )
        return value.strip() if code == 0 else ""

    def file(self, name: str) -> bool:
        return (self.project / name).is_file()

    def repository(self, _detail: str) -> str | None:
        code, _ = self.run.command(["git", "rev-parse", "--git-dir"], self.project)
        return ".git is a repository" if code == 0 else None

    def files(self, detail: str) -> str | None:
        names = detail.removeprefix("would create ").split(", ")
        return f"{', '.join(names)} exist" if all(map(self.file, names)) else None

    def contributor(self, _detail: str) -> str | None:
        return f"{CONTRIBUTOR} exists" if self.file(CONTRIBUTOR) else None

    def private_values(self, detail: str) -> str | None:
        name = detail.removeprefix("would create ").split(";", 1)[0]
        return f"{name} exists" if self.file(name) else None

    def identity(self, _detail: str) -> str | None:
        wanted = {
            **SIGNING_SETTINGS,
            "user.name": IDENTITY["FIRST_COMMIT_AUTHOR_NAME"],
            "user.email": IDENTITY["FIRST_COMMIT_AUTHOR_EMAIL"],
            "user.signingkey": self.run.environment["VERIFY_KEY"] + ".pub",
        }
        found = {key: self.setting(key) for key in wanted}
        return f"{', '.join(wanted)} set" if found == wanted else None

    def template(self, _detail: str) -> str | None:
        value = self.setting("commit.template")
        return f"commit.template names {value}" if value and self.file(value) else None

    def trust(self, _detail: str) -> str | None:
        ready = self.setting(TRUST_SETTING) and self.file(SIGNERS)
        return f"{TRUST_SETTING} set and {SIGNERS} exists" if ready else None

    def scanner(self, detail: str) -> str | None:
        version = detail.removeprefix("would download and install ").split(" ", 1)[0]
        path = self.project / SCANNER
        if not path.is_file() or not os.access(path, os.X_OK):
            return None
        _, printed = self.run.command([path, "version"], self.project)
        return f"{SCANNER} reports {version}" if printed.strip() == version else None

    def hook_scripts(self, _detail: str) -> str | None:
        hooks = [self.project / GIT_HOOKS / stage for stage in HOOK_STAGES]
        ready = all(hook.is_file() and os.access(hook, os.X_OK) for hook in hooks)
        return f"{', '.join(HOOK_STAGES)} hooks are executable" if ready else None

    # The cache is shared with the setup feature: this cannot prove this call built it.
    def hook_environments(self, _detail: str) -> str | None:
        database = Path(self.run.environment["PRE_COMMIT_HOME"]) / "db.db"
        if not database.is_file():
            return None
        with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as db:
            rows = db.execute(
                "SELECT path FROM repos WHERE repo = ? AND ref = ?",
                (HTTPS, self.run.revision),
            ).fetchall()
        ready = any(Path(path).is_dir() for (path,) in rows)
        return "the pre-commit cache holds the hook repository" if ready else None

    def checks(self) -> dict[str, Callable[[str], str | None]]:
        return {
            "Git repository": self.repository,
            "Files": self.files,
            "Local contributor": self.contributor,
            "Private values": self.private_values,
            "Git identity/signing": self.identity,
            "Commit template": self.template,
            "Local signature trust": self.trust,
            "Signature verification": self.trust,
            "Gitleaks": self.scanner,
            "Hook scripts": self.hook_scripts,
            "Hook environments": self.hook_environments,
        }


def prove_effects(run: Run, project: Path, preview: str) -> list[str]:
    actions = announced_actions(preview)
    if not actions:
        raise FeatureFailedError("the dry run announced no action")
    checks = Effects(run, project).checks()
    proofs = []
    for label, detail in actions:
        check = checks.get(label)
        if check is None:
            raise FeatureFailedError(f"no effect check for '{label}: {detail}'")
        found = check(detail)
        proofs.append(
            require(condition=found is not None, observed=f"{label}: {found or detail}")
        )
    return proofs


def feature_preview_matches_apply(run: Run) -> list[str]:
    folder = run.work / "preview-project"
    folder.mkdir()
    previewed, preview = preview_setup(run, folder)
    untouched = not any(folder.iterdir())
    applied, _ = setup_journey(run, folder, preflight=False, transport="https")
    return [
        exited(previewed, 0, "the dry run in an empty folder"),
        require(condition=untouched, observed="the dry run left the folder empty"),
        exited(applied, 0, "setup in the same folder"),
        *prove_effects(run, folder, preview),
    ]
