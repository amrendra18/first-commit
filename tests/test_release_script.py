import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from tests.support import initialize_repository, run_git

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release"
VERSION = "1.2.3"
TAG = "v" + VERSION
REPOSITORY = "example-owner/example-tool"
CI_PYTHONS = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text("utf-8"))[
    "jobs"
]["test"]["strategy"]["matrix"]["python"]
GATES = ["check full", "check matrix", "verify full", "verify control"]
# A gate stand-in: logs its name and arguments, then fails when FAIL_GATE names it.
STUB = (
    "#!/bin/bash\n"
    'gate="${0##*/} $*"\n'
    'printf \'%s\\n\' "$gate" >> "$RELEASE_LOG"\n'
    '[[ "$gate" != "${FAIL_GATE:-}" ]] || exit "$FAIL_EXIT"\n'
)


class ReleaseScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "project"
        self.log = Path(temporary.name) / "gates.log"
        self.pythons = Path(temporary.name) / "pythons"
        for version in CI_PYTHONS:
            build = self.pythons / f"cpython-{version}.0-macos-aarch64-none/bin"
            build.mkdir(parents=True)
            self.write_python(build / f"python{version}")
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "src/first_commit").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.root / "scripts" / "release")
        for name in ("check", "verify"):
            stub = self.root / "scripts" / name
            stub.write_text(STUB, encoding="utf-8")
            stub.chmod(0o755)
        (self.root / "src/first_commit/__init__.py").write_text(
            f'__version__ = "{VERSION}"\n', encoding="utf-8"
        )
        (self.root / "src/first_commit/hooks.py").write_text(
            f'GITHUB_REPOSITORY = "{REPOSITORY}"\n', encoding="utf-8"
        )
        self.write_readme(TAG)
        initialize_repository(self.root)
        self.commit("first")

    def write_readme(self, tag: str) -> None:
        (self.root / "README.md").write_text(
            f"pip install 'first-commit @ git+https://example.invalid/x.git@{tag}'\n",
            encoding="utf-8",
        )

    def commit(self, subject: str) -> str:
        run_git(self.root, "add", "-A")
        run_git(
            self.root,
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=release@example.com",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            subject,
        )
        return run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()

    def release(
        self, *arguments: str, **variables: str | None
    ) -> tuple[int, str, str, list[str]]:
        environment = {
            **os.environ,
            "RELEASE_LOG": str(self.log),
            "FIRST_COMMIT_PYTHONS": str(self.pythons),
        }
        for name, value in variables.items():
            if value is None:
                environment.pop(name, None)
            else:
                environment[name] = value
        result = subprocess.run(
            [str(self.root / "scripts" / "release"), *arguments],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        gates = self.log.read_text("utf-8").splitlines() if self.log.exists() else []
        return result.returncode, result.stdout, result.stderr, gates

    def test_script_is_executable_and_documents_that_it_never_pushes(self) -> None:
        self.assertTrue(SCRIPT.stat().st_mode & 0o111)
        code, output, error, gates = self.release("--help")
        self.assertEqual((0, "", []), (code, error, gates))
        self.assertIn("It never tags or pushes.", output)
        self.assertNotIn("operator", output)
        code, _, error, gates = self.release("now")
        self.assertEqual((2, []), (code, gates))
        self.assertIn("takes no arguments", error)

    def test_contributing_documents_the_release_procedure(self) -> None:
        contributing = (ROOT / "CONTRIBUTING.md").read_text("utf-8")
        section = contributing.split("\n## Release\n", 1)[1].split("\n## ", 1)[0]
        for detail in (
            "Run `scripts/release`",
            "It never tags or pushes",
            "scripts/verify full --require-github",
            "GITHUB_REPOSITORY",
            "`scripts/check full`, `scripts/check matrix`, and `scripts/verify full`",
            "A missing version stops the release before the first check",
        ):
            self.assertIn(detail, " ".join(section.split()))
        skill = (ROOT / ".agents/skills/first-commit/SKILL.md").read_text("utf-8")
        self.assertIn("`scripts/release`", skill)

    def test_lint_finds_the_script_as_bash(self) -> None:
        self.assertEqual("#!/bin/bash", SCRIPT.read_text("utf-8").splitlines()[0])

    def test_a_missing_python_build_stops_before_any_gate(self) -> None:
        for version in (CI_PYTHONS[0], CI_PYTHONS[-1]):
            shutil.rmtree(next(self.pythons.glob(f"cpython-{version}.*")))
        (self.pythons / f"cpython-{CI_PYTHONS[1]}.0-other").mkdir()

        code, output, error, gates = self.release()

        self.assertEqual((1, "", []), (code, output, gates))
        self.assertIn(
            f"release: not ready: FIRST_COMMIT_PYTHONS ({self.pythons}) holds no "
            f"build of Python {CI_PYTHONS[0]} {CI_PYTHONS[-1]}; add a "
            "cpython-<version>.* build of each, or unset it to use python3.11 to "
            "python3.14 on PATH.",
            error,
        )
        self.assertIn(
            "Then runs scripts/check full, scripts/check matrix,",
            " ".join(self.release("--help")[1].split()),
        )

    def test_release_checks_the_ci_pythons(self) -> None:
        self.assertIn(
            f"matrix_versions='{' '.join(CI_PYTHONS)}'",
            SCRIPT.read_text("utf-8").splitlines(),
        )

    def test_without_the_variable_every_ci_python_must_be_on_path(
        self,
    ) -> None:
        tools = self.root.parent / "tools"
        tools.mkdir()
        for name in ("cat", "dirname", "git", "grep", "sed"):
            found = shutil.which(name)
            if found is None:
                self.fail(f"{name} is not on PATH")
            (tools / name).symlink_to(found)
        for version in CI_PYTHONS[1:-1]:
            self.write_python(tools / f"python{version}")
        code, output, error, gates = self.release(
            FIRST_COMMIT_PYTHONS=None, PATH=str(tools)
        )
        self.assertEqual((1, "", []), (code, output, gates))
        self.assertIn(
            "release: not ready: not on PATH: "
            f"python{CI_PYTHONS[0]} python{CI_PYTHONS[-1]}; install each CI Python, "
            "or set FIRST_COMMIT_PYTHONS to a folder of cpython-<version>.* builds.",
            error,
        )
        self.write_python(tools / f"python{CI_PYTHONS[0]}")
        self.write_python(tools / f"python{CI_PYTHONS[-1]}")
        code, output, _, gates = self.release(
            FIRST_COMMIT_PYTHONS=None, PATH=str(tools)
        )
        self.assertEqual((0, GATES), (code, gates), output)
        self.assertIn(f"-m 'first-commit {VERSION}' ", output)
        self.assertIn(f"version  # prints {VERSION}", output)

    @staticmethod
    def write_python(path: Path) -> None:
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)

    def test_failed_git_status_stops_before_any_gate(self) -> None:
        tools = self.root.parent / "tools"
        tools.mkdir()
        (tools / "git").write_text(
            '#!/bin/bash\n[[ "$1" != status ]] || exit 128\n'
            f'exec {shutil.which("git")} "$@"\n',
            encoding="utf-8",
        )
        (tools / "git").chmod(0o755)
        code, output, error, gates = self.release(
            PATH=f"{tools}{os.pathsep}{os.environ['PATH']}"
        )
        self.assertEqual((1, "", []), (code, output, gates))
        self.assertIn("release: not ready: git status failed", error)

    def test_ready_checkout_runs_the_gates_then_prints_the_commands(self) -> None:
        run_git(self.root, "checkout", "-q", "-b", "release")
        commit = self.commit_change()
        code, output, error, gates = self.release()
        self.assertEqual((0, ""), (code, error), output)
        self.assertEqual(GATES, gates)
        self.assertNotIn("operator", output)
        for line in (
            f"release: {TAG} at {commit} on branch release",
            "release: scripts/check full exit 0",
            "release: scripts/verify full exit 0",
            "release: scripts/verify control exit 0",
            f"Ready to release {TAG} at commit {commit}. Run:",
            f"  git tag -s {TAG} -m 'first-commit {VERSION}' {commit}",
            "  git push origin release",
            f"  git push origin {TAG}",
            "The branch is release: merge it into main too",
            "  scripts/verify full --require-github",
            f"git+https://github.com/{REPOSITORY}.git@{TAG}'",
            f"version  # prints {VERSION}",
        ):
            with self.subTest(line=line):
                self.assertIn(line, output)

    def test_existing_tag_on_head_prints_only_the_pushes(self) -> None:
        commit = run_git(self.root, "rev-parse", "HEAD").stdout.decode().strip()
        run_git(self.root, "tag", TAG, commit)
        code, output, _, gates = self.release()
        self.assertEqual((0, GATES), (code, gates))
        self.assertIn(f"Ready to release {TAG} at commit {commit}. Run:", output)
        self.assertNotIn("git tag -s", output)
        self.assertIn(f"  git push origin {TAG}", output)
        self.assertNotIn("merge it into main", output)

    def test_unready_checkouts_stop_before_any_gate(self) -> None:
        cases = {
            "dirty": "the working tree has uncommitted or untracked files",
            "detached": "HEAD is detached",
            "tag elsewhere": f"tag {TAG} already names",
            "readme tag": f"README.md does not install {TAG}",
        }
        for case, message in cases.items():
            with self.subTest(case=case):
                self.setUp()
                if case == "dirty":
                    (self.root / "new.txt").write_text("x\n", encoding="utf-8")
                elif case == "detached":
                    run_git(self.root, "checkout", "-q", "--detach")
                elif case == "tag elsewhere":
                    run_git(self.root, "tag", TAG)
                    self.commit_change()
                else:
                    self.write_readme("v0.0.1")
                    self.commit("readme")
                code, output, error, gates = self.release()
                self.assertEqual((1, "", []), (code, output, gates))
                self.assertIn(f"release: not ready: {message}", error)

    def test_failed_gate_stops_the_release(self) -> None:
        for index, gate in enumerate(GATES):
            with self.subTest(gate=gate):
                self.log.unlink(missing_ok=True)
                code, output, error, gates = self.release(
                    FAIL_GATE=gate, FAIL_EXIT=str(index + 1)
                )
                self.assertEqual((1, GATES[: index + 1]), (code, gates))
                self.assertIn(f"release: scripts/{gate} exit {index + 1}", output)
                self.assertIn(f"scripts/{gate} failed", error)
                self.assertNotIn("git push", output)

    def test_missing_version_or_repository_stops(self) -> None:
        for path, message in (
            ("src/first_commit/__init__.py", "names no __version__"),
            ("src/first_commit/hooks.py", "names no GITHUB_REPOSITORY"),
        ):
            with self.subTest(path=path):
                self.setUp()
                (self.root / path).write_text("\n", encoding="utf-8")
                self.commit("empty")
                code, _, error, gates = self.release()
                self.assertEqual((1, []), (code, gates))
                self.assertIn(message, error)

    def commit_change(self) -> str:
        (self.root / "change.txt").write_text("change\n", encoding="utf-8")
        return self.commit("change")


if __name__ == "__main__":
    unittest.main()
