import importlib
import json
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from tests.support import initialize_repository, run_git

ROOT = Path(__file__).resolve().parents[1]


def harness(name: str) -> ModuleType:
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module(f"verify_lib.{name}")


core = harness("core")
journeys = harness("journeys")
rehearsal = harness("rehearsal")
report = harness("report")


class RunFactsTest(unittest.TestCase):
    def test_facts_name_head_dirty_state_python_and_platform(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_repository(root)
            (root / "a.txt").write_text("a\n", "utf-8")
            run_git(root, "add", "a.txt")
            run_git(root, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "one")
            head = run_git(root, "rev-parse", "HEAD").stdout.decode().strip()
            clean = report.run_facts(sys.executable, root)
            (root / "a.txt").write_text("changed\n", "utf-8")
            dirty = report.run_facts(sys.executable, root)
        self.assertEqual(head, clean["head"])
        self.assertEqual("no", clean["dirty"])
        self.assertEqual("yes", dirty["dirty"])
        self.assertEqual(platform.python_version(), clean["python"])
        self.assertEqual(sys.executable, clean["python path"])
        self.assertIn(platform.system(), clean["platform"])
        self.assertIn(platform.machine(), clean["platform"])

    def test_outside_git_the_head_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            facts = report.run_facts(sys.executable, Path(directory))
        self.assertEqual("unknown (not a Git work tree)", facts["head"])
        self.assertEqual("unknown", facts["dirty"])

    def test_a_python_that_does_not_exist_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "python")
            facts = report.run_facts(missing, Path(directory))
        self.assertEqual("unknown", facts["python"])
        self.assertEqual(missing, facts["python path"])


class EvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def meta(self) -> dict[str, object]:
        return {
            "level": "fast",
            "started": "20261018T000000Z",
            "seconds": 1.0,
            "revision": "a" * 40,
            "plant": None,
            "cleanup": "temporary folder removed",
            "facts": {
                "head": "b" * 40,
                "dirty": "yes",
                "python": "3.13.15",
                "python path": "/usr/bin/python3",
                "platform": "Darwin 24.6.0 arm64",
            },
        }

    def test_verify_summary_records_the_facts_and_the_features_without_preflight(
        self,
    ) -> None:
        run = core.Run(work=self.folder / "work", python=sys.executable, environment={})
        run.features_without_preflight = ["setup", "preview-matches-apply"]
        report.write_evidence(self.folder, run, {}, self.meta())
        summary = (self.folder / "summary.md").read_text("utf-8")
        for line in (
            f"- HEAD: {'b' * 40} (dirty: yes)",
            "- Python: 3.13.15 (/usr/bin/python3)",
            "- platform: Darwin 24.6.0 arm64",
        ):
            self.assertIn(line, summary)
        self.assertNotIn("mocks: none", summary)
        self.assertIn(
            "- preflight: off (SetupRequest preflight=False) in setup, "
            "preview-matches-apply,",
            summary,
        )
        recorded = json.loads((self.folder / "summary.json").read_text("utf-8"))
        self.assertEqual("yes", recorded["facts"]["dirty"])
        self.assertEqual(["setup", "preview-matches-apply"], recorded["preflight_off"])

    def test_summaries_hide_the_work_folder_and_home_path(self) -> None:
        run = core.Run(work=self.folder / "work", python=sys.executable, environment={})
        home = str(Path.home())
        results = {
            "commit": core.FeatureResult(
                "failed", reason=f"git -C {run.work}/project in {home}/x exited 1"
            ),
            "setup": core.FeatureResult(
                "proven", [f"{run.work}/project and {home}/y exist"]
            ),
        }
        report.write_evidence(self.folder, run, results, self.meta())
        for name in ("summary.md", "summary.json"):
            with self.subTest(file=name):
                text = (self.folder / name).read_text("utf-8")
                self.assertNotIn(str(run.work), text)
                self.assertNotIn(home, text)
                self.assertIn("<work>/project", text)

    def test_verify_summary_names_each_path_folder_removed_for_first_commit(
        self,
    ) -> None:
        run = core.Run(work=self.folder / "work", python=sys.executable, environment={})
        for removed, shown in (([], "none"), (["/opt/a", "/opt/b"], "/opt/a, /opt/b")):
            with self.subTest(removed=removed):
                run.removed_path_folders = removed
                report.write_evidence(self.folder, run, {}, self.meta())
                summary = (self.folder / "summary.md").read_text("utf-8")
                self.assertIn(
                    f"- PATH folders removed for holding first-commit: {shown}",
                    summary,
                )
                recorded = json.loads((self.folder / "summary.json").read_text("utf-8"))
                self.assertEqual(removed, recorded["removed_path_folders"])

    def test_gitleaks_counts_come_from_the_setup_lines_in_the_logs(self) -> None:
        run = core.Run(work=self.folder / "work", python=sys.executable, environment={})
        results = {
            "setup": core.FeatureResult(
                "proven", log="$ setup\nGitleaks: downloaded and installed 8.30.0\n"
            ),
            "fix-line-works": core.FeatureResult(
                "proven",
                log="Gitleaks: ready\nGitleaks: would download and install 8.30.0\n"
                "copied Gitleaks: ready\nGitleaks: ready\n",
            ),
            "clone-guided": core.FeatureResult(
                "failed", log="Gitleaks: downloaded and installed 8.30.0\n"
            ),
        }
        report.write_evidence(self.folder, run, results, self.meta())
        summary = (self.folder / "summary.md").read_text("utf-8")
        self.assertIn(
            "- Gitleaks, from setup's own output lines: downloaded 2, reused 2",
            summary,
        )
        recorded = json.loads((self.folder / "summary.json").read_text("utf-8"))
        self.assertEqual({"downloaded": 2, "reused": 2}, recorded["gitleaks"])

    def test_direct_setup_without_preflight_names_its_feature(self) -> None:
        run = core.Run(
            work=self.folder, python=sys.executable, environment={"VERIFY_KEY": "key"}
        )
        run.feature = "setup"
        with patch.object(run, "command", return_value=(0, "")) as command:
            journeys.setup_journey(run, self.folder, preflight=False, transport="https")
            run.feature = "github"
            journeys.setup_journey(run, self.folder, preflight=True, transport="ssh")
        self.assertEqual(2, command.call_count)
        self.assertEqual(["setup"], run.features_without_preflight)

    def test_ci_local_summary_records_the_facts(self) -> None:
        results = {"test": [rehearsal.StepResult("one", 0, 1.0, "log")]}
        rehearsal.write_summary(self.folder, sys.executable, results, 0)
        summary = (self.folder / "summary.md").read_text("utf-8")
        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertIn(f"- HEAD: {head} (dirty: ", summary)
        self.assertIn(
            f"- Python: {platform.python_version()} ({sys.executable})", summary
        )
        self.assertIn(f"- platform: {platform.system()} ", summary)


if __name__ == "__main__":
    unittest.main()
