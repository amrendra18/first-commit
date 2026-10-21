import re
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
STANDARD_RUNNERS = ("ubuntu-latest", "macos-latest", "windows-latest")
MATRIX_REFERENCE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
PINNED_ACTION = re.compile(r"[a-z0-9-]+/[a-z0-9-]+@[0-9a-f]{40}")


def runner_labels(job: dict[str, Any]) -> list[object]:
    runs_on = job.get("runs-on")
    if not isinstance(runs_on, str):
        return [runs_on]
    match = MATRIX_REFERENCE.fullmatch(runs_on.strip())
    if match is None:
        return [runs_on]
    matrix = job.get("strategy", {}).get("matrix", {})
    name = match.group(1)
    values = matrix.get(name)
    labels: list[object] = list(values) if isinstance(values, list) else [values]
    labels.extend(entry[name] for entry in matrix.get("include", []) if name in entry)
    return labels


def workflows() -> dict[str, dict[str, Any]]:
    loaded = {}
    for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        loaded[path.name] = yaml.safe_load(path.read_text("utf-8"))
    return loaded


class WorkflowTest(unittest.TestCase):
    def test_every_job_runs_on_a_standard_github_hosted_runner(self) -> None:
        found = workflows()
        self.assertIn("ci.yml", found)
        for name, workflow in found.items():
            for job_name, job in workflow["jobs"].items():
                with self.subTest(workflow=name, job=job_name):
                    labels = runner_labels(job)
                    self.assertTrue(labels)
                    for label in labels:
                        self.assertIn(label, STANDARD_RUNNERS)

    def test_runner_labels_reject_self_hosted_and_unknown_values(self) -> None:
        for job in (
            {"runs-on": "self-hosted"},
            {"runs-on": ["self-hosted", "linux"]},
            {"runs-on": "ubuntu-24.04-arm64-large"},
            {"runs-on": "${{ matrix.os }}"},
            {
                "runs-on": "${{ matrix.os }}",
                "strategy": {
                    "matrix": {
                        "os": ["ubuntu-latest"],
                        "include": [{"os": "self-hosted"}],
                    }
                },
            },
        ):
            with self.subTest(job=job):
                self.assertFalse(
                    all(label in STANDARD_RUNNERS for label in runner_labels(job))
                )

    def test_every_action_is_pinned_to_a_full_commit(self) -> None:
        for name, workflow in workflows().items():
            for job in workflow["jobs"].values():
                for step in job["steps"]:
                    if "uses" in step:
                        with self.subTest(workflow=name, uses=step["uses"]):
                            self.assertRegex(step["uses"], PINNED_ACTION)

    def test_ci_sets_up_the_checkout_then_runs_the_gate_and_journeys(self) -> None:
        job = workflows()["ci.yml"]["jobs"]["test"]
        matrix = job["strategy"]["matrix"]
        self.assertEqual(["ubuntu-latest", "macos-latest"], matrix["os"])
        self.assertEqual(["3.11", "3.12", "3.13", "3.14"], matrix["python"])
        runs = [step.get("run", "") for step in job["steps"]]
        order = [
            next(i for i, run in enumerate(runs) if marker in run)
            for marker in (
                "ssh-keygen -q -t ed25519 -N '' -C \"test-ci-key, deleted after this job\"",
                'ssh-add -q "$RUNNER_TEMP/test-ci-key"',
                'FIRST_COMMIT_SIGNING_KEY="$RUNNER_TEMP/test-ci-key.pub" first-commit setup',
                "scripts/check full",
                "scripts/verify fast",
            )
        ]
        self.assertEqual(sorted(order), order)
        self.assertIn('"$GITHUB_ENV"', runs[order[1]])
        setup = runs[order[2]]
        self.assertIn('FIRST_COMMIT_AUTHOR_NAME="CI"', setup)
        self.assertIn('FIRST_COMMIT_AUTHOR_EMAIL="ci@example.com"', setup)
        self.assertIn("first-commit setup --yes", setup)
        cleanup = job["steps"][-1]
        self.assertEqual("always()", cleanup.get("if"))
        delete = cleanup["run"].index('rm -f "$RUNNER_TEMP/test-ci-key"')
        stop = cleanup["run"].index("ssh-agent -k > /dev/null || true")
        self.assertLess(delete, stop, "the key is deleted before the agent stops")

    def test_ci_bounds_each_job_and_cancels_superseded_runs(self) -> None:
        workflow = workflows()["ci.yml"]
        self.assertEqual(30, workflow["jobs"]["test"]["timeout-minutes"])
        self.assertEqual(
            {
                "group": "${{ github.workflow }}-"
                "${{ github.event.pull_request.number || github.ref }}",
                "cancel-in-progress": True,
            },
            workflow["concurrency"],
        )

    def test_ci_gets_gitleaks_only_from_setup(self) -> None:
        steps = workflows()["ci.yml"]["jobs"]["test"]["steps"]
        for step in steps:
            with self.subTest(step=step.get("name")):
                text = f"{step.get('name', '')}\n{step.get('run', '')}".lower()
                self.assertNotRegex(text, r"\bgo (install|build|env)\b")
                self.assertNotIn("setup-go", str(step.get("uses", "")))
                if "first-commit setup" not in text:
                    self.assertNotIn("gitleaks", text)


if __name__ == "__main__":
    unittest.main()
