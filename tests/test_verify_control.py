import io
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tests.test_verify_script import ROOT, cli, prepare

CAUGHT = {
    "private-literal": (
        "privacy: failed (1.0 s) - a commit with a planted private value exited 0, "
        "expected non-zero\n"
    ),
    "unsigned-commits": (
        "commit: failed (1.0 s) - not observed: the commit carries an SSH signature\n"
    ),
}


def _fake_runs(outputs: dict[str, tuple[int, str]]):
    def run(arguments, **_):
        name = arguments[arguments.index("--plant") + 1]
        code, output = outputs[name]
        return subprocess.CompletedProcess(arguments, code, output, "")

    return run


class VerifyControlTest(unittest.TestCase):
    def control(self, outputs: dict[str, tuple[int, str]]) -> tuple[int, str]:
        output = io.StringIO()
        with (
            patch.object(cli.subprocess, "run", side_effect=_fake_runs(outputs)) as run,
            redirect_stdout(output),
        ):
            code = cli.control()
        planted = [
            call.args[0][call.args[0].index("--plant") + 1] for call in run.mock_calls
        ]
        self.assertEqual(list(prepare.PLANTS), planted)
        return code, output.getvalue()

    def test_each_plant_still_matches_the_product_source(self) -> None:
        self.assertEqual({"private-literal", "unsigned-commits"}, set(prepare.PLANTS))
        for name, planned in prepare.PLANTS.items():
            with self.subTest(plant=name), tempfile.TemporaryDirectory() as directory:
                tree = Path(directory)
                for relative, _, _ in planned.edits:
                    (tree / relative).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, tree / relative)
                prepare.plant(tree, name)
                for relative, old, new in planned.edits:
                    text = (tree / relative).read_text("utf-8")
                    self.assertNotIn(old, text)
                    self.assertEqual(
                        text, (ROOT / relative).read_text("utf-8").replace(old, new)
                    )
                    (tree / relative).write_text("unrelated", "utf-8")
                with self.assertRaisesRegex(ValueError, "anchor not found"):
                    prepare.plant(tree, name)

    def test_the_unsigned_plant_leaves_commit_signing_unset_and_unchecked(self) -> None:
        edits = {
            path: (old, new)
            for path, old, new in prepare.PLANTS["unsigned-commits"].edits
        }
        self.assertEqual("commit", prepare.PLANTS["unsigned-commits"].feature)
        self.assertEqual(
            ('    "commit.gpgsign": "true",\n', ""),
            edits["src/first_commit/setup_plan.py"],
        )
        self.assertIn(
            '"commit.gpgsign"', edits["src/first_commit/checks/identity.py"][0]
        )

    def test_control_exits_0_only_when_every_plant_is_caught(self) -> None:
        code, output = self.control({name: (1, text) for name, text in CAUGHT.items()})
        self.assertEqual(0, code)
        self.assertIn(
            "control: caught - plant private-literal made privacy fail and the run exit 1",
            output.splitlines(),
        )
        self.assertIn(
            "control: caught - plant unsigned-commits made commit fail and the run exit 1",
            output.splitlines(),
        )

    def test_control_misses_a_plant_whose_feature_passes_or_fails_otherwise(
        self,
    ) -> None:
        outputs = {
            "private-literal": (1, CAUGHT["private-literal"]),
            "unsigned-commits": (0, "commit: proven (1.0 s)\n"),
        }
        code, output = self.control(outputs)
        self.assertEqual(1, code)
        self.assertIn(
            "control: missed - plant unsigned-commits: the planted run exited 0, "
            "commit proven",
            output.splitlines(),
        )
        outputs["unsigned-commits"] = (
            1,
            "commit: failed (1.0 s) - the first commit exited 1\n",
        )
        code, output = self.control(outputs)
        self.assertEqual(1, code)
        self.assertIn(
            "control: missed - plant unsigned-commits: commit failed, but not with "
            '"not observed: the commit carries an SSH signature"',
            output.splitlines(),
        )


if __name__ == "__main__":
    unittest.main()
