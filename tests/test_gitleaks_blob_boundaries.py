import tempfile
import unittest
from pathlib import Path

from first_commit.gitleaks_blobs import scan_hidden_staged
from tests.gitleaks_support import needs_real_scanner
from tests.support import initialize_repository, run_git

AWS_KEY = "AKIA" + "QWERTZUIOPASDFGH"
LIMITS = (100, 1024 * 1024)


class HiddenBlobBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        initialize_repository(self.root)

    @needs_real_scanner
    def test_a_key_at_the_start_of_the_second_file_in_a_batch_is_found(self) -> None:
        (self.root / "a.png").write_bytes(b"prefix-x")
        (self.root / "b.png").write_bytes(AWS_KEY.encode("ascii") + b"\n")
        run_git(self.root, "add", "--", "a.png", "b.png")

        found = scan_hidden_staged(
            self.root, ("a.png", "b.png"), LIMITS, max_findings=10
        )

        self.assertEqual(
            [("b.png", 1, "secrets.gitleaks")],
            [(item.path, item.line, item.rule_id) for item in found],
        )


if __name__ == "__main__":
    unittest.main()
