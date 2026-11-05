import os
import tempfile
import unittest
from pathlib import Path

from tests.test_verify_script import harness

core = harness("core")
prepare = harness("prepare")
# Stands for an ssh-agent that cannot make its default socket. Only a socket path on
# the command line lets it start.
FAKE_AGENT = """#!/bin/sh
[ "$1" = "-a" ] || exit 255
printf 'SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\\n' "$2"
printf 'SSH_AGENT_PID=4242; export SSH_AGENT_PID;\\n'
"""


class StartAgentTest(unittest.TestCase):
    def test_the_agent_socket_is_named_inside_the_work_folder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            tools = folder / "tools"
            work = folder / "work"
            tools.mkdir()
            work.mkdir()
            for name, text in (("ssh-agent", FAKE_AGENT), ("ssh-add", "#!/bin/sh\n")):
                (tools / name).write_text(text, "utf-8")
                (tools / name).chmod(0o755)
            run = core.Run(
                work=work,
                python="python3",
                environment={"PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"},
            )
            prepare.start_agent(run)
            socket = Path(run.environment["SSH_AUTH_SOCK"])
            self.assertEqual(work, socket.parent)


if __name__ == "__main__":
    unittest.main()
