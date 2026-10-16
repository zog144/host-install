from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples/systemd"


class WelcomeUnitContractTests(unittest.TestCase):
    def test_console_readiness_units_never_take_over_login_or_wait_for_optional_stack(self):
        socket = (SOURCE / "host-install-welcome.socket").read_text()
        service = (SOURCE / "host-install-welcome@.service").read_text()
        combined = socket + "\n" + service
        directives = "\n".join(\n            line for line in combined.splitlines()\n            if not line.lstrip().startswith("#")\n        )\n
        self.assertIn("SocketGroup=host-welcome", socket)
        self.assertIn("SocketMode=0660", socket)
        self.assertIn("Accept=yes", socket)
        self.assertIn("ExecStart=/usr/bin/host-install welcome-readiness-serve", service)

        for forbidden in (
            "Requires=state.mount",
            "Wants=state.mount",
            "After=state.mount",
            "network-online.target",
            "box-control",
            "root-control",
            "firefox",
            "chromium",
            "greetd",
            "TTYPath=",
            "StandardInput=tty",
            "Conflicts=getty",
            "Before=getty",
            "Requires=getty",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, directives)

        self.assertIn("After=sysinit.target", socket)
        self.assertIn("After=sysinit.target", service)
        self.assertNotIn("DefaultDependencies=no", service)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd analyzer unavailable")
    def test_boot_graph_keeps_getty_independent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            units = root / "etc/systemd/system"
            units.mkdir(parents=True)
            for name in ("host-install-welcome.socket", "host-install-welcome@.service"):
                shutil.copyfile(SOURCE / name, units / name)

            targets = {
                "sysinit.target": "",
                "basic.target": "Requires=sysinit.target\nAfter=sysinit.target\n",
                "multi-user.target": (
                    "Requires=basic.target\nAfter=basic.target\n"
                    "Wants=host-install-welcome.socket getty.target\n"
                ),
                "getty.target": "After=basic.target\nWants=getty@tty1.service\n",
                "shutdown.target": "",
            }
            for name, body in targets.items():
                (units / name).write_text(
                    "[Unit]\nDescription=fixture\nDefaultDependencies=no\n" + body
                )

            (units / "getty@tty1.service").write_text(
                "[Unit]\nDescription=fixture getty\nAfter=basic.target\n"
                "[Service]\nType=simple\nExecStart=/usr/bin/true\n"
            )
            executable = root / "usr/bin/host-install"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            true = root / "usr/bin/true"
            true.write_text("#!/bin/sh\nexit 0\n")
            true.chmod(0o755)
            (root / "etc/passwd").write_text(
                "root:x:0:0::/root:/bin/sh\n"
                "host-welcome:x:1500:1500::/run/host-welcome:/usr/sbin/nologin\n"
            )
            (root / "etc/group").write_text(
                "root:x:0:\nhost-welcome:x:1500:\n"
            )

            command = [
                "systemd-analyze", "verify", "--generators=no", "--man=no",
                "--root=" + temp, "multi-user.target",
            ]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("ordering cycle", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
