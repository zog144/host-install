import io
from contextlib import redirect_stdout
from importlib.metadata import version as distribution_version
from pathlib import Path
import tomllib
import unittest

import zog.host_install as host_install
from zog.host_install.cli import main


ROOT = Path(__file__).resolve().parents[1]


class VersionContractTests(unittest.TestCase):
    def test_project_module_and_installed_distribution_match(self):
        project_version = tomllib.loads(
            (ROOT / "pyproject.toml").read_text()
        )["project"]["version"]
        self.assertEqual(project_version, "0.14.3")
        self.assertEqual(host_install.__version__, project_version)
        self.assertEqual(distribution_version("host-install"), project_version)

    def test_cli_version_matches(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            main(["--version"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), "host-install 0.14.3")


if __name__ == "__main__":
    unittest.main()
