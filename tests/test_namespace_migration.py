import importlib
import tomllib
import unittest
from importlib.resources import files
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NamespaceMigrationTests(unittest.TestCase):
    def test_component_namespace_and_entry_point(self):
        package = importlib.import_module("zog.host_install")
        cli = importlib.import_module("zog.host_install.cli")
        self.assertEqual(package.__version__, "0.5.0")
        self.assertTrue(callable(cli.main))
        self.assertFalse((ROOT / "host_install").exists())
        self.assertFalse((ROOT / "src" / "zog" / "__init__.py").exists())

        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(
            project["project"]["scripts"]["host-install"],
            "zog.host_install.cli:main",
        )

    def test_runtime_systemd_templates_are_packaged(self):
        packaged = files("zog.host_install").joinpath("systemd")
        for name in (
            "host-install-admission.socket",
            "host-install-admission@.service",
            "host-install-identity.service",
            "host-install-prepare.service",
        ):
            self.assertTrue(packaged.joinpath(name).is_file(), name)

    def test_no_legacy_python_module_paths(self):
        forbidden = (
            "from " + "host_install",
            "import " + "host_install",
            "'" + "host_install.",
            '"' + "host_install.",
            "from " + "host_identify",
            "import " + "host_identify",
            "from " + "host_discover",
            "import " + "host_discover",
            "'" + "image_build.",
            '"' + "image_build.",
        )
        checked = list((ROOT / "src").rglob("*.py")) + [
            path for path in (ROOT / "tests").rglob("*.py") if path != Path(__file__)
        ]
        for path in checked:
            text = path.read_text()
            for marker in forbidden:
                self.assertNotIn(marker, text, f"{marker!r} in {path.relative_to(ROOT)}")


if __name__ == "__main__":
    unittest.main()
