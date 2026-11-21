"""Real Amazon Linux 2023 Python 3.12 staging acceptance (disposable only).

Run inside amazonlinux:2023. This performs actual venv creation, pip wheel
build/install and imports from the three exact source checkouts. It never
inspects or changes a Host systemd service.
"""
import os
from pathlib import Path
import subprocess
import tempfile

from zog.host_install import compiler_controller_versioned_install as installer

root_control = Path("/work/companions/root-control")
box_control = Path("/work/companions/box-control")
image_build = Path("/work/companions/image-build")
checkouts = {
    "root-control": root_control,
    "box-control": box_control,
    "image-build": image_build,
}
for path in checkouts.values():
    subprocess.run(["git", "config", "--global", "--add",
                    "safe.directory", str(path)], check=True)
installer.verify_sources(checkouts)
release = "a1" * 16
service = "zog-root-control.service"
unit = (f"[Service]\nExecStart=/opt/zog/compiler-runtime/versions/"
        f"{release}/bin/root-control\n").encode()
with tempfile.TemporaryDirectory(prefix="compiler-al2023-") as tmp:
    root = Path(tmp)
    result = installer.stage(
        release, checkouts, python="/usr/bin/python3.12",
        service=service, executable="root-control",
        unit_template=unit, root=root,
    )
    selected = installer.host_path(root, installer.VERSIONS / release)
    assert result["execution_authorized"] is False
    assert result["installed_selection_reviewed"] is False
    assert installer._inventory(root, selected)
    python = selected / "venv/bin/python"
    subprocess.run([str(python), "-I", "-B", "-c",
                    "import sys, zog.root_control, zog.box_control, "
                    "zog.image_build, zog.image_build.remote_operations; "
                    "assert sys.version_info[:2] == (3, 12)"],
                   check=True)
    subprocess.run([str(python), "-m", "pip", "check"], check=True)
    assert (selected / "bin/root-control").is_file()
    assert not any(item.is_symlink() for directory, dirs, files in
                   os.walk(selected) for item in
                   [Path(directory) / name for name in dirs + files])
    print("ZOG_AL2023_REAL_COMPILER_STAGE_PASS")
    print("release:", release)
    print("strict_inventory_sha256:", installer._inventory(root, selected))
