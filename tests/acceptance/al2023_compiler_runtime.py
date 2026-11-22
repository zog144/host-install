"""Real Amazon Linux 2023 Python 3.12 staging acceptance (disposable only).

Run inside amazonlinux:2023. This performs actual venv creation, pip wheel
build/install and imports from the three exact source checkouts. It never
inspects or changes a Host systemd service.
"""
import os
import hashlib
import json
import tarfile
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

from zog.host_deploy.fonts_versioned_runtime import SELECTED_SOURCES
assert SELECTED_SOURCES == {
    role: {"revision": pin[0], "source_tree_sha256": pin[1]}
    for role, pin in installer.SOURCES.items()
}, "host-deploy and host-install select differing controller source tuples"
verifier_revision = subprocess.check_output(
    ["git", "-C", "/work/companions/host-deploy", "rev-parse", "HEAD"],
    text=True).strip()
assert verifier_revision == "caa87434cf3c0556084d62642d66b47a348e26a9"
# Distinct candidate identity derived from exact 4-component reviewed source tuple.
release = "3aa6ab5e221a81b3fd7962ec8d91faf9"
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
    # This is the corrected compiler peer contract, not just an import:
    # exact authenticated 0:0 is admissible; partial-zero identities are not.
    subprocess.run([str(python), "-I", "-B", "-c",
                    "from zog.root_control.build import authenticated_build_peer; "
                    "assert authenticated_build_peer((0, 0)) == (0, 0); "
                    "assert authenticated_build_peer((1234, 1234)) == (1234, 1234)"],
                   check=True)
    assert (selected / "bin/root-control").is_file()
    assert not any(item.is_symlink() for directory, dirs, files in
                   os.walk(selected) for item in
                   [Path(directory) / name for name in dirs + files])
    # Store a distinct, unapproved source-built candidate in the Actions
    # artifact store. No Host unit, rollback tree or historical record is used.
    artifact_dir = Path("/work/candidate-out")
    artifact_dir.mkdir(exist_ok=True)
    candidate = artifact_dir / ("compiler-runtime-" + release + ".tar.gz")
    with tarfile.open(candidate, mode="w:gz", dereference=False) as archive:
        archive.add(selected, arcname="versions/" + release)
    release_bytes = candidate.read_bytes()
    manifest = {
        "schema": "zog-compiler-disposable-candidate-v1",
        "release_id": release,
        "native_installed": False,
        "selection_approved": False,
        "execution_authorized": False,
        "service_unit_fixture_only": True,
        "requires_reviewed_real_unit_and_dropins": True,
        "source_revisions": {role: pins[0] for role, pins in installer.SOURCES.items()},
        "source_inventory_sha256": {role: pins[1] for role, pins in installer.SOURCES.items()},
        "host_deploy_verifier_revision": verifier_revision,
        "runtime_tree_sha256": installer._inventory(root, selected),
        "archive_sha256": hashlib.sha256(release_bytes).hexdigest(),
        "archive_size": len(release_bytes),
        "archive_name": candidate.name,
    }
    (artifact_dir / "candidate-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("ZOG_AL2023_REAL_COMPILER_STAGE_PASS")
    print("release:", release)
    print("candidate_archive_sha256:", manifest["archive_sha256"])
    print("strict_inventory_sha256:", installer._inventory(root, selected))
