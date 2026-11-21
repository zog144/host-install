"""Compiler rollback disposable source tests: no Host, SSM or service actions."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_install import compiler_controller_versioned_install as installer


@pytest.fixture
def setup(tmp_path, monkeypatch):
    release = "a" * 32
    service = "zog-root-control.service"
    unit = installer.host_path(tmp_path, installer.UNIT_DIR / service)
    unit.parent.mkdir(parents=True)
    original = b"[Service]\nExecStart=/opt/old/bin/root-control\n"
    unit.write_bytes(original)
    old = installer.host_path(tmp_path, "/opt/old")
    (old / "bin").mkdir(parents=True)
    (old / "bin/root-control").write_bytes(b"original daemon")
    new = installer.host_path(tmp_path, installer.VERSIONS / release)
    (new / "bin").mkdir(parents=True)
    staged = (
        b"[Service]\nExecStart=/opt/zog/compiler-runtime/versions/"
        + release.encode() + b"/bin/root-control\n"
    )
    (new / "bin/root-control").write_bytes(b"new daemon")
    (new / "systemd").mkdir()
    (new / "systemd" / service).write_bytes(staged)
    data = {
        "release_id": release,
        "service": {
            "name": service,
            "active_unit": str(installer.UNIT_DIR / service),
            "staged_unit": str(installer.VERSIONS / release / "systemd" / service),
        },
        "rollback": {
            "unit_sha256": hashlib.sha256(original).hexdigest(),
            "saved_runtime_root": str(installer.BACKUPS / release / "previous-runtime"),
            "runtime_tree_sha256": "will-fill-after-preserve",
        }
    }

    class Inspector:
        def __init__(self):
            self.phases = []
        def inspect_installed(self, selection, phase):
            self.phases.append(phase)
            current = unit.read_bytes()
            assert current == (original if phase == "staged" else staged)
        def _retained_tree_sha256(self, path):
            return installer._inventory(tmp_path, path)

    inspector = Inspector()
    monkeypatch.setattr(installer, "_reviewed",
                        lambda path, sha: (inspector, data))
    return tmp_path, release, service, unit, original, staged, old, data, inspector


def preserved(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    installer.preserve(release, service=service,
                       original_runtime="/opt/old", root=root)
    data["rollback"]["runtime_tree_sha256"] = installer._inventory(
        root, installer.host_path(root, data["rollback"]["saved_runtime_root"]))
    return setup


def test_preserve_select_and_restore_without_touching_original_runtime(setup):
    root, release, service, unit, original, staged, old, data, inspector = preserved(setup)
    copied = installer.host_path(root, installer.BACKUPS / release / "previous-runtime")
    assert (copied / "bin/root-control").read_bytes() == b"original daemon"
    assert (old / "bin/root-control").read_bytes() == b"original daemon"
    result = installer.select("reviewed.json", "f" * 64, root=root)
    assert result["state"] == "selected"
    assert unit.read_bytes() == staged
    assert inspector.phases == ["staged", "selected"]
    rollback = installer.restore("reviewed.json", "f" * 64, root=root)
    assert rollback["state"] == "restored"
    assert unit.read_bytes() == original
    assert (copied / "bin/root-control").read_bytes() == b"original daemon"


def test_second_selection_does_not_overwrite_rollback(setup):
    root, release, service, unit, original, staged, old, data, inspector = preserved(setup)
    installer.select("reviewed.json", "f" * 64, root=root)
    with pytest.raises(installer.CompilerInstallerHold, match="previous or interrupted"):
        installer.select("reviewed.json", "f" * 64, root=root)
    assert unit.read_bytes() == staged


def test_restore_rejects_foreign_active_unit(setup):
    root, release, service, unit, original, staged, old, data, inspector = preserved(setup)
    installer.select("reviewed.json", "f" * 64, root=root)
    unit.write_bytes(b"foreign unit")
    with pytest.raises(installer.CompilerInstallerHold, match="foreign"):
        installer.restore("reviewed.json", "f" * 64, root=root)
    assert unit.read_bytes() == b"foreign unit"


def test_pending_interrupted_record_can_be_explicitly_restored(setup):
    root, release, service, unit, original, staged, old, data, inspector = preserved(setup)
    installer.select("reviewed.json", "f" * 64, root=root)
    record = installer.host_path(root, installer.BACKUPS / release / "selection-transaction.json")
    saved = json.loads(record.read_text())
    saved["state"] = "pending"
    record.write_text(json.dumps(saved))
    assert installer.restore("reviewed.json", "f" * 64, root=root)["state"] == "restored"


def test_tampered_retained_runtime_refuses_restore(setup):
    root, release, service, unit, original, staged, old, data, inspector = preserved(setup)
    installer.select("reviewed.json", "f" * 64, root=root)
    copied = installer.host_path(root, installer.BACKUPS / release / "previous-runtime")
    (copied / "bin/root-control").write_bytes(b"tampered")
    with pytest.raises(installer.CompilerInstallerHold, match="protected original runtime"):
        installer.restore("reviewed.json", "f" * 64, root=root)


def test_preservation_cannot_be_repeated(setup):
    root, release, service, unit, original, staged, old, data, inspector = preserved(setup)
    with pytest.raises(installer.CompilerInstallerHold, match="already exists"):
        installer.preserve(release, service=service,
                           original_runtime="/opt/old", root=root)


def test_release_id_invalid(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    with pytest.raises(installer.CompilerInstallerHold, match="lower-case hexadecimal"):
        installer.preserve("../other", service=service, original_runtime="/opt/old", root=root)


def test_no_symlinks_in_retained_runtime(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    (old / "bin/linked").symlink_to("root-control")
    with pytest.raises(installer.CompilerInstallerHold, match="linked or special"):
        installer.preserve(release, service=service, original_runtime="/opt/old", root=root)
    assert unit.read_bytes() == original


def test_invalid_source_tuple_does_not_stage(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    with pytest.raises(installer.CompilerInstallerHold, match="three source"):
        installer.stage("b" * 32, {"root-control": old}, python="/usr/bin/python3",
                        service=service, executable="root-control",
                        unit_template=staged, root=root)
    assert unit.read_bytes() == original


def test_unknown_executable_refused_before_installer(setup, monkeypatch):
    root, release, service, unit, original, staged, old, data, inspector = setup
    monkeypatch.setattr(installer, "verify_sources", lambda _: None)
    with pytest.raises(installer.CompilerInstallerHold, match="one exact release executable"):
        installer.stage("b" * 32, {}, python="/usr/bin/python3",
                        service=service, executable="root-control",
                        unit_template=staged, root=root)



def test_stage_three_sources_into_isolated_release_without_selecting(setup, monkeypatch):
    root, release, service, unit, original, staged, old, data, inspector = setup
    candidate = "b" * 32
    expected = (
        b"[Service]\nExecStart=/opt/zog/compiler-runtime/versions/"
        + candidate.encode() + b"/bin/root-control\n"
    )
    monkeypatch.setattr(installer, "verify_sources", lambda sources: None)
    commands = []

    def runner(argv, check):
        commands.append([str(arg) for arg in argv])
        if len(argv) >= 4 and argv[1:3] == ["-m", "venv"]:
            venv = Path(argv[-1])
            (venv / "bin").mkdir(parents=True)
            (venv / "bin/python").write_bytes(b"python-executable")
            (venv / "bin/root-control").write_bytes(b"selected-console-entrypoint")
            (venv / "bin/root-control").chmod(0o755)
        return SimpleNamespace(returncode=0)

    result = installer.stage(
        candidate,
        {"root-control": "/review/root-control",
         "box-control": "/review/box-control",
         "image-build": "/review/image-build"},
        python="/usr/bin/python3.12",
        service=service,
        executable="root-control",
        unit_template=expected,
        root=root,
        runner=runner,
    )
    candidate_root = installer.host_path(root, installer.VERSIONS / candidate)
    assert result["release_id"] == candidate
    assert result["execution_authorized"] is False
    assert result["installed_selection_reviewed"] is False
    assert (candidate_root / "systemd" / service).read_bytes() == expected
    assert (candidate_root / "bin/root-control").read_bytes() == b"selected-console-entrypoint"
    assert unit.read_bytes() == original
    assert (old / "bin/root-control").read_bytes() == b"original daemon"
    assert any(command[1:4] == ["-m", "pip", "check"] for command in commands)
    with pytest.raises(installer.CompilerInstallerHold, match="release already staged"):
        installer.stage(
            candidate,
            {"root-control": "/review/root-control",
             "box-control": "/review/box-control",
             "image-build": "/review/image-build"},
            python="/usr/bin/python3.12",
            service=service,
            executable="root-control",
            unit_template=expected,
            root=root,
            runner=runner,
        )


def test_original_runtime_cannot_alias_rollback_root(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    with pytest.raises(installer.CompilerInstallerHold, match="aliases selected"):
        installer.preserve(release, service=service,
                           original_runtime=str(installer.BACKUPS), root=root)
    assert unit.read_bytes() == original


def test_original_unit_must_point_to_preserved_runtime(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    unit.write_bytes(b"[Service]\nExecStart=/opt/somewhere-else/root-control\n")
    with pytest.raises(installer.CompilerInstallerHold, match="does not reference"):
        installer.preserve(release, service=service,
                           original_runtime="/opt/old", root=root)
