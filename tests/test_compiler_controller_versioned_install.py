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
    external_python = tmp_path / "usr/bin/python3.12"
    external_python.parent.mkdir(parents=True)
    external_python.write_bytes(b"verified python interpreter")
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
            "staged_sha256": hashlib.sha256(staged).hexdigest(),
        },
        "composition": {
            "original_fragment": {
                "path": str(installer.UNIT_DIR / service),
                "sha256": hashlib.sha256(original).hexdigest(),
                "size": len(original), "mode": 0o644, "uid": 0, "gid": 0},
            "selected_fragment": {
                "path": str(installer.VERSIONS / release / "systemd" / service),
                "sha256": hashlib.sha256(staged).hexdigest(),
                "size": len(staged), "mode": 0o644, "uid": 0, "gid": 0},
            "original_dropins": [], "selected_dropins": [],
            "original_effective": {}, "selected_effective": {},
        },
        "rollback": {
            "unit_sha256": hashlib.sha256(original).hexdigest(),
            "saved_runtime_root": str(installer.BACKUPS / release / "previous-runtime"),
            "runtime_tree_sha256": "will-fill-after-preserve",
            "original_runtime": "/opt/old",
            "legacy_inventory_schema": installer.legacy_rollback.SCHEMA,
            "legacy_inventory_sha256": "will-fill",
            "python_interpreter_chain": [],
        }
    }

    class Inspector:
        def __init__(self):
            self.phases = []
        def inspect_installed(self, selection, phase, transaction_guard=False):
            self.phases.append(phase)
            current = unit.read_bytes()
            assert current == (original if phase == "staged" else staged)
            if transaction_guard:
                guard = unit.with_name(service + ".d") / (
                    "00-zog-compiler-selection-guard.conf")
                assert guard.is_file() and not guard.is_symlink()
                assert (b"ConditionPathExists=" in guard.read_bytes())
                assert not installer.host_path(
                    tmp_path, installer.BACKUPS / release /
                    "startup-permit").exists()
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
    evidence = installer.legacy_rollback.inventory(
        root, installer.host_path(root, data["rollback"]["saved_runtime_root"]))
    data["rollback"].update({
        "runtime_tree_sha256": evidence["tree_sha256"],
        "legacy_inventory_sha256": evidence["inventory_sha256"],
        "python_interpreter_chain": evidence["python_interpreter_chain"]})
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
    with pytest.raises(installer.legacy_rollback.LegacyHold, match="legacy rollback copy differs"):
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
    with pytest.raises(installer.legacy_rollback.LegacyHold, match="unexpected legacy runtime symlink"):
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
    monkeypatch.setattr(installer, "_snapshot_sources",
                        lambda sources, destination: sources)
    mock_box = root / "checkout-box-control"
    (mock_box / "box-control").mkdir(parents=True)
    (mock_box / "box-control/pyproject.toml").write_text("[build-system]\n")
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
         "box-control": str(mock_box),
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
             "box-control": str(mock_box),
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
    with pytest.raises(installer.CompilerInstallerHold, match="does not name retained runtime"):
        installer.preserve(release, service=service,
                           original_runtime="/opt/old", root=root)



def with_realistic_dropins(setup):
    """Four original overrides, reviewed two-file successor, no Host service."""
    root, release, service, unit, original, staged, old, data, inspector = setup
    original_dir = unit.with_name(service + ".d")
    original_dir.mkdir()
    old_files = {
        "60-boot-a-restrictive-import.conf":
            b"[Service]\nExecStart=\nExecStart=/opt/old/boot-a.py\nReadOnlyPaths=/opt/old\n",
        "70-fonts-combined-runtime.conf":
            b"[Service]\nExecStart=\nExecStart=/opt/old/bin/root-control\nReadOnlyPaths=/opt/old\n",
        "gateway-mounts.conf":
            b"[Unit]\nRequires=state.mount\nAfter=state.mount\n",
        "issuer-persistence.conf":
            b"[Service]\nExecStartPre=/usr/bin/test -d /state\nReadOnlyPaths=/state\n",
    }
    for name, body in old_files.items():
        (original_dir / name).write_bytes(body)
    successor = installer.host_path(
        root, installer.VERSIONS / release / "systemd" / (service + ".d"))
    successor.mkdir()
    successor_files = {
        "70-fonts-combined-runtime.conf":
            (b"[Service]\nExecStart=\nExecStart=/opt/zog/compiler-runtime/"
             + b"versions/" + release.encode() + b"/bin/root-control\n"),
        "gateway-mounts.conf":
            b"[Unit]\nRequires=state.mount\nAfter=state.mount\n",
        "issuer-persistence.conf":
            b"[Service]\nExecStartPre=/usr/bin/test -d /state\nReadOnlyPaths=/state\n",
    }
    for name, body in successor_files.items():
        (successor / name).write_bytes(body)
    data["composition"]["original_dropins"] = installer._dropins(root, original_dir)
    data["composition"]["selected_dropins"] = installer._dropins(root, successor)
    return root, release, service, unit, original, staged, old, data, inspector


def test_all_original_dropins_preserved_then_selected_and_restored(setup):
    root, release, service, unit, original, staged, old, data, inspector = (
        with_realistic_dropins(setup))
    originals = data["composition"]["original_dropins"]
    successors = data["composition"]["selected_dropins"]
    original_dir = unit.with_name(service + ".d")
    installer.preserve(release, service=service,
                       original_runtime="/opt/old", root=root)
    backup_dir = installer.host_path(
        root, installer.BACKUPS / release / (service + ".d"))
    assert installer._dropins(root, backup_dir) == originals
    evidence = installer.legacy_rollback.inventory(
        root, installer.host_path(root, data["rollback"]["saved_runtime_root"]))
    data["rollback"].update({
        "runtime_tree_sha256": evidence["tree_sha256"],
        "legacy_inventory_sha256": evidence["inventory_sha256"],
        "python_interpreter_chain": evidence["python_interpreter_chain"]})
    installer.select("reviewed.json", "f" * 64, root=root)
    assert installer._dropins(root, original_dir) == successors
    assert "60-boot-a-restrictive-import.conf" not in [
        item["name"] for item in installer._dropins(root, original_dir)]
    installer.restore("reviewed.json", "f" * 64, root=root)
    assert installer._dropins(root, original_dir) == originals
    assert unit.read_bytes() == original
    assert installer._dropins(root, backup_dir) == originals


def test_interrupted_dropin_switch_is_masked_and_explicitly_recoverable(
        setup, monkeypatch):
    root, release, service, unit, original, staged, old, data, inspector = (
        with_realistic_dropins(setup))
    installer.preserve(release, service=service,
                       original_runtime="/opt/old", root=root)
    evidence = installer.legacy_rollback.inventory(
        root, installer.host_path(root, data["rollback"]["saved_runtime_root"]))
    data["rollback"].update({
        "runtime_tree_sha256": evidence["tree_sha256"],
        "legacy_inventory_sha256": evidence["inventory_sha256"],
        "python_interpreter_chain": evidence["python_interpreter_chain"]})
    actual_switch = installer._switch_dropins

    def interrupted(root, active_dir, existing, wanted_dir, wanted, guard):
        # Simulate crash after mask and first unlink, before all successors.
        (active_dir / existing[0]["name"]).unlink()
        raise OSError("interrupted-after-first-dropin")
    monkeypatch.setattr(installer, "_switch_dropins", interrupted)
    with pytest.raises(OSError, match="interrupted-after-first"):
        installer.select("reviewed.json", "f" * 64, root=root)
    assert unit.is_symlink() and unit.readlink() == Path("/dev/null")
    monkeypatch.setattr(installer, "_switch_dropins", actual_switch)
    assert installer.restore("reviewed.json", "f" * 64, root=root)["state"] == "restored"
    assert unit.read_bytes() == original
    assert installer._dropins(root, unit.with_name(service + ".d")) == (
        data["composition"]["original_dropins"])


def test_foreign_dropin_prevents_selection_and_cannot_be_erased(setup):
    root, release, service, unit, original, staged, old, data, inspector = (
        with_realistic_dropins(setup))
    installer.preserve(release, service=service,
                       original_runtime="/opt/old", root=root)
    evidence = installer.legacy_rollback.inventory(
        root, installer.host_path(root, data["rollback"]["saved_runtime_root"]))
    data["rollback"].update({
        "runtime_tree_sha256": evidence["tree_sha256"],
        "legacy_inventory_sha256": evidence["inventory_sha256"],
        "python_interpreter_chain": evidence["python_interpreter_chain"]})
    unexpected = unit.with_name(service + ".d") / "90-foreign.conf"
    unexpected.write_bytes(b"[Service]\nExecStart=/foreign\n")
    with pytest.raises(installer.CompilerInstallerHold, match="drop-in"):
        installer.select("reviewed.json", "f" * 64, root=root)
    assert unexpected.read_bytes().endswith(b"/foreign\n")
    assert unit.read_bytes() == original


def test_existing_old_python_symlink_still_denied_without_rewrite(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    python = old / "bin/python"
    python.symlink_to("python3.12")
    with pytest.raises(installer.legacy_rollback.LegacyHold, match="unexpected legacy runtime symlink"):
        installer.preserve(release, service=service,
                           original_runtime="/opt/old", root=root)
    assert python.is_symlink() and python.readlink() == Path("python3.12")



def _four_links(old):
    (old / "venv/bin").mkdir(parents=True)
    (old / "venv/lib").mkdir()
    (old / "venv/lib/installed.py").write_bytes(b"old immutable module")
    for rel, target in installer.legacy_rollback.LINKS.items():
        link = old / rel
        link.symlink_to(target)
    return {rel: (old / rel).readlink().as_posix()
            for rel in installer.legacy_rollback.LINKS}


def test_all_four_legacy_links_preserved_as_literal_objects(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    original_links = _four_links(old)
    receipt = installer.preserve(release, service=service,
                                 original_runtime="/opt/old", root=root)
    copy = installer.host_path(root, installer.BACKUPS / release / "previous-runtime")
    assert receipt["legacy_inventory_schema"] == installer.legacy_rollback.SCHEMA
    assert receipt["runtime_tree_sha256"]
    assert receipt["python_interpreter_chain"][0]["path"] == "/usr/bin/python3.12"
    for rel, target in original_links.items():
        link = copy / rel
        assert link.is_symlink()
        assert link.readlink().as_posix() == target
        assert (old / rel).readlink().as_posix() == target
    assert installer.legacy_rollback.assert_copy(root, old, copy)[
        "inventory_sha256"] == receipt["legacy_inventory_sha256"]


def test_changed_literal_legacy_target_is_rejected(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    _four_links(old)
    installer.preserve(release, service=service, original_runtime="/opt/old", root=root)
    copy = installer.host_path(root, installer.BACKUPS / release / "previous-runtime")
    link = copy / "venv/bin/python3"
    link.unlink()
    link.symlink_to("python")
    with pytest.raises(installer.legacy_rollback.LegacyHold, match="target differs"):
        installer.legacy_rollback.assert_copy(root, old, copy)


@pytest.mark.parametrize("path,target", [
    ("venv/bin/python", "../../../escape"),
    ("venv/bin/python3", "python"),
    ("venv/bin/python3.12", "/usr/bin/other"),
    ("venv/bin/foreign", "python3.12"),
])
def test_unreviewed_or_escaping_legacy_link_holds(setup, path, target):
    root, release, service, unit, original, staged, old, data, inspector = setup
    (old / "venv/bin").mkdir(parents=True)
    (old / path).symlink_to(target)
    with pytest.raises(installer.legacy_rollback.LegacyHold):
        installer.preserve(release, service=service, original_runtime="/opt/old", root=root)


def test_external_python_target_change_blocks_restore(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    _four_links(old)
    receipt = installer.preserve(
        release, service=service, original_runtime="/opt/old", root=root)
    ext = root / "usr/bin/python3.12"
    ext.write_bytes(b"different interpreter")
    changed = installer.legacy_rollback.inventory(root, old)
    assert changed["python_interpreter_chain"] != receipt["python_interpreter_chain"]
    assert changed["inventory_sha256"] != receipt["legacy_inventory_sha256"]


def test_external_interpreter_symlink_chain_is_attested(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    _four_links(old)
    ext = root / "usr/bin/python3.12"
    ext.unlink()
    ext.symlink_to("python3.12-real")
    (ext.parent / "python3.12-real").write_bytes(b"verified interpreter real")
    result = installer.preserve(release, service=service,
                                original_runtime="/opt/old", root=root)
    chain = result["python_interpreter_chain"]
    assert [e["type"] for e in chain] == ["symlink", "file"]
    assert chain[0]["target"] == "python3.12-real"
    assert chain[-1]["sha256"] == hashlib.sha256(
        b"verified interpreter real").hexdigest()


def test_selected_version_symlink_still_rejected(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    selected = installer.host_path(root, installer.VERSIONS / release)
    (selected / "bin/foreign-link").symlink_to("root-control")
    with pytest.raises(installer.CompilerInstallerHold, match="linked"):
        installer._inventory(root, selected)



def test_restore_with_four_links_keeps_original_runtime_path(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    links = _four_links(old)
    preserved(setup)
    installer.select("reviewed.json", "f" * 64, root=root)
    assert installer.restore("reviewed.json", "f" * 64, root=root)[
        "state"] == "restored"
    assert unit.read_bytes() == original
    assert data["rollback"]["original_runtime"] == "/opt/old"
    for rel, target in links.items():
        assert (old / rel).readlink().as_posix() == target
    copied = installer.host_path(
        root, installer.BACKUPS / release / "previous-runtime")
    assert installer.legacy_rollback.assert_copy(root, old, copied)[
        "inventory_sha256"] == data["rollback"]["legacy_inventory_sha256"]


def test_changed_external_python_blocks_explicit_restore(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    _four_links(old)
    preserved(setup)
    installer.select("reviewed.json", "f" * 64, root=root)
    (root / "usr/bin/python3.12").write_bytes(b"replaced external interpreter")
    with pytest.raises(installer.CompilerInstallerHold,
                       match="protected original runtime or external Python changed"):
        installer.restore("reviewed.json", "f" * 64, root=root)
    assert unit.read_bytes() == staged



def test_zero_length_legacy_regular_file_is_allowed(setup):
    root, release, service, unit, original, staged, old, data, inspector = setup
    (old / "venv").mkdir()
    (old / "venv/__init__.py").touch()
    receipt = installer.preserve(
        release, service=service, original_runtime="/opt/old", root=root)
    copy = installer.host_path(root, installer.BACKUPS / release / "previous-runtime")
    assert (copy / "venv/__init__.py").stat().st_size == 0
    assert installer.legacy_rollback.assert_copy(root, old, copy)[
        "inventory_sha256"] == receipt["legacy_inventory_sha256"]



def test_fresh_venv_links_become_real_executables_without_weakening_inventory(tmp_path):
    venv = tmp_path / "new-venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "lib").mkdir()
    actual = venv / "bin/python3.12"
    actual.write_bytes(b"new Python 3.12 executable")
    actual.chmod(0o755)
    (venv / "bin/python").symlink_to("python3.12")
    (venv / "bin/python3").symlink_to("python3.12")
    (venv / "lib64").symlink_to("lib", target_is_directory=True)

    normalized = installer._normalize_new_venv(venv)
    assert normalized == ["bin/python", "bin/python3", "lib64"]
    for name in ("python", "python3", "python3.12"):
        entry = venv / "bin" / name
        assert entry.is_file() and not entry.is_symlink()
        assert entry.read_bytes() == b"new Python 3.12 executable"
        assert entry.stat().st_mode & 0o100
    assert not (venv / "lib64").exists()
    assert (venv / "lib").is_dir()
    assert installer._inventory(tmp_path, venv)


def test_fresh_venv_unexpected_or_escaping_link_holds_without_rewrite(tmp_path):
    venv = tmp_path / "new-venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin/python3.12").write_bytes(b"python")
    (venv / "bin/python").symlink_to("../../foreign")
    with pytest.raises(installer.CompilerInstallerHold, match="unexpected link"):
        installer._normalize_new_venv(venv)
    assert (venv / "bin/python").is_symlink()
    (venv / "bin/python").unlink()
    (venv / "bin/python").symlink_to("python3.12")
    (venv / "other").symlink_to("bin")
    with pytest.raises(installer.CompilerInstallerHold, match="unexpected link"):
        installer._normalize_new_venv(venv)
    assert (venv / "other").is_symlink()



def _manager_properties(*, pid=101, timestamp="old", command="/opt/old/bin/root-control",
                        pre_command="/usr/bin/test -d /state", ignore="no",
                        include_pre=True):
    def record(argv, *, pid, ignore):
        executable = argv.split()[0]
        return ("{ path=" + executable + " ; argv[]=" + argv
                + " ; ignore_errors=" + ignore
                + " ; pid=" + str(pid) + " ; start_time=" + timestamp
                + " ; stop_time=" + timestamp
                + " ; code=exited ; status=0 ; }")
    return {
        "ExecStart": record(command, pid=pid, ignore=ignore),
        "ExecStartPre": record(pre_command, pid=pid+1, ignore="no")
                        if include_pre else "",
        "ReadOnlyPaths": "/state", "Requires": "state.mount",
        "After": "state.mount",
    }


def test_manager_effective_identity_stable_across_process_changes():
    from zog.host_deploy import fonts_unit_composition as composition
    first, old_evidence = composition.normalize_loaded_commands(
        _manager_properties(pid=12, timestamp="start-old"))
    next_stable, new_evidence = composition.normalize_loaded_commands(
        _manager_properties(pid=992, timestamp="start-new"))
    assert first == next_stable
    assert old_evidence != new_evidence
    assert first["ExecStart"][0]["path"] == "/opt/old/bin/root-control"
    assert len(first["ExecStartPre"]) == 1


@pytest.mark.parametrize("overrides", [
    {"command": "/opt/other/bin/root-control"},
    {"pre_command": "/usr/bin/test -d /foreign"},
    {"ignore": "yes"},
    {"include_pre": False},
])
def test_manager_stable_identity_rejects_changed_commands(overrides):
    from zog.host_deploy import fonts_unit_composition as composition
    stable, _ = composition.normalize_loaded_commands(_manager_properties())
    changed, _ = composition.normalize_loaded_commands(
        _manager_properties(**overrides))
    assert stable != changed


def test_preservation_records_stable_identity_separately_from_process_evidence(
        setup, monkeypatch):
    from zog.host_deploy import fonts_unit_composition as composition
    root, release, service, unit, original, staged, old, data, inspector = setup
    original_dir = unit.with_name(service + ".d")
    original_dir.mkdir()
    pre = original_dir / "issuer-persistence.conf"
    pre.write_bytes(b"[Service]\nExecStartPre=/usr/bin/test -d /state\n")
    live = _manager_properties(pid=81)
    # The effective configuration in this fixture is an old runtime command
    # plus the exact prestart guard, just as in the unit file/drop-in.
    live["ReadOnlyPaths"] = ""
    live["Requires"] = ""
    live["After"] = ""
    def manager(*args):
        return composition.normalize_loaded_commands(live)
    monkeypatch.setattr(installer, "_current_manager_composition", manager)
    custody = installer.preserve(release, service=service,
                                 original_runtime="/opt/old", root=root)
    assert custody["original_loaded_properties"]["ExecStart"][0]["path"] == (
        "/opt/old/bin/root-control")
    assert custody["original_loaded_properties"]["ExecStartPre"][0]["path"] == (
        "/usr/bin/test")
    assert custody["original_loaded_process_metadata"]["ExecStart"][0]["pid"] == "81"
    assert custody["original_loaded_process_metadata"]["ExecStartPre"][0]["pid"] == "82"
    assert "start_time" not in custody["original_loaded_properties"]["ExecStart"][0]


@pytest.mark.parametrize("changes", [
    {"pre_command": "/usr/bin/test -d /wrong"},
    {"ignore": "yes"},
    {"include_pre": False},
])
def test_preservation_rejects_changed_prestart_and_execution_flag(
        setup, monkeypatch, changes):
    from zog.host_deploy import fonts_unit_composition as composition
    root, release, service, unit, original, staged, old, data, inspector = setup
    unit.with_name(service + ".d").mkdir()
    (unit.with_name(service + ".d") / "issuer.conf").write_bytes(
        b"[Service]\nExecStartPre=/usr/bin/test -d /state\n")
    raw = _manager_properties(**changes)
    raw.update(ReadOnlyPaths="", Requires="", After="")
    monkeypatch.setattr(
        installer, "_current_manager_composition",
        lambda *args: composition.normalize_loaded_commands(raw))
    with pytest.raises(installer.CompilerInstallerHold,
                       match="composed ExecStart"):
        installer.preserve(release, service=service,
                           original_runtime="/opt/old", root=root)



def test_read_manager_normalizes_systemd252_loaded_records_with_volatile_changes():
    service = "zog-certbot-seed-root.service"
    fragment = Path("/etc/systemd/system") / service
    dropin = "issuer-persistence.conf"
    def read(pid, stamp):
        raw = _manager_properties(pid=pid, timestamp=stamp)
        props = dict(raw, LoadState="loaded", FragmentPath=str(fragment),
                     DropInPaths=str(fragment) + ".d/" + dropin)
        def runner(args, **kwargs):
            assert args[0:2] == ["/usr/bin/systemctl", "show"]
            return SimpleNamespace(
                returncode=0,
                stdout="".join(k + "=" + v + "\n" for k, v in props.items()))
        return installer._current_manager_composition(
            Path("/"), service, fragment, [{"name": dropin}], runner)
    first, process_a = read(100, "old")
    second, process_b = read(999, "new")
    assert first == second
    assert process_a != process_b
    assert first["ExecStart"][0]["flags"]["ignore_errors"] == "no"
    assert first["ExecStartPre"][0]["path"] == "/usr/bin/test"


def test_manager_unknown_command_metadata_fails_closed():
    service = "zog-certbot-seed-root.service"
    fragment = Path("/etc/systemd/system") / service
    raw = _manager_properties()
    raw["ExecStart"] = raw["ExecStart"].replace(
        " ; code=exited", " ; unsupported=surprise ; code=exited")
    props = dict(raw, LoadState="loaded", FragmentPath=str(fragment),
                 DropInPaths="")
    def runner(args, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="".join(k + "=" + v + "\n" for k, v in props.items()))
    with pytest.raises(installer.CompilerInstallerHold, match="unknown or incomplete"):
        installer._current_manager_composition(
            Path("/"), service, fragment, [], runner)
