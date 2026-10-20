import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace

import pytest

from zog.host_install import image_progress_profile as profile
from zog.host_install.state_contract import StateError


ROOT = Path(__file__).resolve().parents[1]
IMAGE_BUILD_SOURCE = Path(os.environ.get("IMAGE_BUILD_SOURCE", "companions/image-build"))


def stage(tmp_path, monkeypatch, **overrides):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    values = dict(
        output=tmp_path / "overlay",
        image_build_state_root="/var/lib/zog-image-build",
        consumer_uid=12041,
        producer_uid=11051,
        producer_gid=11052,
        image_build_source=IMAGE_BUILD_SOURCE,
        producer_source=ROOT,
        identity_evidence={
            "welcome_account": "synthetic",
            "image_build_state_owner": "synthetic",
            "image_build_account": "synthetic",
        },
    )
    values.update(overrides)
    return profile.stage(**values)


def test_reviewed_image_build_source_is_exactly_pinned():
    observed = profile.verify_reviewed_source(IMAGE_BUILD_SOURCE)
    assert len(observed) == 85
    assert set(observed) == set(profile.IMAGE_BUILD_SOURCE_PYTHON_BLOBS)
    assert profile.IMAGE_BUILD_COMMIT == "fcc12f3db959afe395b1adfb5b0b4dc1f16a3258"
    assert profile.IMAGE_BUILD_REPOSITORY == "zog144/image-build"
    assert profile.IMAGE_BUILD_MODULE_BLOBS[
        "zog.image_build.post_install_progress_broker"
    ] == "fc50a6f86b5e1ddc088dc5b33e443a516a0c9189"
    assert profile.IMAGE_BUILD_MODULE_BLOBS[
        "zog.image_build.post_install_progress"
    ] == "5c4e03e1f496b704935caabebfa7eca63188f89e"


def test_stage_matches_host_welcome_policy_and_fixed_broker_contract(tmp_path, monkeypatch):
    result = stage(tmp_path, monkeypatch)
    assert result["consumer_uid"] == 12041
    assert result["producer_uid"] == 11051
    assert result["services_enabled"] is False
    assert result["installed_software_verified"] is False

    output = tmp_path / "overlay"
    units = output / "etc/systemd/system"
    socket = (units / profile.UNIT_SOCKET).read_text()
    service = (units / profile.UNIT_SERVICE).read_text()
    policy_path = output / "etc/zog/host-welcome-image-progress-observer.json"
    policy = json.loads(policy_path.read_text())

    assert policy == {
        "schema": "zog-host-welcome-image-progress-observer-v1",
        "enabled": True,
        "consumer_uid": 12041,
        "producer_uid": 11051,
        "socket": "/run/host-welcome/image-progress.sock",
        "image_build_source_commit": profile.IMAGE_BUILD_COMMIT,
    }
    assert policy_path.stat().st_mode & 0o777 == 0o444
    assert not policy_path.is_symlink()

    assert "ListenStream=/run/host-welcome/image-progress.sock" in socket
    assert "SocketUser=12041" in socket
    assert "SocketMode=0600" in socket
    assert "Accept=no" in socket
    assert "User=11051" in service
    assert "Group=11052" in service
    assert "--state-dir /var/lib/zog-image-build" in service
    assert "--authorized-uid 12041" in service
    assert "--source-repository zog144/image-build" in service
    assert f"--source-revision {profile.IMAGE_BUILD_COMMIT}" in service
    assert "ReadOnlyPaths=/var/lib/zog-image-build" in service
    assert "UnsetEnvironment=PYTHONPATH PYTHONHOME" in service
    for application in profile.GRAPHICAL_APPLICATIONS:
        assert f"--application {application}" in service
    assert "--boot-id" not in service
    assert "controller-progress.sock" not in service + socket
    assert "application-progress.sock" not in service + socket


def test_graphical_allowlist_matches_reviewed_consumer_set():
    assert profile.GRAPHICAL_APPLICATIONS == (
        "agreety",
        "chromium",
        "firefox",
        "firefox-esr",
        "greetd",
        "i3",
        "turbovnc",
        "weston",
        "xorg-server",
    )


def test_live_identity_resolution_uses_state_owner_not_numeric_cli(monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(profile, "welcome_account", lambda: (12041, 12042))
    monkeypatch.setattr(profile, "_protected_state_ancestry", lambda *a: None)
    monkeypatch.setattr(profile.os, "getgrouplist", lambda name, gid: [gid])

    account = SimpleNamespace(pw_uid=11051, pw_gid=11052, pw_name="image-build")
    monkeypatch.setattr(profile.pwd, "getpwuid", lambda uid: account)
    monkeypatch.setattr(profile.pwd, "getpwall", lambda: [account])

    real_lstat = Path.lstat

    def fake_lstat(path):
        text = str(path)
        if text == "/var/lib/zog-image-build":
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0
            )
        if text == "/var/lib/zog-image-build/image-build":
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o750, st_uid=11051, st_gid=11052
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    result = profile.resolve_live_identities("/var/lib/zog-image-build")
    assert result == {
        "consumer_uid": 12041,
        "consumer_gid": 12042,
        "producer_uid": 11051,
        "producer_gid": 11052,
        "image_build_state_root": "/var/lib/zog-image-build",
        "evidence": {
            "welcome_account": "host-account-database",
            "image_build_state_owner": "/var/lib/zog-image-build/image-build",
            "image_build_account": "image-build",
        },
    }


def test_live_identity_resolution_rejects_same_consumer_and_producer(monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(profile, "welcome_account", lambda: (11051, 12042))
    monkeypatch.setattr(profile, "_protected_state_ancestry", lambda *a: None)
    monkeypatch.setattr(profile.os, "getgrouplist", lambda name, gid: [gid])
    account = SimpleNamespace(pw_uid=11051, pw_gid=11052, pw_name="image-build")
    monkeypatch.setattr(profile.pwd, "getpwuid", lambda uid: account)
    monkeypatch.setattr(profile.pwd, "getpwall", lambda: [account])
    real_lstat = Path.lstat

    def fake_lstat(path):
        if str(path) == "/var/lib/zog-image-build":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        if str(path) == "/var/lib/zog-image-build/image-build":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=11051, st_gid=11052)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(StateError, match="distinct"):
        profile.resolve_live_identities("/var/lib/zog-image-build")


@pytest.mark.parametrize("path", ["/", "/run/image-build", "/tmp/image-build", "/var/tmp/image-build"])
def test_live_identity_resolution_rejects_root_or_volatile_state(monkeypatch, path):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    with pytest.raises(StateError):
        profile.resolve_live_identities(path)


def test_stage_live_uses_resolved_host_identities(tmp_path, monkeypatch):
    monkeypatch.setattr(
        profile,
        "resolve_live_identities",
        lambda root: {
            "consumer_uid": 12041,
            "consumer_gid": 12042,
            "producer_uid": 11051,
            "producer_gid": 11052,
            "image_build_state_root": root,
            "evidence": {
                "welcome_account": "host-account-database",
                "image_build_state_owner": root + "/image-build",
                "image_build_account": "image-build",
            },
        },
    )
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    result = profile.stage_live(
        output=tmp_path / "overlay",
        image_build_state_root="/var/lib/zog-image-build",
        image_build_source=IMAGE_BUILD_SOURCE,
        producer_source=ROOT,
    )
    assert result["producer_uid"] == 11051
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["identity_evidence"]["image_build_account"] == "image-build"


def test_profile_keeps_getty_and_other_observers_independent(tmp_path, monkeypatch):
    stage(tmp_path, monkeypatch)
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["visibility"] == {
        "host_welcome_socket": "/run/host-welcome/image-progress.sock",
        "host_welcome_policy": "/etc/zog/host-welcome-image-progress-observer.json",
        "station_progress_socket_inherited": False,
        "controller_progress_socket_inherited": False,
        "raw_image_build_state_inherited": False,
        "image_build_credentials_inherited": False,
        "arbitrary_host_run_binding": False,
    }
    assert manifest["boot_dependencies"] == {
        "state": False,
        "station_access": False,
        "box_control_for_getty": False,
        "network": False,
        "image_build": False,
        "graphics": False,
        "getty_requires_observer": False,
    }
    assert manifest["mutation_authority"] == {
        "submit": False,
        "resume": False,
        "cancel": False,
        "publish": False,
        "install": False,
        "service_start": False,
        "state_write": False,
        "reboot": False,
    }
    assert manifest["units"][profile.UNIT_SOCKET] == (
        "enable-after-installed-software-attestation-and-native-acceptance"
    )


def test_profile_records_selection_and_boot_recovery_requirements(tmp_path, monkeypatch):
    stage(tmp_path, monkeypatch)
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["selection_binding"] == {
        "owner": "host-install",
        "receipt_and_sequence_required": True,
        "selected_rootfs_generation_required_for_compatible_view": True,
        "absence_or_mismatch": "unknown",
    }
    assert manifest["boot_recovery_policy"] == {
        "snapshot_must_name_current_boot": True,
        "retained_terminal_command_may_name_older_controller_boot": True,
        "selection_and_publication_may_survive_reboot": True,
        "observer_may_not_resume_or_retry_work": True,
    }


@pytest.mark.parametrize("values", [
    {"consumer_uid": 0},
    {"producer_uid": 0},
    {"producer_gid": 0},
    {"consumer_uid": 11051},
])
def test_internal_stage_rejects_root_or_same_identity(tmp_path, monkeypatch, values):
    base = dict(
        output=tmp_path / "overlay",
        image_build_state_root="/var/lib/zog-image-build",
        consumer_uid=12041,
        producer_uid=11051,
        producer_gid=11052,
        image_build_source=IMAGE_BUILD_SOURCE,
        producer_source=ROOT,
    )
    base.update(values)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    with pytest.raises(StateError):
        profile.stage(**base)


def test_changed_reviewed_source_is_rejected(tmp_path):
    source = tmp_path / "image-build"
    shutil.copytree(IMAGE_BUILD_SOURCE / "src", source / "src")
    for relative in profile.IMAGE_BUILD_SOURCE_METADATA_BLOBS:
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(IMAGE_BUILD_SOURCE / relative, target)
    broker = source / "src/zog/image_build/post_install_progress_broker.py"
    broker.write_bytes(broker.read_bytes() + b"\n# changed\n")
    with pytest.raises(StateError, match="differs from reviewed revision"):
        profile.verify_reviewed_source(source)


class FakeDistribution:
    def __init__(self, root, version, files, record):
        self.root = Path(root)
        self.version = version
        self.files = files
        self.metadata = {"Name": "zog"}
        self._record = record

    def locate_file(self, value):
        return self.root / str(value)

    def read_text(self, name):
        assert name == "RECORD"
        return self._record


def _source_for_module(module):
    if module == "zog.image_build":
        return IMAGE_BUILD_SOURCE / "src/zog/image_build/__init__.py"
    relative = module.removeprefix("zog.image_build.").replace(".", "/") + ".py"
    return IMAGE_BUILD_SOURCE / "src/zog/image_build" / relative


def fake_installed_aggregate(tmp_path):
    root = tmp_path / "site-packages"
    modules = (
        "zog.image_build",
        "zog.image_build.errors",
        "zog.image_build.post_install_progress",
        "zog.image_build.post_install_progress_broker",
    )
    mapping = {}
    rows = []
    files = []
    for module in modules:
        if module == "zog.image_build":
            relative = Path("zog/image_build/__init__.py")
        else:
            relative = Path(*module.split(".")).with_suffix(".py")
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = _source_for_module(module).read_bytes()
        target.write_bytes(data)
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()
        ).rstrip(b"=").decode()
        rows.append(f"{relative.as_posix()},sha256={digest},{len(data)}")
        files.append(relative)
        mapping[module] = SimpleNamespace(__file__=str(target))
    record_relative = Path("zog-0.1.0.dist-info/RECORD")
    record_path = root / record_relative
    record_path.parent.mkdir(parents=True, exist_ok=True)
    rows.append(f"{record_relative.as_posix()},,")
    record = "\n".join(rows) + "\n"
    record_path.write_text(record)
    files.append(record_relative)
    return root, mapping, FakeDistribution(root, "0.1.0", files, record)


def test_installed_attestation_checks_loaded_bytes_and_wheel_record(tmp_path, monkeypatch):
    root, mapping, distribution = fake_installed_aggregate(tmp_path)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda *a, **k: None)
    monkeypatch.setattr(
        profile.importlib.metadata, "distribution", lambda name: distribution
    )
    monkeypatch.setattr(profile, "_loaded_image_build_modules", lambda: mapping)

    result = profile.verify_installed(python_executable="/usr/bin/python3")
    assert result["status"] == "image-build-observer-installed-software-verified"
    assert result["image_build_source_commit"] == profile.IMAGE_BUILD_COMMIT
    assert result["distribution"]["name"] == "zog"
    assert result["distribution"]["version"] == "0.1.0"
    assert result["distribution"]["record_sha256"]
    assert set(result["modules"]) == set(mapping)
    for module, value in result["modules"].items():
        assert value["git_blob"] == profile.IMAGE_BUILD_MODULE_BLOBS[module]
        assert len(value["sha256"]) == 64
        assert value["origin"].startswith(str(root))
    assert result["mutation_authorized"] is False
    assert result["production_activation_authorized"] is False


def test_installed_attestation_rejects_python_path_override(monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setenv("PYTHONPATH", "/tmp/injected")
    with pytest.raises(StateError, match="import paths"):
        profile.verify_installed()


def test_installed_attestation_rejects_modified_loaded_module(tmp_path, monkeypatch):
    _root, mapping, distribution = fake_installed_aggregate(tmp_path)
    broken = Path(mapping["zog.image_build.post_install_progress_broker"].__file__)
    broken.write_bytes(broken.read_bytes() + b"\n# modified\n")
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda *a, **k: None)
    monkeypatch.setattr(
        profile.importlib.metadata, "distribution", lambda name: distribution
    )
    monkeypatch.setattr(profile, "_loaded_image_build_modules", lambda: mapping)
    with pytest.raises(StateError, match="differ"):
        profile.verify_installed(python_executable="/usr/bin/python3")
