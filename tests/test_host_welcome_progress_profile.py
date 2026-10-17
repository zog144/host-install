import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_install import host_welcome_progress_profile as profile
from zog.host_install import application_progress_profile as station_profile
from zog.host_install.state_contract import StateError


ROOT = Path(__file__).resolve().parents[1]
BOX_CONTROL_SOURCE = Path(os.environ.get("BOX_CONTROL_SOURCE", "companions/box-control"))


def stage(tmp_path, monkeypatch, **overrides):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    values = dict(
        output=tmp_path / "overlay",
        controller_project="/home/controller/zog-project",
        consumer_uid=12041,
        controller_uid=11021,
        controller_gid=11022,
        box_control_source=BOX_CONTROL_SOURCE,
        producer_source=ROOT,
    )
    values.update(overrides)
    return profile.stage(**values)


def test_reviewed_box_control_source_is_exactly_pinned():
    observed = profile.verify_reviewed_source(BOX_CONTROL_SOURCE)
    assert observed == profile.BOX_CONTROL_MODULE_BLOBS
    assert profile.BOX_CONTROL_COMMIT == "644170fc441863307092f329bf7e23cb64eb33e2"


def test_stage_creates_dedicated_socket_and_exact_root_policy(tmp_path, monkeypatch):
    result = stage(tmp_path, monkeypatch)
    assert result["consumer_uid"] == 12041
    assert result["controller_owner_uid"] == 11021
    assert result["services_enabled"] is False
    assert result["installed_bytes_verified"] is False

    output = tmp_path / "overlay"
    units = output / "etc/systemd/system"
    socket = (units / profile.UNIT_SOCKET).read_text()
    service = (units / profile.UNIT_SERVICE).read_text()
    policy_path = output / "etc/zog/host-welcome-progress-observer.json"
    policy = json.loads(policy_path.read_text())

    assert policy == {
        "schema": "zog-host-welcome-progress-observer-v1",
        "enabled": True,
        "consumer_uid": 12041,
        "controller_owner_uid": 11021,
        "socket": "/run/host-welcome/controller-progress.sock",
        "box_control_source_commit": profile.BOX_CONTROL_COMMIT,
    }
    assert policy_path.stat().st_mode & 0o777 == 0o444
    assert not policy_path.is_symlink()
    assert (policy_path.parent.stat().st_mode & 0o022) == 0

    assert "ListenStream=/run/host-welcome/controller-progress.sock" in socket
    assert "SocketUser=12041" in socket
    assert "SocketMode=0600" in socket
    assert "User=11021" in service
    assert "Group=11022" in service
    assert "--authorized-uid 12041" in service
    assert "--project /home/controller/zog-project" in service
    assert "--root-control-socket /run/zog/root-control.sock" in service
    assert "User=root" not in service
    assert "station-access" not in socket + service
    assert "regular" not in socket + service


def test_host_welcome_observer_does_not_modify_or_reuse_station_observer(tmp_path, monkeypatch):
    stage(tmp_path, monkeypatch)
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["runtime_model"] == "host-rootfs-bootstrap-consumer"
    assert manifest["visibility"] == {
        "host_welcome_socket": "/run/host-welcome/controller-progress.sock",
        "host_welcome_policy": "/etc/zog/host-welcome-progress-observer.json",
        "station_progress_socket_inherited": False,
        "raw_state_inherited": False,
        "controller_credentials_inherited": False,
        "arbitrary_host_run_binding": False,
    }
    assert manifest["socket"] != station_profile.HOST_SOCKET
    assert station_profile.HOST_SOCKET == (
        "/run/zog-host-export/application-progress/application-progress.sock"
    )
    assert not (tmp_path / "overlay/etc/zog/host-bindings.json").exists()


def test_boot_dependencies_remain_optional_and_getty_independent(tmp_path, monkeypatch):
    stage(tmp_path, monkeypatch)
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["boot_dependencies"] == {
        "state": False,
        "station_access": False,
        "network": False,
        "image_build": False,
        "graphics": False,
        "getty_requires_observer": False,
    }
    service = (
        tmp_path / "overlay/etc/systemd/system" / profile.UNIT_SERVICE
    ).read_text()
    socket = (
        tmp_path / "overlay/etc/systemd/system" / profile.UNIT_SOCKET
    ).read_text()
    active = "\n".join(
        line for line in (service + "\n" + socket).splitlines()
        if not line.lstrip().startswith("#")
    )
    for forbidden in (
        "station-access",
        "network-online.target",
        "image-build",
        "greetd",
        "graphical.target",
        "Requires=getty",
        "Before=getty",
        "Conflicts=getty",
        "TTYPath=",
        "StandardInput=tty",
    ):
        assert forbidden not in active


def test_profile_grants_no_mutation_authority(tmp_path, monkeypatch):
    stage(tmp_path, monkeypatch)
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["mutation_authority"] == {
        "controller_build": False,
        "application_launch": False,
        "login_manager": False,
        "state_write": False,
        "reboot": False,
    }
    assert manifest["units"][profile.UNIT_SOCKET] == (
        "enable-after-installed-byte-verification"
    )


@pytest.mark.parametrize("values", [
    {"consumer_uid": 0},
    {"controller_uid": 0},
    {"controller_gid": 0},
    {"consumer_uid": 11021},
])
def test_stage_rejects_root_or_same_consumer_server_identity(
    tmp_path, monkeypatch, values
):
    base = dict(
        output=tmp_path / "overlay",
        controller_project="/home/controller/zog-project",
        consumer_uid=12041,
        controller_uid=11021,
        controller_gid=11022,
        box_control_source=BOX_CONTROL_SOURCE,
    )
    base.update(values)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    with pytest.raises(StateError):
        profile.stage(**base)


@pytest.mark.parametrize("path", [
    "/",
    "/home/controller/../other",
    "/home/controller/project name",
])
def test_stage_rejects_unsafe_controller_paths(tmp_path, monkeypatch, path):
    with pytest.raises(StateError):
        stage(tmp_path, monkeypatch, controller_project=path)


def test_changed_reviewed_source_is_rejected(tmp_path):
    source = tmp_path / "box"
    for module, relative in profile._SOURCE_FILES.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        original = BOX_CONTROL_SOURCE / relative
        target.write_bytes(original.read_bytes())
    first = source / next(iter(profile._SOURCE_FILES.values()))
    first.write_bytes(first.read_bytes() + b"\n# changed\n")
    with pytest.raises(StateError, match="differs from reviewed source"):
        profile.verify_reviewed_source(source)


def test_installed_byte_verifier_checks_actual_module_files(monkeypatch):
    mapping = {
        module: BOX_CONTROL_SOURCE / relative
        for module, relative in profile._SOURCE_FILES.items()
    }

    def find_spec(name):
        return SimpleNamespace(origin=str(mapping[name]))

    monkeypatch.setattr(profile.importlib.util, "find_spec", find_spec)
    result = profile.verify_installed()
    assert result["status"] == "box-control-observer-installed-bytes-verified"
    assert result["box_control_source_commit"] == profile.BOX_CONTROL_COMMIT
    assert result["modules"] == profile.BOX_CONTROL_MODULE_BLOBS
    assert result["mutation_authorized"] is False


def test_installed_byte_verifier_rejects_modified_or_redirected_module(
    tmp_path, monkeypatch
):
    broken = tmp_path / "client.py"
    broken.write_text("# wrong\n")
    good = BOX_CONTROL_SOURCE / profile._SOURCE_FILES[
        "zog.box_control.application_progress_broker"
    ]

    def find_spec(name):
        if name.endswith("application_progress_client"):
            return SimpleNamespace(origin=str(broken))
        return SimpleNamespace(origin=str(good))

    monkeypatch.setattr(profile.importlib.util, "find_spec", find_spec)
    with pytest.raises(StateError, match="differ"):
        profile.verify_installed()
