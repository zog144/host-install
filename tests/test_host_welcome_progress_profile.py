import base64
import hashlib
import json
import os
from pathlib import Path
import stat
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
        identity_evidence={
            "welcome_account": "synthetic",
            "controller_project_owner": "synthetic",
            "root_control_socket_owner": "synthetic",
        },
    )
    values.update(overrides)
    return profile.stage(**values)


def test_reviewed_box_control_source_is_exactly_pinned():
    observed = profile.verify_reviewed_source(BOX_CONTROL_SOURCE)
    assert set(observed) == set(profile.BOX_CONTROL_MODULE_BLOBS)
    assert {
        module: value["git_blob"] for module, value in observed.items()
    } == profile.BOX_CONTROL_MODULE_BLOBS
    assert profile.BOX_CONTROL_COMMIT == "8249715708c6ef8a1fd30a3fb529b4034ffffe25"
    assert {
        "zog.box_control.application_progress_broker",
        "zog.box_control.application_progress_client",
        "zog.box_control.application_progress",
        "zog.box_control.role_broker",
        "zog.box_control.api",
        "zog.box_control.project",
        "zog.box_control.errors",
        "zog.box_control.root_protocol",
        "zog.box_control.runtime.root_control",
    } == set(observed)


def test_stage_creates_dedicated_socket_and_exact_root_policy(tmp_path, monkeypatch):
    result = stage(tmp_path, monkeypatch)
    assert result["consumer_uid"] == 12041
    assert result["controller_owner_uid"] == 11021
    assert result["services_enabled"] is False
    assert result["installed_software_verified"] is False

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
    assert "Accept=no" in socket
    assert "User=11021" in service
    assert "Group=11022" in service
    assert "--authorized-uid 12041" in service
    assert "--project /home/controller/zog-project" in service
    assert "--root-control-socket /run/zog/root-control.sock" in service
    assert "--observer-role host-welcome" in service
    assert "--controller-owner-uid 11021" in service
    assert "User=root" not in service
    assert "station-access" not in socket + service
    assert "regular" not in socket + service


def test_live_identity_resolution_cross_checks_independent_host_facts(monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(profile, "welcome_account", lambda: (12041, 12042))
    monkeypatch.setattr(profile, "_protected_root_control_ancestry", lambda: None)

    account = SimpleNamespace(pw_uid=11021, pw_gid=11022)
    monkeypatch.setattr(profile.pwd, "getpwuid", lambda uid: account)
    monkeypatch.setattr(profile.pwd, "getpwall", lambda: [account])

    real_lstat = Path.lstat

    def fake_lstat(path):
        text = str(path)
        if text == "/home/controller/zog-project":
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_uid=11021, st_gid=11022
            )
        if text == profile.ROOT_CONTROL_SOCKET:
            return SimpleNamespace(
                st_mode=stat.S_IFSOCK | 0o600, st_uid=11021, st_gid=0
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    result = profile.resolve_live_identities("/home/controller/zog-project")
    assert result == {
        "consumer_uid": 12041,
        "consumer_gid": 12042,
        "controller_uid": 11021,
        "controller_gid": 11022,
        "controller_project": "/home/controller/zog-project",
        "evidence": {
            "welcome_account": "host-account-database",
            "controller_project_owner": "/home/controller/zog-project",
            "root_control_socket_owner": "/run/zog/root-control.sock",
        },
    }


def test_live_identity_resolution_rejects_controller_uid_disagreement(monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(profile, "welcome_account", lambda: (12041, 12042))
    monkeypatch.setattr(profile, "_protected_root_control_ancestry", lambda: None)
    account = SimpleNamespace(pw_uid=11021, pw_gid=11022)
    monkeypatch.setattr(profile.pwd, "getpwuid", lambda uid: account)
    monkeypatch.setattr(profile.pwd, "getpwall", lambda: [account])
    real_lstat = Path.lstat

    def fake_lstat(path):
        if str(path) == "/home/controller/zog-project":
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_uid=11021, st_gid=11022
            )
        if str(path) == profile.ROOT_CONTROL_SOCKET:
            return SimpleNamespace(
                st_mode=stat.S_IFSOCK | 0o600, st_uid=11099, st_gid=0
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(StateError, match="root-control socket"):
        profile.resolve_live_identities("/home/controller/zog-project")


def test_stage_live_uses_resolved_ids_not_cli_numeric_assertions(tmp_path, monkeypatch):
    monkeypatch.setattr(
        profile,
        "resolve_live_identities",
        lambda project: {
            "consumer_uid": 12041,
            "consumer_gid": 12042,
            "controller_uid": 11021,
            "controller_gid": 11022,
            "controller_project": project,
            "evidence": {
                "welcome_account": "host-account-database",
                "controller_project_owner": project,
                "root_control_socket_owner": profile.ROOT_CONTROL_SOCKET,
            },
        },
    )
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    result = profile.stage_live(
        output=tmp_path / "overlay",
        controller_project="/home/controller/zog-project",
        box_control_source=BOX_CONTROL_SOURCE,
        producer_source=ROOT,
    )
    assert result["consumer_uid"] == 12041
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["identity_evidence"]["welcome_account"] == "host-account-database"
    assert manifest["controller_owner_uid"] == 11021


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
        "root_control_socket_inherited_by_consumer": False,
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
        "root_control_for_getty": False,
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
        "enable-after-installed-software-attestation-and-native-acceptance"
    )


@pytest.mark.parametrize("values", [
    {"consumer_uid": 0},
    {"controller_uid": 0},
    {"controller_gid": 0},
    {"consumer_uid": 11021},
])
def test_internal_stage_rejects_root_or_same_consumer_server_identity(
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
    for _module, relative in profile._SOURCE_FILES.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        original = BOX_CONTROL_SOURCE / relative
        target.write_bytes(original.read_bytes())
    first = source / next(iter(profile._SOURCE_FILES.values()))
    first.write_bytes(first.read_bytes() + b"\n# changed\n")
    with pytest.raises(StateError, match="differs from reviewed source"):
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


def fake_installed_aggregate(tmp_path):
    root = tmp_path / "site-packages"
    module_paths = {}
    rows = []
    files = []
    for module, source_relative in profile._SOURCE_FILES.items():
        relative = Path(*module.split(".")).with_suffix(".py")
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (BOX_CONTROL_SOURCE / source_relative).read_bytes()
        target.write_bytes(data)
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()
        ).rstrip(b"=").decode()
        rows.append(f"{relative.as_posix()},sha256={digest},{len(data)}")
        files.append(relative)
        module_paths[module] = target
    record_relative = Path("zog-0.1.0.dist-info/RECORD")
    record_path = root / record_relative
    record_path.parent.mkdir(parents=True, exist_ok=True)
    rows.append(f"{record_relative.as_posix()},,")
    record = "\n".join(rows) + "\n"
    record_path.write_text(record)
    files.append(record_relative)
    return root, module_paths, FakeDistribution(root, "0.1.0", files, record)


def test_installed_attestation_checks_loaded_bytes_and_wheel_record(
    tmp_path, monkeypatch
):
    root, mapping, distribution = fake_installed_aggregate(tmp_path)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda path, stop: None)
    monkeypatch.setattr(
        profile.importlib.metadata, "distribution", lambda name: distribution
    )
    monkeypatch.setattr(
        profile.importlib,
        "import_module",
        lambda name: SimpleNamespace(__file__=str(mapping[name])),
    )

    result = profile.verify_installed(python_executable="/usr/bin/python3")
    assert result["status"] == "box-control-observer-installed-software-verified"
    assert result["box_control_source_commit"] == profile.BOX_CONTROL_COMMIT
    assert result["distribution"]["name"] == "zog"
    assert result["distribution"]["version"] == "0.1.0"
    assert result["distribution"]["record_sha256"]
    assert result["pythonpath_present"] is False
    assert set(result["modules"]) == set(profile.BOX_CONTROL_MODULE_BLOBS)
    for module, value in result["modules"].items():
        assert value["git_blob"] == profile.BOX_CONTROL_MODULE_BLOBS[module]
        assert len(value["sha256"]) == 64
        assert value["origin"].startswith(str(root))
    assert result["mutation_authorized"] is False
    assert result["production_activation_authorized"] is False


def test_installed_attestation_rejects_nonempty_pythonpath(tmp_path, monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setenv("PYTHONPATH", "/tmp/injected")
    with pytest.raises(StateError, match="PYTHONPATH"):
        profile.verify_installed()


def test_installed_attestation_rejects_modified_module_even_with_import_origin(
    tmp_path, monkeypatch
):
    _root, mapping, distribution = fake_installed_aggregate(tmp_path)
    broken = mapping["zog.box_control.application_progress_client"]
    broken.write_bytes(broken.read_bytes() + b"\n# modified\n")
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda path, stop: None)
    monkeypatch.setattr(
        profile.importlib.metadata, "distribution", lambda name: distribution
    )
    monkeypatch.setattr(
        profile.importlib,
        "import_module",
        lambda name: SimpleNamespace(__file__=str(mapping[name])),
    )
    with pytest.raises(StateError, match="differ"):
        profile.verify_installed(python_executable="/usr/bin/python3")
