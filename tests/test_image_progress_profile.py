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


def test_reviewed_deployment_reference_and_runtime_inventory_are_exact():
    observed = profile.verify_reviewed_source(IMAGE_BUILD_SOURCE)
    assert profile.IMAGE_BUILD_DEPLOYMENT_COMMIT == (
        "53ad8c2166e6b73dffbc722c2e47ccf3593612ec"
    )
    assert profile.IMAGE_BUILD_COMMIT == (
        "fe625fd901a62ef3c877a8fbc159e3b4aae7f952"
    )
    assert profile.IMAGE_BUILD_REPOSITORY == "zog144/image-build"
    assert profile.HOST_WELCOME_CONSUMER_COMMIT == (
        "cf22abc98fef05231b0c6dabc9f6f7930862affc"
    )
    assert len(observed["runtime_modules"]) == 13
    assert set(observed["runtime_modules"]) == set(profile.IMAGE_BUILD_MODULE_BLOBS)
    assert profile.TRANSPORT_AUTH == (
        "image-build-post-install-progress-linux-credentials-v1"
    )
    assert profile.IMAGE_BUILD_MODULE_BLOBS[
        "zog.image_build.post_install_progress_broker"
    ] == "997f802492f5bc60724bc6cebff2c045191f2fc1"
    assert profile.IMAGE_BUILD_MODULE_BLOBS[
        "zog.image_build.post_install_progress"
    ] == "7fa485ca5d3f067999dbe16ff66986315abcf1e3"
    assert profile.IMAGE_BUILD_DEPLOYMENT_MODULE_BLOB == (
        "32a0ff998087ea3337046fef117820dca29fad8f"
    )
    assert profile.IMAGE_BUILD_SOCKET_TEMPLATE_BLOB == (
        "8e7e7bbd6af41572441f33e8db178f6588e117d6"
    )
    assert profile.IMAGE_BUILD_SERVICE_TEMPLATE_BLOB == (
        "b2faa79886f54ec54ba15a57416acbbfa8806166"
    )
    assert profile.IMAGE_BUILD_CERTIFY_MANAGE_SERVICE_TEMPLATE_BLOB == (
        "deef20a24c7ae3a6b54512e65c8c8efdffe34dde"
    )
    assert observed["deployment_reference"][
        "src/zog/image_build/post_install_progress_deployment.py"
    ]["git_blob"] == profile.IMAGE_BUILD_DEPLOYMENT_MODULE_BLOB
    assert observed["deployment_reference"][
        "examples/systemd/zog-host-welcome-image-progress.socket.in"
    ]["git_blob"] == profile.IMAGE_BUILD_SOCKET_TEMPLATE_BLOB
    assert observed["deployment_reference"][
        "examples/systemd/zog-host-welcome-image-progress.service.in"
    ]["git_blob"] == profile.IMAGE_BUILD_SERVICE_TEMPLATE_BLOB
    assert observed["deployment_reference"][
        "examples/systemd/zog-host-welcome-image-progress-certify-manage.service.in"
    ]["git_blob"] == profile.IMAGE_BUILD_CERTIFY_MANAGE_SERVICE_TEMPLATE_BLOB


def test_stage_matches_exact_producer_policy_and_unit_reference(tmp_path, monkeypatch):
    result = stage(tmp_path, monkeypatch)
    assert result["consumer_uid"] == 12041
    assert result["producer_uid"] == 11051
    assert result["services_enabled"] is False
    assert result["installed_software_verified"] is False
    assert result["production_activation_authorized"] is False

    output = tmp_path / "overlay"
    units = output / "etc/systemd/system"
    socket = (units / profile.UNIT_SOCKET).read_text()
    service = (units / profile.UNIT_SERVICE).read_text()
    policy_path = output / "etc/zog/host-welcome-image-progress-observer.json"
    policy = json.loads(policy_path.read_text())
    manifest = json.loads((output / "profile.json").read_text())

    assert policy == {
        "schema": "zog-host-welcome-image-progress-observer-v1",
        "enabled": True,
        "consumer_uid": 12041,
        "producer_uid": 11051,
        "socket": "/run/host-welcome/image-progress.sock",
        "image_build_source_commit": profile.IMAGE_BUILD_COMMIT,
    }
    assert policy_path.stat().st_mode & 0o777 == 0o444
    assert "ListenStream=/run/host-welcome/image-progress.sock" in socket
    assert "SocketUser=12041" in socket
    assert "SocketMode=0600" in socket
    assert "Accept=no" in socket

    assert "User=11051" in service
    assert "Group=11052" in service
    assert "Environment=PYTHONPATH=" in service
    assert "--state-dir /var/lib/zog-image-build" in service
    assert "--authorized-uid 12041" in service
    assert "--source-repository zog144/image-build" in service
    assert f"--source-revision {profile.IMAGE_BUILD_COMMIT}" in service
    assert "ReadOnlyPaths=/var/lib/zog-image-build" in service
    assert "RestrictAddressFamilies=AF_UNIX" in service
    assert "CapabilityBoundingSet=" in service
    assert "AmbientCapabilities=" in service
    assert "MemoryDenyWriteExecute=yes" in service
    assert "root-control.sock" not in service
    assert "controller-progress.sock" not in service
    assert "application-progress.sock" not in service

    assert manifest["deployment_contract"] == (
        "image-build-post-install-progress-native-deployment-v3"
    )
    assert manifest["observer_profile"] == {
        "schema": 1,
        "contract": "image-build-post-install-progress-observer-profile-v1",
        "profile": profile.GRAPHICAL_OBSERVER_PROFILE,
        "purpose": "graphical-first-wave",
        "applications": list(profile.GRAPHICAL_APPLICATIONS),
        "service_template": profile.UNIT_SERVICE + ".in",
    }
    assert manifest["application_allowlist"] == list(profile.GRAPHICAL_APPLICATIONS)
    assert "--application certify-manage" not in service
    assert manifest["transport_auth"] == (
        "image-build-post-install-progress-linux-credentials-v1"
    )
    assert manifest["image_build_deployment_reference_commit"] == (
        profile.IMAGE_BUILD_DEPLOYMENT_COMMIT
    )
    assert manifest["host_welcome_consumer_commit"] == (
        "cf22abc98fef05231b0c6dabc9f6f7930862affc"
    )
    assert manifest["host_welcome_consumer_commit"] == (
        profile.HOST_WELCOME_CONSUMER_COMMIT
    )


def test_packaged_templates_are_byte_identical_to_producer_reference():
    packaged = ROOT / "src/zog/host_install/systemd"
    reference = IMAGE_BUILD_SOURCE / "examples/systemd"
    for name, expected in (
        (profile.UNIT_SOCKET + ".in", profile.IMAGE_BUILD_SOCKET_TEMPLATE_BLOB),
        (profile.UNIT_SERVICE + ".in", profile.IMAGE_BUILD_SERVICE_TEMPLATE_BLOB),
        (
            profile.CERTIFY_MANAGE_SERVICE_TEMPLATE,
            profile.IMAGE_BUILD_CERTIFY_MANAGE_SERVICE_TEMPLATE_BLOB,
        ),
    ):
        local = (packaged / name).read_bytes()
        upstream = (reference / name).read_bytes()
        assert local == upstream
        assert profile._git_blob_sha(local) == expected


def test_first_wave_allowlist_is_exact_and_excludes_later_graphics():
    assert profile.GRAPHICAL_APPLICATIONS == (
        "agreety",
        "firefox-esr",
        "greetd",
        "i3",
        "xorg-server",
    )
    assert profile.CERTIFY_MANAGE_APPLICATIONS == ("certify-manage",)
    assert set(profile.GRAPHICAL_APPLICATIONS).isdisjoint(
        profile.CERTIFY_MANAGE_APPLICATIONS
    )
    forbidden = {"chromium", "turbovnc", "weston", "firefox", "certify-manage"}
    assert forbidden.isdisjoint(profile.GRAPHICAL_APPLICATIONS)


def test_certify_manage_gate_c_profile_is_exact_and_disjoint(tmp_path, monkeypatch):
    result = stage(
        tmp_path,
        monkeypatch,
        observer_profile=profile.CERTIFY_MANAGE_OBSERVER_PROFILE,
    )
    assert result["observer_profile"] == profile.CERTIFY_MANAGE_OBSERVER_PROFILE
    assert result["application_allowlist"] == ["certify-manage"]

    output = tmp_path / "overlay"
    manifest = json.loads((output / "profile.json").read_text())
    service = (output / "etc/systemd/system" / profile.UNIT_SERVICE).read_text()
    assert manifest["observer_profile"] == {
        "schema": 1,
        "contract": profile.OBSERVER_PROFILE_CONTRACT,
        "profile": profile.CERTIFY_MANAGE_OBSERVER_PROFILE,
        "purpose": "gate-c-non-graphical-certify-manage",
        "applications": ["certify-manage"],
        "service_template": profile.CERTIFY_MANAGE_SERVICE_TEMPLATE,
    }
    assert manifest["application_allowlist"] == ["certify-manage"]
    assert "--application certify-manage" in service
    for application in profile.GRAPHICAL_APPLICATIONS:
        assert f"--application {application}" not in service
    assert "ReadOnlyPaths=/var/lib/zog-image-build" in service
    assert "RestrictAddressFamilies=AF_UNIX" in service
    assert "CapabilityBoundingSet=" in service
    assert manifest["production_activation_authorized"] is False


def test_observer_profile_selection_fails_closed(tmp_path, monkeypatch):
    with pytest.raises(StateError, match="unsupported"):
        stage(tmp_path, monkeypatch, observer_profile="certify-manage-plus-firefox")

    stage(tmp_path, monkeypatch)
    with pytest.raises(StateError, match="profile.json|record-conflict"):
        stage(
            tmp_path,
            monkeypatch,
            observer_profile=profile.CERTIFY_MANAGE_OBSERVER_PROFILE,
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
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        if text == "/var/lib/zog-image-build/image-build":
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o750, st_uid=11051, st_gid=11052
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    result = profile.resolve_live_identities("/var/lib/zog-image-build")
    assert result["consumer_uid"] == 12041
    assert result["producer_uid"] == 11051
    assert result["producer_gid"] == 11052
    assert result["evidence"]["image_build_account"] == "image-build"


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
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o750, st_uid=11051, st_gid=11052
            )
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(StateError, match="distinct"):
        profile.resolve_live_identities("/var/lib/zog-image-build")


@pytest.mark.parametrize(
    "path", ["/", "/run/image-build", "/tmp/image-build", "/var/tmp/image-build"]
)
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


def test_profile_keeps_getty_and_other_observers_independent(tmp_path, monkeypatch):
    stage(tmp_path, monkeypatch)
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["visibility"] == {
        "host_welcome_socket": "/run/host-welcome/image-progress.sock",
        "host_welcome_policy": "/etc/zog/host-welcome-image-progress-observer.json",
        "station_progress_socket_inherited": False,
        "controller_progress_socket_inherited": False,
        "root_control_socket_inherited": False,
        "raw_image_build_state_inherited": False,
        "image_build_credentials_inherited": False,
        "arbitrary_host_run_binding": False,
    }
    assert manifest["boot_dependencies"]["getty_requires_observer"] is False
    assert all(value is False for value in manifest["mutation_authority"].values())
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
    assert manifest["boot_recovery_policy"]["snapshot_must_name_current_boot"] is True
    assert (
        manifest["boot_recovery_policy"][
            "retained_terminal_command_may_name_older_controller_boot"
        ]
        is True
    )


@pytest.mark.parametrize(
    "values",
    [
        {"consumer_uid": 0},
        {"producer_uid": 0},
        {"producer_gid": 0},
        {"consumer_uid": 11051},
    ],
)
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


def test_changed_runtime_source_is_rejected(tmp_path):
    source = tmp_path / "image-build"
    for relative in set(profile._SOURCE_FILES.values()) | set(profile._DEPLOYMENT_FILES):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(IMAGE_BUILD_SOURCE / relative, target)
    broker = source / "src/zog/image_build/post_install_progress_broker.py"
    broker.write_bytes(broker.read_bytes() + b"\n# changed\n")
    with pytest.raises(StateError, match="differs from reviewed source"):
        profile.verify_reviewed_source(source)


def test_changed_deployment_template_is_rejected(tmp_path):
    source = tmp_path / "image-build"
    for relative in set(profile._SOURCE_FILES.values()) | set(profile._DEPLOYMENT_FILES):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(IMAGE_BUILD_SOURCE / relative, target)
    service = source / "examples/systemd/zog-host-welcome-image-progress.service.in"
    service.write_bytes(service.read_bytes() + b"\n# changed\n")
    with pytest.raises(StateError, match="deployment reference differs"):
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
    relative = Path(*module.split(".")).with_suffix(".py")
    return IMAGE_BUILD_SOURCE / "src" / relative


def fake_installed_aggregate(tmp_path):
    root = tmp_path / "site-packages"
    mapping = {}
    rows = []
    files = []
    for module in profile.IMAGE_BUILD_MODULE_BLOBS:
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


def test_installed_attestation_checks_all_13_modules_and_wheel_record(
    tmp_path, monkeypatch
):
    root, mapping, distribution = fake_installed_aggregate(tmp_path)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda *a, **k: None)
    monkeypatch.setattr(
        profile.importlib.metadata, "distribution", lambda name: distribution
    )
    monkeypatch.setattr(
        profile.importlib, "import_module", lambda name: mapping[name]
    )

    result = profile.verify_installed(python_executable="/usr/bin/python3")
    assert result["status"] == "image-build-observer-installed-software-verified"
    assert result["image_build_source_commit"] == profile.IMAGE_BUILD_COMMIT
    assert result["transport_auth"] == (
        "image-build-post-install-progress-linux-credentials-v1"
    )
    assert result["modules"]["zog.image_build.post_install_progress_broker"][
        "git_blob"
    ] == "997f802492f5bc60724bc6cebff2c045191f2fc1"
    assert result["modules"]["zog.image_build.post_install_progress"][
        "git_blob"
    ] == "7fa485ca5d3f067999dbe16ff66986315abcf1e3"
    assert result["image_build_deployment_reference_commit"] == (
        profile.IMAGE_BUILD_DEPLOYMENT_COMMIT
    )
    assert result["distribution"]["record_sha256"]
    assert set(result["modules"]) == set(profile.IMAGE_BUILD_MODULE_BLOBS)
    assert len(result["modules"]) == 13
    for module, value in result["modules"].items():
        assert value["git_blob"] == profile.IMAGE_BUILD_MODULE_BLOBS[module]
        assert len(value["sha256"]) == 64
        assert value["origin"].startswith(str(root))
    assert result["production_activation_authorized"] is False


def test_installed_attestation_rejects_python_path_override(monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setenv("PYTHONPATH", "/tmp/injected")
    with pytest.raises(StateError, match="PYTHONPATH"):
        profile.verify_installed()


def test_installed_attestation_rejects_modified_module(tmp_path, monkeypatch):
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
    monkeypatch.setattr(
        profile.importlib, "import_module", lambda name: mapping[name]
    )
    with pytest.raises(StateError, match="differ"):
        profile.verify_installed(python_executable="/usr/bin/python3")
