import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace

import pytest

from zog.host_install import certify_manage_profile as profile
from zog.host_install.state_contract import StateError


ROOT = Path(__file__).resolve().parents[1]
IMAGE_BUILD_SOURCE = Path(os.environ.get("IMAGE_BUILD_SOURCE", "companions/image-build"))
CERTIFY_MANAGE_SOURCE = Path(os.environ.get("CERTIFY_MANAGE_SOURCE", "companions/certify-manage"))
BOX_CONTROL_SOURCE = Path(os.environ.get("CERTIFICATE_BOX_CONTROL_SOURCE", "companions/box-control-certificate"))
ROOT_CONTROL_SOURCE = Path(os.environ.get("ROOT_CONTROL_SOURCE", "companions/root-control"))


def software_result():
    binding = {
        "schema": 1,
        "contract": "application-software-consumer-v1",
        "mount_contract": "application-software-mount-v1",
        "view": "sha256:" + "2" * 64,
        "application": "certify-manage",
        "profile": "application",
        "root": "/protected/views/" + "2" * 64 + "/root",
        "manifest": "/protected/views/" + "2" * 64 + "/manifest.json",
        "mount_point": "/applications/certify-manage",
        "objects": [{
            "artifact": "sha256:" + "1" * 64,
            "root": "/protected/artifacts/" + "1" * 64 + "/root",
            "mount_point": "/applications/.store/" + "1" * 64,
            "manifest": "/protected/artifacts/" + "1" * 64 + "/manifest.json",
            "compatibility": {"schema": 1},
        }],
        "rootfs_compatibility": {"schema": 1},
        "visibility": {
            "executables": ["bin"],
            "libraries": ["lib", "lib64"],
            "resources": ["share"],
            "helpers": ["libexec"],
        },
        "reclamation_protection": {
            "view": "sha256:" + "2" * 64,
            "artifacts": ["sha256:" + "1" * 64],
        },
    }
    raw = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    binding["binding_digest"] = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    return {
        "contract": "image-build-certify-manage-software-result-v1",
        "profile": "cloudflare-dns-01",
        "runtime_lock_digest": "sha256:" + "3" * 64,
        "artifact": "sha256:" + "1" * 64,
        "view": "sha256:" + "2" * 64,
        "binding": binding,
        "commands": {
            "python": "/applications/certify-manage/bin/python3",
            "certbot": "/applications/certify-manage/bin/certbot",
        },
    }


def host_bindings(tmp_path):
    path = tmp_path / "host-bindings.json"
    path.write_text(json.dumps({
        "schema": 1,
        "bindings": [{
            "project": "/home/controller/project",
            "application": "archive-mirror",
            "program": "server",
            "capability": "mirror-live",
            "source": "/run/zog-host-export/mirror-live",
        }],
    }))
    return path


def fake_identities():
    return {
        "controller_uid": 11021,
        "controller_gid": 11022,
        "controller_account": "controller",
        "consumer_uid": 12031,
        "consumer_gid": 12032,
        "consumer_account": "cert-renewal",
        "controller_project": "/home/controller/project",
        "root_control_socket": "/run/zog/root-control.sock",
        "evidence": {
            "controller_project_owner": "/home/controller/project",
            "root_control_socket_owner": "/run/zog/root-control.sock",
            "lifecycle_consumer_account": "cert-renewal",
        },
    }


def test_reviewed_source_pins_are_exact():
    observed = profile.verify_reviewed_sources(
        IMAGE_BUILD_SOURCE, CERTIFY_MANAGE_SOURCE
    )
    assert observed["image-build certify-manage software producer"]["git_blob"] == (
        "ed69143e42d13db8e0165158af61c9d592394e7b"
    )
    assert observed["certify-manage controller declaration"]["git_blob"] == (
        "23b180f1f731dae67a06fcd1bdb994304c67390f"
    )


def test_software_result_binds_exact_immutable_view():
    result = profile.validate_software_result(software_result())
    assert result["view"] == "sha256:" + "2" * 64
    assert result["binding"]["mount_point"] == "/applications/certify-manage"
    changed = software_result()
    changed["commands"]["certbot"] = "/usr/bin/certbot"
    with pytest.raises(StateError, match="command paths"):
        profile.validate_software_result(changed)


def test_host_bindings_add_five_exact_policy_grants_and_preserve_others(tmp_path):
    raw = host_bindings(tmp_path).read_bytes()
    merged = profile._binding_policy(raw, "/home/controller/project")
    existing = [r for r in merged["bindings"] if r["application"] == "archive-mirror"]
    assert len(existing) == 1
    cert = [r for r in merged["bindings"] if r["application"] == "certify-manage"]
    assert [r["program"] for r in cert] == ["inspect", "issue", "prepare", "renew", "stage"]
    assert all(r["capability"] == "certify-policy" for r in cert)
    assert all(r["source"] == "/etc/zog/certify-policy" for r in cert)


def test_rendered_application_uses_immutable_view_and_selected_programs(tmp_path):
    view = "sha256:" + "2" * 64
    path = tmp_path / "application.py"
    path.write_bytes(profile.render_application(view))
    from zog.box_control.specification import parse_application
    spec = parse_application(path)
    assert spec.name == "certify-manage"
    assert spec.software_view == view
    assert spec.execution_identity == "application"
    assert spec.persistent is True
    assert spec.multiple_instances is False
    assert spec.start_policy.value == "externally-controlled"
    assert spec.writable_mounts == ("certificate-data",)
    assert spec.preparation_revision == "certify-manage-state-v1"
    assert [p.name for p in spec.preparation] == ["prepare"]
    assert [p.name for p in spec.programs] == ["issue", "renew", "stage", "inspect"]
    for program in spec.preparation + spec.programs:
        assert program.command[0] == "/applications/certify-manage/bin/python3"
        assert "/var/lib/zog-certify-manage" in program.command
        assert "/run/zog-host/certify-policy/policy.json" in program.command


def test_stage_writes_nonactivating_install_profile(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "resolve_live_controller", lambda *a: fake_identities())
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    result_file = tmp_path / "software.json"
    result_file.write_text(json.dumps(software_result()))
    output = tmp_path / "overlay"
    result = profile.stage_live(
        output=output,
        controller_project="/home/controller/project",
        root_control_socket="/run/zog/root-control.sock",
        lifecycle_consumer_account="cert-renewal",
        generation="4" * 64,
        software_result=result_file,
        host_bindings_policy=host_bindings(tmp_path),
        image_build_source=IMAGE_BUILD_SOURCE,
        certify_manage_source=CERTIFY_MANAGE_SOURCE,
    )
    assert result["status"] == "certify-manage-native-install-staged"
    assert result["services_enabled"] is False
    assert result["application_prepared"] is False
    assert result["production_activation_authorized"] is False

    install = json.loads(
        (output / "etc/zog/certify-manage/install.json").read_text()
    )
    assert install["schema"] == "zog-certify-manage-native-install-v1"
    assert install["controller_uid"] == 11021
    assert install["lifecycle_consumer_uid"] == 12031
    assert install["software_view"] == "sha256:" + "2" * 64
    assert install["policy_installed"] is False
    assert install["application_prepared"] is False

    assert not (output / "etc/zog/certify-policy").exists()
    assert not (output / "var/lib/zog-certify-manage").exists()

    socket = (output / "etc/systemd/system/zog-certify-lifecycle.socket").read_text()
    service = (output / "etc/systemd/system/zog-certify-lifecycle.service").read_text()
    assert "ListenStream=/run/zog/certify-lifecycle.sock" in socket
    assert "SocketUser=12031" in socket
    assert "SocketMode=0600" in socket
    assert "User=11021" in service and "Group=11022" in service
    assert "--authorized-uid 12031" in service
    assert "--generation " + "4" * 64 in service
    assert "--software-view sha256:" + "2" * 64 in service
    assert "--root-control-socket /run/zog/root-control.sock" in service
    assert "PYTHONPATH=" in service

    app = output / "controller/application/certify-manage/application.py"
    assert app.is_file()
    merged = json.loads((output / "etc/zog/host-bindings.json").read_text())
    assert len([r for r in merged["bindings"] if r["application"] == "certify-manage"]) == 5


def test_stage_rejects_conflicting_existing_policy_binding(tmp_path, monkeypatch):
    monkeypatch.setattr(profile, "resolve_live_controller", lambda *a: fake_identities())
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    policy = tmp_path / "bindings.json"
    policy.write_text(json.dumps({
        "schema": 1,
        "bindings": [{
            "project": "/home/controller/project",
            "application": "certify-manage",
            "program": "renew",
            "capability": "certify-policy",
            "source": "/etc/zog/wrong",
        }],
    }))
    software = tmp_path / "software.json"
    software.write_text(json.dumps(software_result()))
    with pytest.raises(StateError, match="disagrees"):
        profile.stage_live(
            output=tmp_path / "overlay",
            controller_project="/home/controller/project",
            root_control_socket="/run/zog/root-control.sock",
            lifecycle_consumer_account="cert-renewal",
            generation="4" * 64,
            software_result=software,
            host_bindings_policy=policy,
            image_build_source=IMAGE_BUILD_SOURCE,
            certify_manage_source=CERTIFY_MANAGE_SOURCE,
        )


def test_resolve_live_controller_uses_project_socket_and_consumer_account(monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(profile, "_protected_socket_parent", lambda path: None)
    controller = SimpleNamespace(
        pw_uid=11021, pw_gid=11022, pw_name="controller"
    )
    consumer = SimpleNamespace(
        pw_uid=12031, pw_gid=12032, pw_name="cert-renewal"
    )
    monkeypatch.setattr(profile.pwd, "getpwuid", lambda uid: controller)
    monkeypatch.setattr(
        profile.pwd, "getpwnam",
        lambda name: consumer if name == "cert-renewal" else controller
    )
    monkeypatch.setattr(profile.pwd, "getpwall", lambda: [controller, consumer])
    real = Path.lstat
    def lstat(path):
        if str(path) == "/home/controller/project":
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_uid=11021, st_gid=11022
            )
        if str(path) == "/run/zog/root-control.sock":
            return SimpleNamespace(
                st_mode=stat.S_IFSOCK | 0o600, st_uid=11021, st_gid=11022
            )
        return real(path)
    monkeypatch.setattr(Path, "lstat", lstat)
    result = profile.resolve_live_controller(
        "/home/controller/project", "/run/zog/root-control.sock", "cert-renewal"
    )
    assert result["controller_uid"] == 11021
    assert result["consumer_uid"] == 12031


def test_attest_prepared_compares_controller_root_control_and_real_storage(
    tmp_path, monkeypatch
):
    project_path = tmp_path / "project"
    storage = project_path / "state/mounts/persistent" / ("a" * 32) / "certificate-data"
    storage.mkdir(parents=True)
    storage.chmod(0o700)
    grant = {
        "schema": "zog-execution-identity-v1",
        "grant_id": "b" * 32,
        "version": 1,
        "project": str(project_path),
        "application": "certify-manage",
        "uid": 29001,
        "gid": 29002,
    }
    state = {
        "state": "ready",
        "revision": "certify-manage-state-v1",
        "storage_id": "a" * 32,
        "definition": {
            "name": "certify-manage",
            "software_view": "sha256:" + "2" * 64,
            "execution_binding": grant,
        },
    }
    import zog.box_control.api as api
    import zog.box_control.project as project_mod
    import zog.box_control.runtime.root_control as rc
    class FakeProject:
        def __init__(self, path):
            self.path = Path(path)
            self.mounts_dir = self.path / "state/mounts"
    class FakeTransport:
        def __init__(self, path): self.path = path
        def resolve_execution_identity(self, **kwargs): return grant
    class FakeControl:
        def __init__(self, project, **kwargs): self.project = project
        def application_preparation(self, name): return state
    monkeypatch.setattr(project_mod, "Project", FakeProject)
    monkeypatch.setattr(rc, "RootControlSystemdTransport", FakeTransport)
    monkeypatch.setattr(api, "BoxControl", FakeControl)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    real = Path.lstat
    def lstat(path):
        info = real(path)
        if Path(path) == storage:
            return SimpleNamespace(
                st_mode=info.st_mode, st_uid=29001, st_gid=29002
            )
        return info
    monkeypatch.setattr(Path, "lstat", lstat)
    result = profile.attest_prepared(
        controller_project=str(project_path),
        root_control_socket="/run/zog/root-control.sock",
        expected_software_view="sha256:" + "2" * 64,
    )
    assert result["status"] == "ready"
    assert result["issuer_uid"] == 29001
    assert result["issuer_gid"] == 29002
    assert result["grant_id"] == "b" * 32
    assert result["storage_id"] == "a" * 32
    assert result["root_control_identity_verified"] is True
    assert result["production_activation_authorized"] is False


class FakeDistribution:
    def __init__(self, root, files, record):
        self.root = Path(root)
        self.files = files
        self.version = "0.12.0"
        self.metadata = {"Name": "zog"}
        self._record = record
    def locate_file(self, value): return self.root / str(value)
    def read_text(self, name):
        assert name == "RECORD"
        return self._record


def _source_path(module):
    if module.startswith("zog.box_control."):
        rel = module.removeprefix("zog.box_control.").replace(".", "/") + ".py"
        return BOX_CONTROL_SOURCE / "box-control/src/zog/box_control" / rel
    rel = module.removeprefix("zog.root_control.").replace(".", "/") + ".py"
    return ROOT_CONTROL_SOURCE / "src/zog/root_control" / rel


def fake_controller_distribution(tmp_path):
    root = tmp_path / "site-packages"
    mapping = {}
    rows = []
    files = []
    for module in profile.INSTALLED_MODULE_BLOBS:
        relative = Path(*module.split(".")).with_suffix(".py")
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = _source_path(module).read_bytes()
        target.write_bytes(data)
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()
        ).rstrip(b"=").decode()
        rows.append(f"{relative.as_posix()},sha256={digest},{len(data)}")
        files.append(relative)
        mapping[module] = SimpleNamespace(__file__=str(target))
    record_rel = Path("zog-0.12.0.dist-info/RECORD")
    record = "\n".join(rows + [f"{record_rel.as_posix()},,"]) + "\n"
    path = root / record_rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record)
    files.append(record_rel)
    return mapping, FakeDistribution(root, files, record)


def test_installed_controller_attestation_checks_box_and_root_control(tmp_path, monkeypatch):
    mapping, distribution = fake_controller_distribution(tmp_path)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda *a: None)
    monkeypatch.setattr(profile.importlib.metadata, "distribution", lambda name: distribution)
    monkeypatch.setattr(profile.importlib, "import_module", lambda name: mapping[name])
    result = profile.attest_installed_controller(python_executable="/usr/bin/python3")
    assert result["box_control_source_commit"] == profile.BOX_CONTROL_COMMIT
    assert result["root_control_source_commit"] == profile.ROOT_CONTROL_COMMIT
    assert set(result["modules"]) == set(profile.INSTALLED_MODULE_BLOBS)
    assert result["record_sha256"]
    assert result["production_activation_authorized"] is False


def test_installed_controller_attestation_rejects_tamper(tmp_path, monkeypatch):
    mapping, distribution = fake_controller_distribution(tmp_path)
    target = Path(mapping["zog.box_control.issuer_lifecycle_client"].__file__)
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda *a: None)
    monkeypatch.setattr(profile.importlib.metadata, "distribution", lambda name: distribution)
    monkeypatch.setattr(profile.importlib, "import_module", lambda name: mapping[name])
    with pytest.raises(StateError, match="bytes differ"):
        profile.attest_installed_controller(python_executable="/usr/bin/python3")
