"""Source-only normal Task C installation; no S3, crypto approval or SSM."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_install import task_c_local_install as selected


@pytest.fixture(autouse=True)
def synthetic_root_source_pin(monkeypatch):
    # Unit fixtures have no Git objects; real source pin checks are exercised
    # independently by the cross-repository CI workflow.
    monkeypatch.setattr(selected, "_reviewed_root_control", lambda path: {
        "revision": selected.ROOT_CONTROL_REVISION,
        "journal_git_blob": selected.ROOT_CONTROL_JOURNAL_GIT_BLOB,
    })
    monkeypatch.setattr(selected, "_reviewed_dependency",
                        lambda path, revision, component: revision)


def inputs(tmp_path):
    sources = {}
    for directory, package in (
        ("host-deploy", "host_deploy"),
        ("host-install", "host_install"),
        ("root-control", "root_control"),
        ("box-control", "box_control"),
        ("image-build", "image_build"),
    ):
        root = tmp_path / directory
        (root / "src" / "zog" / package).mkdir(parents=True)
        (root / "pyproject.toml").write_text("[project]\nname='test'\n")
        sources[directory.replace("-", "_")] = str(root)
    python = tmp_path / "python3.12"
    python.write_bytes(b"test interpreter")
    return {**sources, "python": str(python)}


def recorder(commands, *, fail_runtime=False):
    def run(args, *, check=False):
        commands.append(tuple(map(str, args)))
        if args[1:3] == ["-m", "venv"]:
            target = Path(args[3]) / "bin" / "python"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"mock venv")
        if fail_runtime and "-c" in args:
            return SimpleNamespace(returncode=1)
        return SimpleNamespace(returncode=0)
    return run


def test_source_selection_is_ordinary_local_repositories(tmp_path):
    plan = selected.source_plan(**inputs(tmp_path))
    assert plan["schema"] == selected.SCHEMA
    assert plan["s3_required"] is False
    assert plan["signed_storage_approval_required"] is False
    assert plan["separate_storage_volume_required"] is False
    assert plan["ssm_execution"] is False
    assert plan["root_control_revision"] == selected.ROOT_CONTROL_REVISION
    assert plan["root_control_journal_git_blob"] == selected.ROOT_CONTROL_JOURNAL_GIT_BLOB
    assert plan["root_control_journal"] == "/var/lib/zog-task-c/operations"
    assert plan["box_control_revision"] == selected.BOX_CONTROL_REVISION
    assert plan["image_build_revision"] == selected.IMAGE_BUILD_REVISION
    assert plan["journal_owner"] == "root:root"
    assert plan["journal_mode"] == "0700"
    assert plan["service_activation"] is False
    assert "approved_signature" not in plan
    assert "genesis" not in plan
    assert "checkpoint_reader_role" not in plan
    assert "anchor" not in plan
    assert plan["runtime_modules"] == [
        "zog.host_deploy.gateway.generic_pipeline",
        "zog.host_deploy.gateway.trusted_host_submission",
        "zog.host_deploy.gateway.graphics_operation_send_intent",
        "zog.root_control.task_c_trusted_host",
    ]


def test_disabled_gateway_template_selects_one_existing_direct_runtime():
    units = selected._units()
    assert set(units) == {"zog-task-c-gateway.service"}
    text = units["zog-task-c-gateway.service"].decode()
    lines = [v for v in text.splitlines()
             if v.strip() and not v.lstrip().startswith("#")]
    assert not any(line.startswith(("User=", "Group=")) for line in lines)
    assert "StateDirectory=host-deploy-gateway" in lines
    assert "StateDirectoryMode=0700" in lines
    assert "ReadWritePaths=/var/lib/host-deploy-gateway /var/lib/zog-task-c/operations" in lines
    assert "ExecStart=/opt/zog/task-c/venv/bin/host-deploy-gateway --state-directory /var/lib/host-deploy-gateway run" in lines
    assert "NoNewPrivileges=yes" in lines
    assert "ProtectSystem=strict" in lines
    assert "[Install]" not in lines
    assert "DynamicUser=yes" not in lines
    assert "zog-task-c/operations" in text
    assert not any(v.startswith(("RequiresMountsFor=", "LoadCredential=",
                                 "WantedBy=")) for v in lines)
    for forbidden in ("zog-task-c-trust", "zog-task-c-owner",
                      "s3://", "broker-private.key"):
        assert forbidden not in text



def test_normal_stage_creates_root_backed_data_and_disabled_units(
        tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("real root-owned Task C journal staging is tested by root CI")
    monkeypatch.setattr(selected.os, "geteuid", lambda: 0)
    plan = selected.source_plan(**inputs(tmp_path))
    root = tmp_path / "host"
    root.mkdir()
    commands = []
    result = selected.stage(plan, root=root, runner=recorder(commands))
    assert result["status"] == "software-and-disabled-units-staged"
    assert result["ssm_authorized"] is False
    assert result["journal"] == {
        "directory": "/var/lib/zog-task-c/operations", "owner_uid": 0,
        "owner_gid": 0, "mode": "0700", "root_owned": True,
        "precreated_by_installer": True,
    }
    assert result["gateway_active"] is False
    for directory in selected.DATA_DIRS:
        path = root / directory.lstrip("/")
        assert path.is_dir()
        assert path.stat().st_mode & 0o777 == 0o700
    assert not any((root / directory.lstrip("/")).is_mount()
                   for directory in selected.DATA_DIRS)
    for name, body in selected._units().items():
        file = root / "etc/systemd/system" / name
        assert file.read_bytes() == body
        assert file.stat().st_mode & 0o777 == 0o644
    assert any(command[1:3] == ("-m", "pip") and
               "install" in command for command in commands)
    assert any(command[1:4] == ("-m", "pip", "install")
               and "--no-deps" not in command
               and plan["host_deploy_source"] in command
               and plan["host_install_source"] in command
               and plan["root_control_source"] in command
               and plan["box_control_source"] in command
               and plan["image_build_source"] in command
               for command in commands)
    assert any(command[1:4] == ("-m", "pip", "check")
               for command in commands)
    assert any("-c" in command and
               "trusted_host_submission" in " ".join(command)
               and "root_control.task_c_trusted_host" in " ".join(command)
               and selected.ROOT_CONTROL_JOURNAL_GIT_BLOB in " ".join(command)
               for command in commands)
    assert not any(word in command for command in commands
                   for word in ("start", "enable", "restart", "ssm",
                                "aws", "s3", "mount", "mkfs", "groupadd"))
    assert not any("graphical" in part for part in result["units"])
    # Rerun: identical bytes are idempotent; no alternate authority created.
    result2 = selected.stage(plan, root=root, runner=recorder(commands))
    assert result == result2


def test_installer_refuses_missing_simplified_root_runtime_before_units(
        tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("real root-owned Task C journal staging is tested by root CI")
    monkeypatch.setattr(selected.os, "geteuid", lambda: 0)
    plan = selected.source_plan(**inputs(tmp_path))
    root = tmp_path / "host"
    root.mkdir()
    commands = []
    with pytest.raises(selected.TaskCInstallError, match="installation command failed"):
        selected.stage(plan, root=root, runner=recorder(
            commands, fail_runtime=True))
    assert any("-c" in command for command in commands)
    assert not (root / "etc/systemd/system").exists()


def test_installer_refuses_foreign_plan_and_symlink_ancestor(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("real root-owned Task C journal staging is tested by root CI")
    monkeypatch.setattr(selected.os, "geteuid", lambda: 0)
    plan = selected.source_plan(**inputs(tmp_path))
    changed = dict(plan, s3_required=True)
    root = tmp_path / "host"
    root.mkdir()
    with pytest.raises(selected.TaskCInstallError, match="plan changed"):
        selected.stage(changed, root=root, runner=recorder([]))
    (root / "var").symlink_to(tmp_path)
    with pytest.raises(selected.TaskCInstallError, match="symlinked|linked|unsafe"):
        selected.stage(plan, root=root, runner=recorder([]))
    assert not (root / "etc/systemd/system").exists()


def test_unprivileged_stage_cannot_modify_host(tmp_path, monkeypatch):
    plan = selected.source_plan(**inputs(tmp_path))
    monkeypatch.setattr(selected.os, "geteuid", lambda: 1000)
    root = tmp_path / "host"
    root.mkdir()
    with pytest.raises(selected.TaskCInstallError, match="requires root"):
        selected.stage(plan, root=root, runner=recorder([]))
    assert list(root.iterdir()) == []


def test_existing_foreign_unit_cannot_be_followed(tmp_path):
    root = tmp_path / "host"
    units = root / "etc/systemd/system"
    units.mkdir(parents=True)
    foreign = tmp_path / "other"
    foreign.write_text("foreign")
    dest = units / selected.UNITS[0]
    dest.symlink_to(foreign)
    with pytest.raises(selected.TaskCInstallError, match="ordinary regular file"):
        selected._publish_unit(root, selected.UNITS[0], b"replacement\n")
    assert foreign.read_text() == "foreign"


def test_package_entrypoint_and_templates_included_in_normal_install():
    import tomllib
    metadata = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert metadata["project"]["scripts"]["host-install-task-c"] == (
        "zog.host_install.task_c_local_install:main")
    assert "systemd/task-c-local/*" in (
        metadata["tool"]["setuptools"]["package-data"]["zog.host_install"])


def test_optional_local_host_inspection_reuses_canonical_reader(monkeypatch):
    from zog.host_install import state_inspect
    events = []
    class OriginalState:
        bundle = {"bootstrap":{
            "installation_id": "original-installation",
            "initialization": {"expected_host_uuid": "original-host"},
            "state": {
                "state_volume_id": "original-state",
                "storage_backend": "root-directory",
                "filesystem_uuid": "original-root-fs",
            },
        }}
        def __enter__(self):
            events.append("open")
            return self
        def recheck(self):
            events.append("recheck")
        def __exit__(self, *args):
            events.append("close")
    monkeypatch.setattr(state_inspect, "inspect_live", OriginalState)
    observed=selected.inspect_local_host_state()
    assert observed == {
        "schema": "zog-task-c-local-host-state-observation-v1",
        "status": "existing-local-installation-observed",
        "installation_id": "original-installation",
        "state_id": "original-state",
        "state_backend": "root-directory",
        "root_filesystem_uuid": "original-root-fs",
        "expected_host_uuid": "original-host",
        "ssm_authorized": False,
    }
    assert events == ["open", "recheck", "recheck", "close"]



def test_source_plan_requires_real_selected_root_control_source(tmp_path, monkeypatch):
    # A selection cannot silently omit root-control or replace its Git-reviewed
    # journal with a consumer-side copy.
    values = inputs(tmp_path)
    del values["root_control"]
    with pytest.raises(TypeError, match="root_control"):
        selected.source_plan(**values)
    values["root_control"] = values["host_install"]
    with pytest.raises(selected.TaskCInstallError, match="incorrect component repository"):
        selected.source_plan(**values)
    values["root_control"] = str(tmp_path / "root-control")
    selected_plan = selected.source_plan(**values)
    assert selected_plan["runtime_modules"][-1] == "zog.root_control.task_c_trusted_host"
    assert len({selected_plan[k] for k in (
        "host_deploy_source", "host_install_source",
        "root_control_source", "box_control_source",
        "image_build_source")}) == 5


def test_staging_requires_gateway_inactive_before_host_changes():
    commands = []

    def active(args, *, check=False):
        commands.append(tuple(args))
        return SimpleNamespace(returncode=0)

    with pytest.raises(selected.TaskCInstallError, match="Gateway is active"):
        selected._require_gateway_inactive(active)
    assert commands == [
        ("/usr/bin/systemctl", "is-active", "--quiet", "zog-task-c-gateway.service")
    ]
    for code in (3, 4):
        selected._require_gateway_inactive(
            lambda args, *, check=False: SimpleNamespace(returncode=code))
    with pytest.raises(selected.TaskCInstallError, match="cannot be established"):
        selected._require_gateway_inactive(
            lambda args, *, check=False: SimpleNamespace(returncode=1))



def test_selected_normal_controller_dependency_closure_is_explicit(tmp_path, monkeypatch):
    selected_plan = selected.source_plan(**inputs(tmp_path))
    assert selected_plan["box_control_revision"] == (
        "c886e7a90bb4ea74e771a6c5dcefaa2069539ec7")
    assert selected_plan["image_build_revision"] == (
        "77a5e3c13e1c41582b3278941fb4b1f5e2f16678")
    assert selected_plan["root_control_revision"] == (
        "b655b0a2b2ba7abb5fddbdaadae01ef6e34bcb56")
    assert selected_plan["ssm_execution"] is False
    assert selected_plan["service_activation"] is False
    changed = dict(selected_plan, box_control_revision="0" * 40)
    monkeypatch.setattr(selected.os, "geteuid", lambda: 0)
    root = tmp_path / "host"
    root.mkdir()
    with pytest.raises(selected.TaskCInstallError, match="plan changed"):
        selected.stage(changed, root=root, runner=recorder([]))
    assert list(root.iterdir()) == []
