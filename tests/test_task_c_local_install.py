"""Source-only normal Task C installation; no S3, crypto approval or SSM."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_install import task_c_local_install as selected


def inputs(tmp_path):
    sources = {}
    for directory, package in (
        ("root-control", "root_control"),
        ("host-deploy", "host_deploy"),
        ("host-install", "host_install"),
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
    assert "approved_signature" not in plan
    assert "genesis" not in plan
    assert "checkpoint_reader_role" not in plan
    assert "anchor" not in plan
    assert plan["runtime_modules"] == [
        "zog.root_control.task_c_local_service",
        "zog.host_deploy.gateway.task_c_local_trust_daemon",
    ]


def test_disabled_service_templates_select_new_local_runtime_not_v3_v4():
    units = selected._units()
    assert set(units) == set(selected.UNITS)
    owner = units["zog-task-c-owner.service"].decode()
    trust = units["zog-task-c-trust.service"].decode()
    assert " -m zog.root_control.task_c_local_service" in owner
    assert " -m zog.host_deploy.gateway.task_c_local_trust_daemon" in trust
    assert "graphical_task_c_service" not in owner
    for name, data in units.items():
        text = data.decode()
        lines = [v for v in text.splitlines()
                 if v.strip() and not v.lstrip().startswith("#")]
        assert not any(v.startswith((
            "RequiresMountsFor=", "LoadCredential=",
            "WantedBy=", "LoadCredentialEncrypted=",
        )) for v in lines)
        assert "[Install]" not in lines
        assert "s3://" not in text.lower()
        if name.endswith(".socket"):
            assert "SocketUser=root" in lines
            assert "SocketGroup=root" in lines
            assert "SocketMode=0600" in lines
            assert "Accept=no" in lines
        else:
            assert "User=root" in lines
            assert "Group=root" in lines
            assert "ProtectSystem=strict" in lines
            assert "NoNewPrivileges=yes" in lines


def test_normal_stage_creates_root_backed_data_and_disabled_units(
        tmp_path, monkeypatch):
    monkeypatch.setattr(selected.os, "geteuid", lambda: 0)
    plan = selected.source_plan(**inputs(tmp_path))
    root = tmp_path / "host"
    root.mkdir()
    commands = []
    result = selected.stage(plan, root=root, runner=recorder(commands))
    assert result["status"] == "software-and-disabled-units-staged"
    assert result["ssm_authorized"] is False
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
    assert any(command[1:4] == ("-m", "pip", "check")
               for command in commands)
    assert any("-c" in command and
               "task_c_local_service" in " ".join(command)
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
    monkeypatch.setattr(selected.os, "geteuid", lambda: 0)
    plan = selected.source_plan(**inputs(tmp_path))
    changed = dict(plan, s3_required=True)
    root = tmp_path / "host"
    root.mkdir()
    with pytest.raises(selected.TaskCInstallError, match="plan changed"):
        selected.stage(changed, root=root, runner=recorder([]))
    (root / "var").symlink_to(tmp_path)
    with pytest.raises(selected.TaskCInstallError, match="symlinked"):
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
