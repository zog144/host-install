"""Recoverable issuer guard replacement tests, never touches a native Host."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from zog.host_install import issuer_guard_deploy as deploy


@pytest.fixture
def installed(tmp_path):
    source = Path(deploy.__file__).parent
    original = (source / deploy.ORIGINAL_FILE).read_bytes()
    assert len(original) == 3853
    assert hashlib.sha256(original).hexdigest() == deploy.ORIGINAL_SHA256
    base = deploy._host(tmp_path, deploy.BASE)
    base.mkdir(parents=True)
    deploy._host(tmp_path, deploy.ROLLBACK).parent.mkdir(parents=True)
    guard = base / "guard.py"
    guard.write_bytes(original)
    guard.chmod(0o444)
    unit = deploy._host(tmp_path, deploy.UNIT)
    unit.parent.mkdir(parents=True)
    original_unit = b"[Service]\nExecStart=/original\n"
    unit.write_bytes(original_unit)
    unit.chmod(0o644)
    baseline = {"hashes": {str(deploy.UNIT):
                            hashlib.sha256(original_unit).hexdigest()}}
    (base / "baseline.json").write_text(json.dumps(baseline))
    (base / "baseline.json").chmod(0o600)
    return tmp_path, guard, unit, original, original_unit, base


def test_staged_create_only_and_recoverable_selected_helper(installed):
    root, guard, unit, original, old_unit, base = installed
    baseline = (base / "baseline.json").read_bytes()
    record = deploy.stage(root=root)
    assert guard.read_bytes() == original
    assert (base / deploy.POLICY_FILE).exists() is False
    assert record["state"] == "staged"
    assert record["original_sha256"] == deploy.ORIGINAL_SHA256
    copy = deploy._host(root, deploy.ROLLBACK / "original-guard.py")
    assert copy.read_bytes() == original
    with pytest.raises(deploy.HelperDeploymentHold, match="already exists"):
        deploy.stage(root=root)
    active = deploy.activate(root=root)
    assert active["state"] == "active"
    assert hashlib.sha256(guard.read_bytes()).hexdigest() == record["replacement_sha256"]
    assert hashlib.sha256((base / deploy.POLICY_FILE).read_bytes()).hexdigest() == record["policy_sha256"]
    assert (base / "baseline.json").read_bytes() == baseline
    assert copy.read_bytes() == original
    restored = deploy.restore(root=root)
    assert restored["state"] == "restored"
    assert guard.read_bytes() == original
    assert not (base / deploy.POLICY_FILE).exists()
    assert (base / "baseline.json").read_bytes() == baseline
    assert copy.read_bytes() == original


def test_selected_unit_prevents_original_helper_rollback(installed):
    root, guard, unit, original, old_unit, base = installed
    deploy.stage(root=root)
    deploy.activate(root=root)
    unit.write_bytes(b"[Service]\nExecStart=/replacement\n")
    with pytest.raises(deploy.HelperDeploymentHold,
                       match="original issuer unit has not been restored"):
        deploy.restore(root=root)
    assert guard.read_bytes() != original
    unit.write_bytes(old_unit)
    assert deploy.restore(root=root)["state"] == "restored"


def test_tampered_original_guard_blocks_staging(installed):
    root, guard, unit, original, old_unit, base = installed
    guard.chmod(0o600)
    guard.write_bytes(b"bad")
    guard.chmod(0o444)
    with pytest.raises(deploy.HelperDeploymentHold, match="original guard"):
        deploy.stage(root=root)
    assert not deploy._host(root, deploy.ROLLBACK).exists()


def test_issuer_original_baseline_must_remain_byte_identical(installed):
    root, guard, unit, original, old_unit, base = installed
    deploy.stage(root=root)
    before = (base / "baseline.json").read_bytes()
    (base / "baseline.json").write_bytes(before + b" ")
    with pytest.raises(deploy.HelperDeploymentHold, match="baseline"):
        deploy.activate(root=root)
    assert guard.read_bytes() == original


def test_unknown_policy_or_guard_blocks_activation(installed):
    root, guard, unit, original, old_unit, base = installed
    deploy.stage(root=root)
    p = base / deploy.POLICY_FILE
    p.write_bytes(b"foreign")
    p.chmod(0o444)
    with pytest.raises(deploy.HelperDeploymentHold, match="policy differs"):
        deploy.activate(root=root)
    assert guard.read_bytes() == original
    p.unlink()
    guard.chmod(0o600)
    guard.write_bytes(b"unknown")
    guard.chmod(0o444)
    with pytest.raises(deploy.HelperDeploymentHold, match="unknown installed"):
        deploy.activate(root=root)


def test_restoration_refuses_incomplete_or_modified_backup(installed):
    root, guard, unit, original, old_unit, base = installed
    deploy.stage(root=root)
    deploy.activate(root=root)
    copy = deploy._host(root, deploy.ROLLBACK / "original-guard.py")
    copy.chmod(0o600)
    copy.write_bytes(b"foreign")
    copy.chmod(0o400)
    with pytest.raises(deploy.HelperDeploymentHold):
        deploy.restore(root=root)
    assert guard.read_bytes() != original


def test_missing_live_guard_and_readonly_staging_hold(installed):
    root, guard, unit, original, old_unit, base = installed
    guard.unlink()
    with pytest.raises((FileNotFoundError, deploy.HelperDeploymentHold)):
        deploy.stage(root=root)
    guard.write_bytes(original)
    guard.chmod(0o644)
    with pytest.raises(deploy.HelperDeploymentHold, match="mode"):
        deploy.stage(root=root)


def test_original_helper_restore_denies_unfinished_selected_transaction(installed):
    root, guard, unit, original, old_unit, base = installed
    deploy.stage(root=root)
    deploy.activate(root=root)
    selected = deploy._host(root, Path("/opt/zog/compiler-runtime/rollback") / ("a"*32))
    selected.mkdir(parents=True)
    tx = selected / "selection-transaction.json"
    tx.write_text(json.dumps({
        "service": deploy.SERVICE, "release_id": "a"*32,
        "state": "selected"}))
    tx.chmod(0o600)
    with pytest.raises(deploy.HelperDeploymentHold, match="incomplete compiler selection"):
        deploy.restore(root=root)
    assert guard.read_bytes() != original
    tx.write_text(json.dumps({
        "service": deploy.SERVICE, "release_id": "a"*32,
        "state": "restored"}))
    assert deploy.restore(root=root)["state"] == "restored"



# Native systemd 252 status readback is mocked; no real Host or service is used.
def _systemd_show(*, identity=deploy.SERVICE, load="loaded", active="inactive",
                  sub="dead", job="0"):
    return (f"Id={identity}\nLoadState={load}\nActiveState={active}\n"
            f"SubState={sub}\nJob={job}\n")


def _native_systemd_fixture(monkeypatch, stdout, *, code=0):
    from subprocess import CompletedProcess
    monkeypatch.setattr(deploy.os, "geteuid", lambda: 0)
    monkeypatch.setattr(deploy.os, "getegid", lambda: 0)
    calls = []
    def runner(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return CompletedProcess(argv, code, stdout=stdout, stderr="")
    return runner, calls


@pytest.mark.parametrize("no_job", ["0", ""])
def test_native_helper_install_admits_only_loaded_inactive_dead_with_no_job(
        monkeypatch, no_job):
    runner, calls = _native_systemd_fixture(
        monkeypatch, _systemd_show(job=no_job))
    deploy._inactive(Path("/"), runner)
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv[0] == "/usr/bin/systemctl"
    assert "show" in argv and deploy.SERVICE in argv
    assert "--property=Id,LoadState,ActiveState,SubState,Job" in argv
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True


@pytest.mark.parametrize(("description", "properties"), [
    ("activating", {"active": "activating", "sub": "start"}),
    ("deactivating", {"active": "deactivating", "sub": "stop"}),
    ("reloading", {"active": "reloading", "sub": "reload"}),
    ("active", {"active": "active", "sub": "running"}),
    ("failed", {"active": "failed", "sub": "failed"}),
    ("inactive but stop unfinished", {"active": "inactive", "sub": "stop"}),
    ("inactive but restarting", {"active": "inactive", "sub": "auto-restart"}),
    ("missing unit", {"load": "not-found"}),
    ("masked unit", {"load": "masked"}),
    ("bad unit", {"load": "bad-setting"}),
    ("different service", {"identity": "other.service"}),
    ("queued start job", {"job": "42"}),
    ("queued stop job", {"job": "181"}),
])
def test_native_inactive_guard_rejects_transition_missing_unit_or_queued_job(
        monkeypatch, description, properties):
    runner, calls = _native_systemd_fixture(
        monkeypatch, _systemd_show(**properties))
    with pytest.raises(deploy.HelperDeploymentHold):
        deploy._inactive(Path("/"), runner)
    assert len(calls) == 1, description


@pytest.mark.parametrize("output", [
    "", "Id=zog-certbot-seed-root.service\n",
    _systemd_show().replace("Job=0\n", ""),
    _systemd_show() + "Job=0\n",
    _systemd_show().replace("LoadState=loaded", "LoadState=loaded\nLoadState=loaded"),
    _systemd_show().replace("Job=0", "Job=garbled"),
    "unrecognized property\n" + _systemd_show(),
])
def test_inactive_guard_rejects_missing_duplicate_or_malformed_systemd_properties(
        monkeypatch, output):
    runner, _ = _native_systemd_fixture(monkeypatch, output)
    with pytest.raises(deploy.HelperDeploymentHold):
        deploy._inactive(Path("/"), runner)


def test_inactive_guard_rejects_systemd_failure_even_with_inactive_text(monkeypatch):
    runner, _ = _native_systemd_fixture(
        monkeypatch, _systemd_show(), code=1)
    with pytest.raises(deploy.HelperDeploymentHold, match="status unavailable"):
        deploy._inactive(Path("/"), runner)


@pytest.mark.parametrize("action", [deploy.stage, deploy.activate, deploy.restore],
                         ids=["stage", "activate", "restore"])
@pytest.mark.parametrize("transition", [
    _systemd_show(active="activating", sub="start"),
    _systemd_show(active="deactivating", sub="stop"),
    _systemd_show(load="not-found"),
    _systemd_show(job="77"),
])
def test_native_helper_operations_stop_before_touching_files_when_unit_not_stopped(
        monkeypatch, action, transition):
    runner, calls = _native_systemd_fixture(monkeypatch, transition)
    def unexpected(*args, **kwargs):
        raise AssertionError("should not access issuer files while service unsafe")
    monkeypatch.setattr(deploy, "_source_tuple", unexpected)
    monkeypatch.setattr(deploy, "_validate_staging", unexpected)
    monkeypatch.setattr(deploy, "_read", unexpected)
    with pytest.raises(deploy.HelperDeploymentHold):
        action(root=Path("/"), runner=runner)
    assert len(calls) == 1
