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



def _restored_issuer_fixture(installed):
    root, guard, unit, original, old_unit, base = installed
    staged = deploy.stage(root=root)
    assert staged["state"] == "staged"
    deploy.activate(root=root)
    result = deploy.restore(root=root)
    assert result["state"] == "restored"
    record_file = deploy._host(root, deploy.ROLLBACK / "record.json")
    original_copy = deploy._host(root, deploy.ROLLBACK / "original-guard.py")
    successor_copy = deploy._host(root, deploy.ROLLBACK / "approved-successor.py")
    policy_copy = deploy._host(root, deploy.ROLLBACK / "approved-binding.py")
    return root, guard, unit, original, base, record_file, (
        original_copy, successor_copy, policy_copy,
    )


def test_restored_to_staged_revalidates_and_preserves_immutable_rollback(installed):
    root, guard, unit, original, base, record_file, copies = (
        _restored_issuer_fixture(installed))
    old_record = record_file.read_bytes()
    old_baseline = (base / "baseline.json").read_bytes()
    original_backups = [(p.read_bytes(), p.stat().st_ino) for p in copies]
    staged = deploy.stage(root=root)
    assert staged["state"] == "staged" and staged["restage_count"] == 1
    assert record_file.read_bytes() != old_record
    receipt = deploy._host(
        root, deploy.ROLLBACK / "restored-before-restage-000001.json")
    assert receipt.read_bytes() == old_record
    assert receipt.stat().st_mode & 0o777 == 0o400
    assert [(p.read_bytes(), p.stat().st_ino) for p in copies] == original_backups
    assert guard.read_bytes() == original
    assert not (base / deploy.POLICY_FILE).exists()
    assert (base / "baseline.json").read_bytes() == old_baseline
    with pytest.raises(deploy.HelperDeploymentHold, match="already exists"):
        deploy.stage(root=root)
    deploy.activate(root=root)
    assert guard.read_bytes() != original
    deploy.restore(root=root)
    second_old_record = record_file.read_bytes()
    again = deploy.stage(root=root)
    assert again["state"] == "staged" and again["restage_count"] == 2
    assert receipt.read_bytes() == old_record
    assert deploy._host(
        root, deploy.ROLLBACK /
        "restored-before-restage-000002.json").read_bytes() == second_old_record
    assert [(p.read_bytes(), p.stat().st_ino) for p in copies] == original_backups
    assert (base / "baseline.json").read_bytes() == old_baseline


@pytest.mark.parametrize("alter", [
    "live-original", "live-original-mode", "baseline",
    "backup-original", "backup-successor", "backup-policy",
    "record-replacement", "remaining-policy", "incomplete-transaction",
])
def test_restored_to_staged_rejects_drift_without_rewriting_rollback(
        installed, alter):
    root, guard, unit, original, base, record_file, copies = (
        _restored_issuer_fixture(installed))
    original_record = record_file.read_bytes()
    if alter == "live-original":
        guard.chmod(0o600)
        guard.write_bytes(b"foreign")
        guard.chmod(0o444)
    elif alter == "live-original-mode":
        guard.chmod(0o644)
    elif alter == "baseline":
        (base / "baseline.json").write_bytes(
            (base / "baseline.json").read_bytes() + b" ")
    elif alter.startswith("backup-"):
        index = {"backup-original": 0, "backup-successor": 1,
                 "backup-policy": 2}[alter]
        copies[index].chmod(0o600)
        copies[index].write_bytes(b"foreign")
        copies[index].chmod(0o400)
    elif alter == "record-replacement":
        data = json.loads(record_file.read_bytes())
        data["replacement_sha256"] = "f" * 64
        record_file.write_text(json.dumps(data))
    elif alter == "remaining-policy":
        p = base / deploy.POLICY_FILE
        p.write_bytes(b"residual unapproved policy")
        p.chmod(0o444)
    elif alter == "incomplete-transaction":
        folder = deploy._host(root, Path(
            "/opt/zog/compiler-runtime/rollback") / ("a" * 32))
        folder.mkdir(parents=True)
        p = folder / "selection-transaction.json"
        p.write_text(json.dumps(
            {"service": deploy.SERVICE, "state": "selected"}))
        p.chmod(0o600)
    else:
        raise AssertionError("unhandled case")
    with pytest.raises(deploy.HelperDeploymentHold):
        deploy.stage(root=root)
    assert not deploy._host(
        root, deploy.ROLLBACK /
        "restored-before-restage-000001.json").exists()
    if alter != "record-replacement":
        assert record_file.read_bytes() == original_record
    assert all(p.exists() for p in copies)


def test_restored_to_staged_retry_after_evidence_created_before_record_commit(
        installed, monkeypatch):
    root, guard, unit, original, base, record_file, copies = (
        _restored_issuer_fixture(installed))
    before = record_file.read_bytes()
    real_atomic = deploy._atomic
    def simulated_crash(path, content, mode):
        if path == record_file:
            raise OSError("crash before restage state commit")
        return real_atomic(path, content, mode)
    monkeypatch.setattr(deploy, "_atomic", simulated_crash)
    with pytest.raises(OSError, match="crash"):
        deploy.stage(root=root)
    assert record_file.read_bytes() == before
    evidence = deploy._host(
        root, deploy.ROLLBACK / "restored-before-restage-000001.json")
    assert evidence.read_bytes() == before
    monkeypatch.setattr(deploy, "_atomic", real_atomic)
    assert deploy.stage(root=root)["state"] == "staged"
    assert evidence.read_bytes() == before
    assert not deploy._host(
        root, deploy.ROLLBACK / "restored-before-restage-000002.json").exists()


def test_restored_to_staged_refuses_mismatched_existing_history(installed):
    root, guard, unit, original, base, record_file, copies = (
        _restored_issuer_fixture(installed))
    evidence = deploy._host(
        root, deploy.ROLLBACK / "restored-before-restage-000001.json")
    evidence.write_bytes(b'{"foreign":"receipt"}')
    evidence.chmod(0o400)
    old_record = record_file.read_bytes()
    with pytest.raises(deploy.HelperDeploymentHold, match="history conflicts"):
        deploy.stage(root=root)
    assert record_file.read_bytes() == old_record


def _simulate_reviewed_policy_update(monkeypatch, old_policy=b"old-protected-policy"):
    """Model a previously reviewed historical policy and a new source pin.

    Keep the actual pinned source tuple in production; only the disposable
    fixture uses a distinct old policy to prove that history isn't replaced.
    """
    original_tuple = deploy._source_tuple()
    original, successor, new_policy = original_tuple
    old_tuple = (original, successor, old_policy)
    monkeypatch.setattr(deploy, "_source_tuple", lambda: old_tuple)
    return original_tuple, old_tuple


def test_restored_to_staged_with_updated_policy_preserves_old_files_and_receipts(
        installed, monkeypatch):
    root, guard, unit, original, original_unit, base = installed
    new_tuple, previous_tuple = _simulate_reviewed_policy_update(monkeypatch)
    deploy.stage(root=root)
    deploy.activate(root=root)
    deploy.restore(root=root)
    directory = deploy._host(root, deploy.ROLLBACK)
    preserved = [directory / name for name in (
        "original-guard.py", "approved-successor.py", "approved-binding.py")]
    before = [(p.read_bytes(), p.stat().st_ino) for p in preserved]
    baseline = (base / "baseline.json").read_bytes()
    record_before = (directory / "record.json").read_bytes()
    monkeypatch.setattr(deploy, "_source_tuple", lambda: new_tuple)
    result = deploy.stage(root=root)
    new_digest = hashlib.sha256(new_tuple[2]).hexdigest()
    revised = directory / ("approved-binding-" + new_digest + ".py")
    history = directory / "restored-before-restage-000001.json"
    assert result["state"] == "staged"
    assert result["policy_sha256"] == new_digest
    assert result["previous_policy_sha256"] == hashlib.sha256(previous_tuple[2]).hexdigest()
    assert result["policy_backup_name"] == revised.name
    assert revised.read_bytes() == new_tuple[2]
    assert revised.stat().st_mode & 0o777 == 0o400
    assert history.read_bytes() == record_before
    assert [(p.read_bytes(), p.stat().st_ino) for p in preserved] == before
    assert (base / "baseline.json").read_bytes() == baseline
    assert guard.read_bytes() == original
    assert deploy.activate(root=root)["policy_sha256"] == new_digest
    assert (base / deploy.POLICY_FILE).read_bytes() == new_tuple[2]
    assert deploy.restore(root=root)["state"] == "restored"
    assert not (base / deploy.POLICY_FILE).exists()
    assert revised.read_bytes() == new_tuple[2]
    assert [(p.read_bytes(), p.stat().st_ino) for p in preserved] == before
    assert history.read_bytes() == record_before


def test_staged_to_staged_policy_revision_requires_changed_reviewed_bytes(
        installed, monkeypatch):
    root, guard, unit, original, original_unit, base = installed
    new_tuple, previous_tuple = _simulate_reviewed_policy_update(monkeypatch)
    staged = deploy.stage(root=root)
    original_record = deploy._host(root, deploy.ROLLBACK / "record.json").read_bytes()
    with pytest.raises(deploy.HelperDeploymentHold, match="same approved policy"):
        deploy.stage(root=root)
    monkeypatch.setattr(deploy, "_source_tuple", lambda: new_tuple)
    updated = deploy.stage(root=root)
    assert updated["state"] == "staged"
    assert updated["policy_update_count"] == 1
    assert updated["policy_sha256"] == hashlib.sha256(new_tuple[2]).hexdigest()
    history = deploy._host(root, deploy.ROLLBACK /
                          "staged-before-policy-update-000001.json")
    assert history.read_bytes() == original_record
    assert deploy._host(root, deploy.ROLLBACK /
                        "approved-binding.py").read_bytes() == previous_tuple[2]
    assert guard.read_bytes() == original


@pytest.mark.parametrize("drift", [
    "source-original", "source-successor", "historical-policy",
    "baseline", "live-original", "residual-policy", "selected-transaction",
])
def test_policy_restage_denies_source_or_history_drift(installed, monkeypatch, drift):
    root, guard, unit, original, original_unit, base = installed
    new_tuple, old_tuple = _simulate_reviewed_policy_update(monkeypatch)
    deploy.stage(root=root)
    deploy.activate(root=root)
    deploy.restore(root=root)
    directory = deploy._host(root, deploy.ROLLBACK)
    record = directory / "record.json"
    before = record.read_bytes()
    if drift in ("source-original", "source-successor", "historical-policy"):
        filename = {"source-original": "original-guard.py",
                    "source-successor": "approved-successor.py",
                    "historical-policy": "approved-binding.py"}[drift]
        target = directory / filename
        target.chmod(0o600)
        target.write_bytes(b"changed-history")
        target.chmod(0o400)
    elif drift == "baseline":
        (base / "baseline.json").write_bytes(
            (base / "baseline.json").read_bytes() + b" ")
    elif drift == "live-original":
        guard.chmod(0o600)
        guard.write_bytes(b"foreign")
        guard.chmod(0o444)
    elif drift == "residual-policy":
        policy_path = base / deploy.POLICY_FILE
        policy_path.write_bytes(b"not-restored")
        policy_path.chmod(0o444)
    elif drift == "selected-transaction":
        folder = deploy._host(root, Path("/opt/zog/compiler-runtime/rollback") / ("b"*32))
        folder.mkdir(parents=True)
        tx = folder / "selection-transaction.json"
        tx.write_text(json.dumps({"service": deploy.SERVICE, "state": "selected"}))
        tx.chmod(0o600)
    monkeypatch.setattr(deploy, "_source_tuple", lambda: new_tuple)
    with pytest.raises(deploy.HelperDeploymentHold):
        deploy.stage(root=root)
    assert record.read_bytes() == before
    assert not (directory / "restored-before-restage-000001.json").exists()


def test_policy_revision_retry_reuses_new_backup_and_immutable_history(installed, monkeypatch):
    root, guard, unit, original, original_unit, base = installed
    new_tuple, old_tuple = _simulate_reviewed_policy_update(monkeypatch)
    deploy.stage(root=root)
    deploy.activate(root=root)
    deploy.restore(root=root)
    monkeypatch.setattr(deploy, "_source_tuple", lambda: new_tuple)
    directory = deploy._host(root, deploy.ROLLBACK)
    record = directory / "record.json"
    old_record = record.read_bytes()
    real_atomic = deploy._atomic
    def interrupt(path, content, mode):
        if path == record:
            raise OSError("interrupt versioned policy commit")
        return real_atomic(path, content, mode)
    monkeypatch.setattr(deploy, "_atomic", interrupt)
    with pytest.raises(OSError, match="interrupt"):
        deploy.stage(root=root)
    revised = directory / ("approved-binding-" + hashlib.sha256(new_tuple[2]).hexdigest() + ".py")
    history = directory / "restored-before-restage-000001.json"
    assert revised.read_bytes() == new_tuple[2]
    assert history.read_bytes() == old_record
    assert record.read_bytes() == old_record
    monkeypatch.setattr(deploy, "_atomic", real_atomic)
    assert deploy.stage(root=root)["state"] == "staged"
    assert history.read_bytes() == old_record
    assert revised.read_bytes() == new_tuple[2]
    assert (directory / "approved-binding.py").read_bytes() == old_tuple[2]


def test_staged_policy_revision_refuses_conflicting_prior_version_copy(
        installed, monkeypatch):
    root, guard, unit, original, original_unit, base = installed
    new_tuple, old_tuple = _simulate_reviewed_policy_update(monkeypatch)
    deploy.stage(root=root)
    directory = deploy._host(root, deploy.ROLLBACK)
    new_digest = hashlib.sha256(new_tuple[2]).hexdigest()
    foreign = directory / ("approved-binding-" + new_digest + ".py")
    foreign.write_bytes(b"forged")
    foreign.chmod(0o400)
    before = (directory / "record.json").read_bytes()
    monkeypatch.setattr(deploy, "_source_tuple", lambda: new_tuple)
    with pytest.raises(deploy.HelperDeploymentHold, match="conflicts"):
        deploy.stage(root=root)
    assert (directory / "record.json").read_bytes() == before
    assert not (directory / "staged-before-policy-update-000001.json").exists()


def test_old_active_policy_can_be_safely_restored_after_source_update(
        installed, monkeypatch):
    root, guard, unit, original, original_unit, base = installed
    new_tuple, old_tuple = _simulate_reviewed_policy_update(monkeypatch)
    deploy.stage(root=root)
    deploy.activate(root=root)
    assert (base / deploy.POLICY_FILE).read_bytes() == old_tuple[2]
    # New source selection must never prevent recovery of the original
    # helper, provided the previously installed policy bytes are still
    # exactly attested by the historical protected rollback record.
    monkeypatch.setattr(deploy, "_source_tuple", lambda: new_tuple)
    assert deploy.restore(root=root)["state"] == "restored"
    assert guard.read_bytes() == original
    assert not (base / deploy.POLICY_FILE).exists()
    assert deploy._host(root, deploy.ROLLBACK / "approved-binding.py").read_bytes() == old_tuple[2]
    assert deploy.stage(root=root)["policy_sha256"] == hashlib.sha256(new_tuple[2]).hexdigest()


def test_revised_policy_cannot_activate_before_versioned_staging(installed, monkeypatch):
    root, guard, unit, original, original_unit, base = installed
    new_tuple, old_tuple = _simulate_reviewed_policy_update(monkeypatch)
    deploy.stage(root=root)
    monkeypatch.setattr(deploy, "_source_tuple", lambda: new_tuple)
    with pytest.raises(deploy.HelperDeploymentHold,
                       match="not the currently reviewed successor"):
        deploy.activate(root=root)
    assert guard.read_bytes() == original
    assert not (base / deploy.POLICY_FILE).exists()
    assert deploy.stage(root=root)["state"] == "staged"
    assert deploy.activate(root=root)["state"] == "active"
