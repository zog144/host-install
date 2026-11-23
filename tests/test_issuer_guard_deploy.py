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
