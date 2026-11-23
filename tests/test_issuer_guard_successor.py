"""Source-level acceptance of recovered issuer guard and its selected-only successor."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

from zog.host_install import issuer_guard_successor as guard
from zog.host_install import compiler_issuer_persistence_binding as policy
from test_compiler_issuer_persistence_binding import (
    fixture as binding_fixture, _approved_selected_transaction, _selection_bytes,
)

PACKAGE = Path(guard.__file__).parent


def _function(source, name):
    nodes = ast.parse(source).body
    return next(ast.dump(node, include_attributes=False)
                for node in nodes if isinstance(node, ast.FunctionDef)
                and node.name == name)


def test_recovered_original_exact_bytes_and_unchanged_issuer_checks():
    original = (PACKAGE / "issuer_guard_original_20261023.py").read_bytes()
    successor = (PACKAGE / "issuer_guard_successor.py").read_bytes()
    assert len(original) == 3853
    assert hashlib.sha256(original).hexdigest() == (
        "990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78")
    for name in ("h", "snapshot", "verify_mounts"):
        assert _function(original.decode(), name) == _function(successor.decode(), name)
    main = successor.decode().split("if __name__=='__main__':", 1)[1]
    assert main.index("actual=snapshot()") < main.index("identity=verify_snapshot(")
    assert main.index("identity=verify_snapshot(") < main.index("mounts=verify_mounts()")
    assert "sys.argv[1]=='verify'" in main
    assert "baseline.json').open('x')" not in main


def _simple_identity():
    return {
        "hashes": {str(guard.UNIT): "a" * 64, "/protected/policy": "b" * 64},
        "storage_hashes": {"data": "c" * 64},
        "storage_inode": 871,
        "filesystem_uuid": "known-uuid",
        "storage_owner": [1000020, 1000020],
        "storage_mode": "0o700",
    }


def test_original_startup_uses_entire_original_baseline(monkeypatch):
    monkeypatch.setattr(guard, "_transactions", lambda: iter(()))
    old = _simple_identity()
    assert guard.verify_snapshot(copy.deepcopy(old), copy.deepcopy(old)) == "original"
    for key, replacement in [
        ("filesystem_uuid", "wrong"), ("storage_inode", 0),
        ("storage_owner", [0, 0]), ("storage_mode", "0o777"),
        ("storage_hashes", {}), ("hashes", {str(guard.UNIT): "a" * 64}),
    ]:
        current = copy.deepcopy(old)
        current[key] = replacement
        with pytest.raises(AssertionError):
            guard.verify_snapshot(current, old)


def selected_fixture(monkeypatch):
    selected, receipt, issuer = binding_fixture()
    selected["service"]["active_unit"] = str(guard.UNIT)
    digest, tx = _approved_selected_transaction(selected, receipt, issuer)
    raw = _selection_bytes(selected)
    assert hashlib.sha256(raw).hexdigest() == digest
    release = selected["release_id"]
    directory = guard.ROLLBACK / release
    unit = b"[Service]\nExecStart=/opt/selected/controller\n"
    staged = Path(selected["service"]["staged_unit"])
    files = {
        directory / "approved-selection.json": raw,
        directory / "preservation.json": json.dumps(receipt).encode(),
        directory / (guard.SERVICE + ".d") / guard.ISSUER: issuer,
        staged.parent / (guard.SERVICE + ".d") / guard.ISSUER: issuer,
        guard.UNIT: unit,
    }
    monkeypatch.setattr(guard, "_transactions", lambda: iter([(directory, tx)]))
    monkeypatch.setattr(guard, "_protected", lambda p: files[Path(p)])
    monkeypatch.setitem(sys.modules, "compiler_issuer_persistence_binding", policy)
    expected = _simple_identity()
    expected["hashes"][str(guard.UNIT)] = receipt["unit_sha256"]
    current = copy.deepcopy(expected)
    current["hashes"][str(guard.UNIT)] = hashlib.sha256(unit).hexdigest()
    return selected, receipt, tx, files, current, expected


def test_selected_replacement_with_approved_bytes_only(monkeypatch):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    assert guard.verify_snapshot(current, expected) == "reviewed-selected"
    assert current["hashes"][str(guard.UNIT)] != expected["hashes"][str(guard.UNIT)]
    assert receipt["unit_sha256"] == expected["hashes"][str(guard.UNIT)]


@pytest.mark.parametrize("state", ["arming", "pending", "restoring", "restored", "aborted"])
def test_interrupted_or_restored_transactions_deny_replacement(monkeypatch, state):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    tx["state"] = state
    with pytest.raises((AssertionError, policy.IssuerBindingHold)):
        guard.verify_snapshot(current, expected)


@pytest.mark.parametrize("field,bad", [
    ("filesystem_uuid", "foreign"), ("storage_owner", [0, 0]),
    ("storage_mode", "0o755"), ("storage_hashes", {}),
])
def test_replacement_rejects_any_issuer_storage_drift(monkeypatch, field, bad):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    current[field] = bad
    with pytest.raises(AssertionError):
        guard.verify_snapshot(current, expected)


def test_replacement_refuses_issuer_policy_or_extra_file_change(monkeypatch):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    current["hashes"]["/protected/policy"] = "f" * 64
    with pytest.raises(AssertionError):
        guard.verify_snapshot(current, expected)
    current = copy.deepcopy(expected)
    current["hashes"][str(guard.UNIT)] = selected["service"]["staged_sha256"]
    current["hashes"]["/foreign"] = "b" * 64
    with pytest.raises(AssertionError):
        guard.verify_snapshot(current, expected)


def test_replacement_denies_approvals_changed_on_disk(monkeypatch):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    directory = guard.ROLLBACK / selected["release_id"]
    files[directory / "approved-selection.json"] = b'{"malicious":true}'
    with pytest.raises(policy.IssuerBindingHold):
        guard.verify_snapshot(current, expected)


def test_replacement_denies_active_byte_change(monkeypatch):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    files[guard.UNIT] = b"[Service]\nExecStart=/unreviewed\n"
    with pytest.raises(policy.IssuerBindingHold):
        guard.verify_snapshot(current, expected)


def test_replacement_denies_original_receipt_change(monkeypatch):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    directory = guard.ROLLBACK / selected["release_id"]
    receipt["unit_sha256"] = "0" * 64
    files[directory / "preservation.json"] = json.dumps(receipt).encode()
    with pytest.raises(AssertionError):
        guard.verify_snapshot(current, expected)


def test_replacement_rejects_parallel_incomplete_operation(monkeypatch):
    selected, receipt, tx, files, current, expected = selected_fixture(monkeypatch)
    other = dict(tx, state="pending", release_id="b" * 32)
    directory = guard.ROLLBACK / selected["release_id"]
    monkeypatch.setattr(guard, "_transactions",
                        lambda: iter([(directory, tx), (guard.ROLLBACK / ("b"*32), other)]))
    with pytest.raises(AssertionError, match="interrupted"):
        guard.verify_snapshot(current, expected)
