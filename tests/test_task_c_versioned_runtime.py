"""Disposable version-selection tests: no Host, systemctl, pip or SSM."""
import hashlib
import json

import pytest

from zog.host_install import task_c_versioned_runtime as versioned


@pytest.fixture
def staged(tmp_path, monkeypatch):
    unit = tmp_path / versioned.UNIT.lstrip("/")
    unit.parent.mkdir(parents=True)
    original = (
        b"[Service]\n"
        b"ExecStart=/opt/zog/task-c/venv/bin/host-deploy-gateway "
        b"--state-directory /var/lib/host-deploy-gateway run\n"
    )
    unit.write_bytes(original)
    old = tmp_path / versioned.legacy.VENVDIR.lstrip("/")
    (old / "bin").mkdir(parents=True)
    (old / "bin/host-deploy-gateway").write_bytes(b"old gateway")
    candidate = (
        tmp_path / versioned.BASE.lstrip("/")
        / "versions" / "release-1" / "venv" / "bin"
    )
    candidate.mkdir(parents=True)
    (candidate / "host-deploy-gateway").write_bytes(b"new gateway")
    receipt = {
        "schema": versioned.SCHEMA,
        "release": "release-1",
        "status": "prepared-not-selected",
        "activation_authorized": False,
        "gateway_sha256": hashlib.sha256(b"new gateway").hexdigest(),
        "tree_sha256": versioned._tree_digest(candidate.parent),
    }
    (candidate.parent.parent / "preparation.json").write_text(json.dumps(receipt))
    monkeypatch.setattr(versioned.legacy, "_units",
                        lambda: {versioned.legacy.UNITS[0]: original})
    return tmp_path, unit, original, old


def test_switch_preserves_original_and_restores_unit(staged):
    root, unit, original, old = staged
    selected = versioned.select("release-1", root=root)
    assert selected["status"] == "selected"
    assert b"/versions/release-1/venv/bin/host-deploy-gateway" in unit.read_bytes()
    storage = root / versioned.ROLLBACK.lstrip("/")
    assert (storage / "previous-unit").read_bytes() == original
    assert (storage / "original-venv/bin/host-deploy-gateway").read_bytes() == b"old gateway"
    assert (old / "bin/host-deploy-gateway").read_bytes() == b"old gateway"
    restored = versioned.restore(root=root)
    assert restored["status"] == "restored"
    assert unit.read_bytes() == original
    assert (storage / "original-venv/bin/host-deploy-gateway").is_file()


def test_second_switch_cannot_replace_protected_rollback(staged):
    root, unit, original, old = staged
    versioned.select("release-1", root=root)
    with pytest.raises(versioned.SelectionError, match="previous selection"):
        versioned.select("release-1", root=root)
    assert (root / versioned.ROLLBACK.lstrip("/") / "previous-unit").read_bytes() == original


def test_modified_unit_denies_rollback(staged):
    root, unit, original, old = staged
    versioned.select("release-1", root=root)
    unit.write_bytes(b"foreign unit")
    with pytest.raises(versioned.SelectionError, match="current unit differs"):
        versioned.restore(root=root)
    assert unit.read_bytes() == b"foreign unit"


def test_modified_saved_unit_denies_rollback(staged):
    root, unit, original, old = staged
    versioned.select("release-1", root=root)
    (root / versioned.ROLLBACK.lstrip("/") / "previous-unit").write_bytes(b"foreign")
    with pytest.raises(versioned.SelectionError, match="rollback unit bytes differ"):
        versioned.restore(root=root)


def test_missing_version_refuses_without_modifying_unit(staged):
    root, unit, original, old = staged
    with pytest.raises((versioned.SelectionError, FileNotFoundError)):
        versioned.select("release-missing", root=root)
    assert unit.read_bytes() == original


def test_version_name_rejects_path_escape(staged):
    root, unit, original, old = staged
    with pytest.raises(versioned.SelectionError, match="invalid immutable release"):
        versioned.select("../other", root=root)
    assert unit.read_bytes() == original


def test_interrupted_pending_record_restores_prior_unit(staged):
    root, unit, original, old = staged
    versioned.select("release-1", root=root)
    path = root / versioned.ROLLBACK.lstrip("/") / "selection.json"
    record = json.loads(path.read_text())
    record["status"] = "pending"
    path.write_text(json.dumps(record))
    assert versioned.restore(root=root)["status"] == "restored"
    assert unit.read_bytes() == original


def test_changed_prepared_runtime_denied(staged):
    root, unit, original, old = staged
    path = (
        root / versioned.BASE.lstrip("/")
        / "versions/release-1/venv/bin/host-deploy-gateway"
    )
    path.write_bytes(b"changed")
    with pytest.raises(versioned.SelectionError, match="unverified versioned runtime"):
        versioned.select("release-1", root=root)
    assert unit.read_bytes() == original
