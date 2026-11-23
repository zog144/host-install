"""Issuer persistence replacement-unit approval binding, source-only.

The original issuer baseline remains immutable; new SHA authorization must
derive from the already reviewed selection and never remove the storage guard.
"""
import copy
import hashlib
import json

import pytest

from zog.host_install import compiler_issuer_persistence_binding as binding


def fixture():
    original = b"[Service]\nExecStart=/opt/original/controller\n"
    selected = b"[Service]\nExecStart=/opt/selected/controller\n"
    dropin = (b"[Service]\nExecStartPre=/usr/bin/test -d /state/issuer\n"
              b"ReadOnlyPaths=/state/issuer /var/lib/zog-certify-manage\n")
    original_sha = hashlib.sha256(original).hexdigest()
    selected_sha = hashlib.sha256(selected).hexdigest()
    issuer_sha = hashlib.sha256(dropin).hexdigest()
    metadata = {"name": "issuer-persistence.conf", "sha256": issuer_sha,
                "uid": 0, "gid": 0, "mode": 0o644, "size": len(dropin)}
    effect = {
        "ExecStartPre": [{
            "path": "/usr/bin/test", "argv": "/usr/bin/test -d /state/issuer",
            "flags": {"ignore_errors": "no", "flags": ""},
        }],
        "ReadOnlyPaths": "/state/issuer /var/lib/zog-certify-manage",
        "Requires": "state.mount issuer-storage.mount",
        "After": "state.mount issuer-storage.mount",
    }
    selection = {
        "release_id": "a" * 32,
        "service": {
            "name": "zog-certbot-seed-root.service",
            "staged_unit": "/opt/zog/compiler-runtime/versions/" + "a" * 32 +
                           "/systemd/zog-certbot-seed-root.service",
            "staged_sha256": selected_sha,
        },
        "rollback": {"unit_sha256": original_sha},
        "composition": {
            "original_fragment": {
                "path": "/etc/systemd/system/zog-certbot-seed-root.service",
                "sha256": original_sha, "uid": 0, "gid": 0, "mode": 0o644,
                "size": len(original)},
            "selected_fragment": {
                "path": "/opt/zog/compiler-runtime/versions/" + "a" * 32 +
                        "/systemd/zog-certbot-seed-root.service",
                "sha256": selected_sha, "uid": 0, "gid": 0, "mode": 0o644,
                "size": len(selected)},
            "original_dropins": [metadata],
            "selected_dropins": [dict(metadata)],
            "original_effective": effect,
            "selected_effective": copy.deepcopy(effect),
        },
    }
    receipt = {
        "release_id": "a" * 32,
        "service": "zog-certbot-seed-root.service",
        "unit_sha256": original_sha,
        "original_fragment": copy.deepcopy(selection["composition"]["original_fragment"]),
        "original_dropins": copy.deepcopy(selection["composition"]["original_dropins"]),
    }
    return selection, receipt, dropin


def test_approved_replacement_digest_separate_from_original_rollback_baseline():
    selected, original, issuer = fixture()
    before = (copy.deepcopy(selected), copy.deepcopy(original), issuer)
    actual = binding.reviewed_replacement_binding(selected, "f" * 64, original,
                                                  issuer, issuer)
    assert actual["original_rollback_unit_sha256"] != actual["approved_replacement_unit_sha256"]
    assert actual["original_rollback_unit_sha256"] == original["unit_sha256"]
    assert actual["approved_replacement_unit_sha256"] == selected["service"]["staged_sha256"]
    assert actual["approved_selection_sha256"] == "f" * 64
    assert actual["issuer_native_storage_rechecked"] is False
    assert actual["startup_authorized"] is False
    assert (selected, original, issuer) == before


@pytest.mark.parametrize("mutation", [
    lambda s,r: s["service"].update(staged_sha256="f"*64),
    lambda s,r: s["composition"]["selected_fragment"].update(sha256="f"*64),
    lambda s,r: r.update(unit_sha256="e"*64),
    lambda s,r: r["original_fragment"].update(sha256="e"*64),
    lambda s,r: s["rollback"].update(unit_sha256="e"*64),
    lambda s,r: s["composition"].update(original_dropins=[]),
    lambda s,r: s["composition"].update(selected_dropins=[]),
    lambda s,r: s["composition"]["selected_dropins"][0].update(sha256="a"*64),
    lambda s,r: s["composition"]["selected_dropins"][0].update(uid=1000),
    lambda s,r: s["composition"]["selected_effective"].update(ExecStartPre=[]),
    lambda s,r: s["composition"]["selected_effective"].update(ReadOnlyPaths="/tmp"),
    lambda s,r: s["composition"]["selected_effective"].update(Requires="state.mount"),
    lambda s,r: s["composition"]["selected_effective"].update(After="state.mount"),
])
def test_original_baseline_digest_mount_and_storage_mutations_hold(mutation):
    selected, original, issuer = fixture()
    mutation(selected, original)
    with pytest.raises(binding.IssuerBindingHold):
        binding.reviewed_replacement_binding(selected, "f"*64, original, issuer, issuer)


@pytest.mark.parametrize("new_bytes", [
    b"[Service]\nExecStartPre=/usr/bin/true\nReadOnlyPaths=/state/issuer\n",
    b"[Service]\nExecStartPre=/usr/bin/test -d /state/issuer\n",
    b"[Service]\nReadOnlyPaths=/state/issuer\n",
    b"[Service]\nExecStartPre=\nReadOnlyPaths=/state/issuer\n",
])
def test_rewritten_or_reduced_issuer_guard_bytes_hold(new_bytes):
    selected, original, issuer = fixture()
    with pytest.raises(binding.IssuerBindingHold):
        binding.reviewed_replacement_binding(selected, "f"*64, original,
                                             issuer, new_bytes)


def test_rejects_other_service_and_invalid_selection_digest():
    selected, original, issuer = fixture()
    selected["service"]["name"] = "other.service"
    with pytest.raises(binding.IssuerBindingHold):
        binding.reviewed_replacement_binding(selected, "f"*64, original, issuer, issuer)
    selected["service"]["name"] = binding.COMPILER_UNIT
    with pytest.raises(binding.IssuerBindingHold):
        binding.reviewed_replacement_binding(selected, "anything", original,
                                             issuer, issuer)



def _selection_bytes(selection):
    return json.dumps(selection, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _approved_selected_transaction(selection, original, issuer):
    digest = hashlib.sha256(_selection_bytes(selection)).hexdigest()
    reviewed = binding.reviewed_replacement_binding(
        selection, digest, original, issuer, issuer)
    transaction = {
        "schema": "zog-compiler-controller-versioned-installer-v1",
        "release_id": selection["release_id"],
        "service": binding.COMPILER_UNIT,
        "selection_sha256": digest,
        "old_unit_sha256": original["unit_sha256"],
        "new_unit_sha256": selection["service"]["staged_sha256"],
        "old_dropins": copy.deepcopy(selection["composition"]["original_dropins"]),
        "new_dropins": copy.deepcopy(selection["composition"]["selected_dropins"]),
        "issuer_replacement_binding": reviewed,
        "state": "selected",
    }
    return digest, transaction


def test_selected_only_digest_evidence_retains_native_issuer_guard():
    selection, original, issuer = fixture()
    digest, transaction = _approved_selected_transaction(selection, original, issuer)
    active = b"[Service]\nExecStart=/opt/selected/controller\n"
    initial = copy.deepcopy(transaction)
    evidence = binding.verify_selected_replacement_digest(
        selection, digest, _selection_bytes(selection), original,
        transaction, active, issuer, issuer)
    assert evidence["selected_transaction_verified"] is True
    assert evidence["approved_replacement_unit_sha256"] == hashlib.sha256(active).hexdigest()
    assert evidence["original_rollback_unit_sha256"] == original["unit_sha256"]
    assert evidence["issuer_native_storage_rechecked"] is False
    assert evidence["startup_authorized"] is False
    assert transaction == initial


@pytest.mark.parametrize("state", ["arming", "pending", "restoring", "restored", "aborted", "", None])
def test_replacement_digest_denied_before_or_after_selected_state(state):
    selection, original, issuer = fixture()
    digest, transaction = _approved_selected_transaction(selection, original, issuer)
    transaction["state"] = state
    with pytest.raises(binding.IssuerBindingHold, match="selected"):
        binding.verify_selected_replacement_digest(
            selection, digest, _selection_bytes(selection), original, transaction,
            b"[Service]\nExecStart=/opt/selected/controller\n", issuer, issuer)


@pytest.mark.parametrize("attribute,value", [
    ("schema", "zog-other-v1"),
    ("release_id", "b" * 32),
    ("service", "other.service"),
    ("selection_sha256", "e" * 64),
    ("old_unit_sha256", "e" * 64),
    ("new_unit_sha256", "e" * 64),
    ("old_dropins", []),
    ("new_dropins", []),
    ("issuer_replacement_binding", {}),
])
def test_selected_digest_denies_forged_transaction(attribute, value):
    selection, original, issuer = fixture()
    digest, transaction = _approved_selected_transaction(selection, original, issuer)
    transaction[attribute] = value
    with pytest.raises(binding.IssuerBindingHold):
        binding.verify_selected_replacement_digest(
            selection, digest, _selection_bytes(selection), original, transaction,
            b"[Service]\nExecStart=/opt/selected/controller\n", issuer, issuer)


@pytest.mark.parametrize("active", [
    b"[Service]\nExecStart=/opt/original/controller\n",
    b"[Service]\nExecStart=/opt/unreviewed/controller\n",
    b"",
])
def test_selected_digest_denies_foreign_original_or_missing_active_bytes(active):
    selection, original, issuer = fixture()
    digest, transaction = _approved_selected_transaction(selection, original, issuer)
    with pytest.raises(binding.IssuerBindingHold, match="active compiler"):
        binding.verify_selected_replacement_digest(
            selection, digest, original, transaction, active, issuer, issuer)


def test_selected_digest_denies_mismatched_issuer_storage_and_reviewed_approval():
    selection, original, issuer = fixture()
    digest, transaction = _approved_selected_transaction(selection, original, issuer)
    with pytest.raises(binding.IssuerBindingHold):
        binding.verify_selected_replacement_digest(
            selection, "e"*64, _selection_bytes(selection), original, transaction,
            b"[Service]\nExecStart=/opt/selected/controller\n", issuer, issuer)
    selection["composition"]["selected_effective"]["ReadOnlyPaths"] = "/tmp"
    with pytest.raises(binding.IssuerBindingHold):
        binding.verify_selected_replacement_digest(
            selection, digest, _selection_bytes(selection), original, transaction,
            b"[Service]\nExecStart=/opt/selected/controller\n", issuer, issuer)


def test_selected_digest_rejects_unapproved_raw_selection_and_duplicate_json():
    selection, original, issuer = fixture()
    digest, transaction = _approved_selected_transaction(selection, original, issuer)
    active = b"[Service]\\nExecStart=/opt/selected/controller\\n"
    with pytest.raises(binding.IssuerBindingHold, match="approved selection"):
        binding.verify_selected_replacement_digest(
            selection, digest, b'{"unreviewed": true}', original,
            transaction, active, issuer, issuer)
    noncanonical = _selection_bytes(selection)
    # Duplicated top-level selection key is forbidden even if an independent
    # hash were computed for those exact bytes.
    duplicate = noncanonical[:-1] + b',"release_id":"a"}'
    duplicate_digest = hashlib.sha256(duplicate).hexdigest()
    with pytest.raises(binding.IssuerBindingHold, match="duplicate key"):
        binding.verify_selected_replacement_digest(
            selection, duplicate_digest, duplicate, original,
            transaction, active, issuer, issuer)
