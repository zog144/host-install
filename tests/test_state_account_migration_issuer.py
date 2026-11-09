"""Source regressions for protected local registry STATE admission issuer.

Only disposable directories are mutated. No system NSS, /state, registry Host,
service or installed candidate is modified.
"""
import copy
import hashlib
import os
from pathlib import Path

import pytest

from test_state_account_migration import fixture, HOST_UUID, FINGERPRINT
from test_state_directory_runtime import ROOT_UUID, ROOT_PARTUUID
from zog.host_install import state_account_migration_issuer as issuer
from zog.host_install import state_account_migration_admission as admission
from zog.host_install.state_account_migration_completion import (
    WITNESS_SCHEMA, WITNESS_FIELDS,
)
from zog.host_install.state_account_migration_consumer import CONSUMER_SELECTION
from zog.host_install.state_contract import StateError, canonical, digest, decode
from zog.host_install.state_io import lock


def selection_and_evidence():
    f = fixture()
    f["consumer_contract"] = dict(CONSUMER_SELECTION)
    bundle = f.pop("bundle")
    identity = {
        "directory": [259, 100],
        "identity.pem": [259, 121],
        "binding.json": [259, 122],
        "key.lock": [259, 123],
    }
    creds = {"archive.json": [259, 471]}
    selected = {
        "schema": issuer.OPERATOR_SCHEMA,
        "migration_id": f["migration_id"],
        "installation_id": bundle["installation"]["installation_id"],
        "state_volume_id": bundle["bootstrap"]["state"]["state_volume_id"],
        "installation_record_id": bundle["installation"]["record_id"],
        "authorization_id":
            bundle["bootstrap"]["initialization"]["authorization_id"],
        "root_fs_uuid": ROOT_UUID,
        "root_partuuid": ROOT_PARTUUID,
        "host_uuid": HOST_UUID, "fingerprint": FINGERPRINT,
        "registry_origin":
            "https://host-registry.hosts.zog-network-demo.uk",
        "identity_inode": identity["directory"],
        "credential_inodes": creds,
        "file_inventory_sha256": digest(f["file_inventory"]),
        "configuration_sha256": hashlib.sha256(
            f["configuration_bytes"]).hexdigest(),
        "unit_sha256": hashlib.sha256(f["unit_bytes"]).hexdigest(),
        "account_snapshot_sha256": digest(f["account_snapshot"]),
        "candidate_executable_sha256": "a"*64,
        "candidate_interpreter_sha256": "b"*64,
        "authorization_reference": "operator-native-migration-approval",
        "approved_admission_sha256": None,
    }
    runtime = {
        "schema": admission.RUNTIME_SCHEMA,
        "consumer_selection_sha256": digest(CONSUMER_SELECTION),
        "executable": admission.CANDIDATE_EXECUTABLE,
        "interpreter": admission.CANDIDATE_PYTHON,
        "executable_sha256": "a"*64, "interpreter_sha256": "b"*64,
        "executable_inode": [259, 221], "interpreter_inode": [259, 222],
    }
    observation = {
        "source_inputs": f, "runtime": runtime,
        "identity_inodes": identity,
        "credential_inodes": creds, "root_device": 259,
    }
    return selected, observation


def test_operator_selection_produces_exact_canonical_bundle_and_held_journal():
    selected, observation = selection_and_evidence()
    bundle, result = issuer.evaluate(selected, observation)
    assert result["plan"]["host_uuid"] == HOST_UUID
    assert result["plan"]["root_fs_uuid"] == ROOT_UUID
    assert result["plan"]["root_partuuid"] == ROOT_PARTUUID
    assert result["plan"]["consumer_selection_sha256"] == digest(CONSUMER_SELECTION)
    assert bundle["marker"]["kind"] == "zog-state-directory"
    assert result["plan"]["status"] == "SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
    initial = admission.initial_journal(result)
    assert initial["status"] == "applying" and initial["completed"] == []
    assert issuer.check_selection(selected) == selected


@pytest.mark.parametrize("attack", [
    "foreign-host", "wrong-original-inode", "credential-substitution",
    "modified-unit", "modified-config", "account-change",
    "modified-file-inventory", "wrong-root", "wrong-consumer",
    "wrong-runtime", "unsupported-signer", "unreviewed-registry",
])
def test_operator_selection_denies_foreign_source_or_inventory(attack):
    selected, observation = selection_and_evidence()
    if attack == "foreign-host":
        selected["host_uuid"] = "6f551c3f-4b50-4746-b226-1c2b90e45a0f"
    elif attack == "wrong-original-inode":
        selected["identity_inode"] = [259, 555]
    elif attack == "credential-substitution":
        selected["credential_inodes"]["archive.json"] = [259, 999]
    elif attack == "modified-unit":
        observation["source_inputs"]["unit_bytes"] += b"# unexpected\n"
    elif attack == "modified-config":
        observation["source_inputs"]["configuration_bytes"] += b" "
    elif attack == "account-change":
        observation["source_inputs"]["account_snapshot"]["groups"][
            "host-discover"] = 972
    elif attack == "modified-file-inventory":
        observation["source_inputs"]["file_inventory"][
            "key.lock"]["inode"] = 999
    elif attack == "wrong-root":
        selected["root_fs_uuid"] = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
    elif attack == "wrong-consumer":
        observation["source_inputs"]["consumer_contract"] = None
    elif attack == "wrong-runtime":
        observation["runtime"]["executable_sha256"] = "f"*64
    elif attack == "unsupported-signer":
        selected["registrar_signature"] = "not-a-required-authority"
    elif attack == "unreviewed-registry":
        selected["registry_origin"] = "https://unknown.invalid"
    with pytest.raises(StateError):
        issuer.evaluate(selected, observation)


def _witness(admission_record):
    plan = admission_record["plan"]
    data = {
        "schema": WITNESS_SCHEMA,
        "migration_id": plan["migration_id"],
        "plan_sha256": digest(plan),
        "host_uuid": plan["host_uuid"],
        "fingerprint": plan["public_fingerprint"],
        "registry_origin": plan["registry_origin"],
        "identity_inode": [259, 100],
        "key_inode": [259, 121],
        "binding_inode": [259, 122],
        "lock_inode": [259, 123],
        "ca_inode": None, "ca_sha256": None,
        "retained_files": {},
    }
    assert set(data) == WITNESS_FIELDS
    return data


def _open_test_parent(folder):
    if os.geteuid() != 0:
        pytest.skip("protected publisher tests need disposable root")
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o700)
    return os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def test_protected_journal_publication_is_atomic_same_byte_retry(tmp_path):
    selected, observed = selection_and_evidence()
    bundle, result = issuer.evaluate(selected, observed)
    parent = tmp_path / "migrations"
    fd = _open_test_parent(parent)
    try:
        with lock(fd, ".admission.lock"):
            issued = issuer._publish_records(
                fd, selected["migration_id"], bundle=bundle, admission=result,
                witness=_witness(result))
        assert issued["native_execution_enabled"] is False
        tx = parent / selected["migration_id"]
        assert set(x.name for x in tx.iterdir()) == {
            "plan.json", "admission.json", "bundle.json",
            "original.json", "transaction.json"}
        assert all(x.stat().st_uid == 0 and
                   x.stat().st_mode & 0o777 == 0o600 for x in tx.iterdir())
        assert decode((tx/"transaction.json").read_bytes()) == (
            admission.initial_journal(result))
        with lock(fd, ".admission.lock"):
            again = issuer._publish_records(
                fd, selected["migration_id"], bundle=bundle, admission=result,
                witness=_witness(result))
        assert again["admission_sha256"] == issued["admission_sha256"]
        changed = _witness(result)
        changed["key_inode"] = [259, 999]
        with lock(fd, ".admission.lock"):
            with pytest.raises(StateError):
                issuer._publish_records(
                    fd, selected["migration_id"], bundle=bundle, admission=result,
                    witness=changed)
    finally:
        os.close(fd)


@pytest.mark.parametrize("crash_at", (
    "staged:bundle.json", "linked:bundle.json", "published:plan.json",
    "published:original.json", "linked:transaction.json",
))
def test_interrupted_original_publication_restarts_only_same_bytes(
        tmp_path, crash_at):
    selected, observed = selection_and_evidence()
    bundle, result = issuer.evaluate(selected, observed)
    fd = _open_test_parent(tmp_path / "migrations")
    class Crash(Exception):
        pass
    def crash(phase):
        if phase == crash_at:
            raise Crash()
    try:
        with lock(fd, ".admission.lock"):
            with pytest.raises(Crash):
                issuer._publish_records(
                    fd, selected["migration_id"], bundle=bundle,
                    admission=result, witness=_witness(result),
                    checkpoint=crash)
        with lock(fd, ".admission.lock"):
            issuer._publish_records(
                fd, selected["migration_id"], bundle=bundle, admission=result,
                witness=_witness(result))
        assert decode((tmp_path / "migrations" / selected["migration_id"] /
                       "transaction.json").read_bytes()) == (
                           admission.initial_journal(result))
    finally:
        os.close(fd)


def test_second_migration_and_foreign_entry_never_adopted(tmp_path):
    selected, observed = selection_and_evidence()
    bundle, result = issuer.evaluate(selected, observed)
    parent = tmp_path / "migrations"
    fd = _open_test_parent(parent)
    try:
        with lock(fd, ".admission.lock"):
            issuer._publish_records(
                fd, selected["migration_id"], bundle=bundle, admission=result,
                witness=_witness(result))
        with lock(fd, ".admission.lock"):
            with pytest.raises(StateError):
                issuer._publish_records(
                    fd, "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
                    bundle=bundle,
                    admission={**result, "plan": {
                        **result["plan"],
                        "migration_id": "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"}},
                    witness=_witness(result))
        (parent / "foreign").write_text("no")
        with lock(fd, ".admission.lock"):
            with pytest.raises(StateError):
                issuer._publish_records(
                    fd, selected["migration_id"], bundle=bundle,
                    admission=result, witness=_witness(result))
    finally:
        os.close(fd)


def test_production_issuer_rejects_non_root_before_reading_operator_file(
        monkeypatch):
    monkeypatch.setattr(issuer.os, "geteuid", lambda: 1100)
    with pytest.raises(StateError):
        issuer.issue()
    with pytest.raises(StateError):
        issuer.preview()
