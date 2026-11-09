"""Source-only admission and launcher pin tests; never migrate a live Host."""
import copy
import hashlib
import os

import pytest

from zog.host_install import state_account_migration_admission as a
from zog.host_install import state_account_migration_launcher as launcher
from zog.host_install.state_account_migration_consumer import CONSUMER_SELECTION
from zog.host_install.state_contract import StateError, digest
from test_state_account_migration import fixture


def selection():
    raw = fixture()
    raw["consumer_contract"] = dict(CONSUMER_SELECTION)
    bundle = raw.pop("bundle")
    inventory = raw["file_inventory"]
    identity = {k: [v["dev"], v["inode"]] for k,v in inventory.items()
                if k in ("identity.pem", "binding.json", "key.lock") and v}
    creds = {"archive.json": [259, 131]}
    runtime = {
        "schema": a.RUNTIME_SCHEMA,
        "consumer_selection_sha256": digest(CONSUMER_SELECTION),
        "executable": a.CANDIDATE_EXECUTABLE,
        "interpreter": a.CANDIDATE_PYTHON,
        "executable_sha256": "a"*64,
        "interpreter_sha256": "b"*64,
        "executable_inode": [259, 222],
        "interpreter_inode": [259, 223],
    }
    return bundle, raw, runtime, identity, creds


def review(values):
    b, raw, runtime, identity, creds = values
    return a.review_admission(
        b, raw, runtime, original_identity_inodes=identity,
        original_credential_inodes=creds,
        authorization_reference="reviewed-work-approval-reference")


def test_admission_binds_existing_identity_bundle_and_runtime_without_activation():
    selected = review(selection())
    plan = selected["plan"]
    assert selected["bundle_sha256"] == digest(selection()[0])
    assert plan["consumer_selection_sha256"] == digest(CONSUMER_SELECTION)
    assert plan["status"] == "SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
    assert a.initial_journal(selected)["completed"] == []
    assert not launcher.RUNTIME_ENABLED
    assert a.CANDIDATE_EXECUTABLE in launcher.selected_beacon_argv(
        4, 5, plan["public_fingerprint"], runtime=selected["runtime"])
    unit = launcher.render_selected_launcher_dropin(selected)
    assert a.CANDIDATE_PYTHON.encode() in unit
    assert b"@PINNED_HOST_INSTALL_PYTHON312@" not in unit
    assert b"User=root" in unit


@pytest.mark.parametrize("attack", (
    "identity", "credential", "runtime", "executable", "interpreter",
    "bundle", "no-consumer", "no-authorization",
))
def test_admission_refuses_foreign_bundle_runtime_or_original_inventory(attack):
    values = list(selection())
    if attack == "identity":
        values[3] = dict(values[3], **{"key.lock": [259, 999]})
    elif attack == "credential":
        values[4] = {"other.json": [259, 131]}
    elif attack == "runtime":
        values[2]["consumer_selection_sha256"] = "f"*64
    elif attack == "executable":
        values[2]["executable"] = "/opt/host-discover/venv/bin/host-discover"
    elif attack == "interpreter":
        values[2]["interpreter"] = "/usr/bin/python3"
    elif attack == "bundle":
        values[0]["bootstrap"]["initialization"]["expected_host_uuid"] = (
            "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa")
    elif attack == "no-consumer":
        values[1]["consumer_contract"] = None
    elif attack == "no-authorization":
        b, raw, runtime, identity, creds = values
        with pytest.raises(StateError):
            a.review_admission(
                b, raw, runtime, original_identity_inodes=identity,
                original_credential_inodes=creds, authorization_reference="")
        return
    with pytest.raises(StateError):
        review(values)


def test_disposable_admission_publication_is_exclusive_and_protected(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("root-only disposable publisher")
    folder = tmp_path / "journal"
    folder.mkdir(mode=0o700)
    selected = review(selection())
    outcome = a.publish_disposable_admission(folder, selected)
    assert outcome["native_accepted"] is False
    assert (folder/"plan.json").stat().st_mode & 0o777 == 0o600
    assert (folder/"transaction.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(StateError):
        a.publish_disposable_admission(folder, selected)
    assert not launcher.RUNTIME_ENABLED


def test_runtime_byte_selection_rejects_wrong_digest_and_path(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("root-owned test tree required")
    root = tmp_path / "root"
    dest = root / a.CANDIDATE_ROOT.lstrip("/")
    (dest/"bin").mkdir(parents=True)
    (dest/"bin/host-discover").write_bytes(b"#!/bin/sh\nexit 0\n")
    (dest/"bin/python3.12").write_bytes(b"synthetic python selection")
    for x in (dest/"bin/host-discover", dest/"bin/python3.12"):
        x.chmod(0o755)
    one = hashlib.sha256((dest/"bin/host-discover").read_bytes()).hexdigest()
    two = hashlib.sha256((dest/"bin/python3.12").read_bytes()).hexdigest()
    out = a.select_runtime(a.CANDIDATE_EXECUTABLE, a.CANDIDATE_PYTHON,
                           one, two, fs_root=str(root), disposable=True)
    assert out["executable_sha256"] == one
    with pytest.raises(StateError):
        a.select_runtime(a.CANDIDATE_EXECUTABLE, a.CANDIDATE_PYTHON,
                         "0"*64, two, fs_root=str(root), disposable=True)


def test_bundle_builder_preserves_original_host_and_directory_root_selection():
    from test_state_directory_runtime import BASE, ROOT_UUID, ROOT_PARTUUID
    from test_state_account_migration import HOST_UUID, FINGERPRINT
    built = a.assemble_migration_bundle(
        BASE,
        installation_id="b31db5af-20bb-4eb5-9755-e9ceba393198",
        state_volume_id="2e91d838-093a-4ae2-9c2a-a6162d13c0a4",
        installation_record_id="abf76c5d-7626-478e-b5ed-59a77ddf27ac",
        authorization_id="4c6ba68c-3477-4bdf-8dc5-bd52aad4f983",
        root_fs_uuid=ROOT_UUID, root_partuuid=ROOT_PARTUUID,
        host_uuid=HOST_UUID, fingerprint=FINGERPRINT,
        registry_origin="https://host-registry.hosts.zog-network-demo.uk")
    assert built["bootstrap"]["mode"] == "migration"
    assert built["installation"]["operation"] == "migration"
    assert built["marker"]["kind"] == "zog-state-directory"
    assert built["bootstrap"]["initialization"]["expected_host_uuid"] == HOST_UUID
    assert built["bootstrap"]["state"]["filesystem_uuid"] == ROOT_UUID
    assert built["bootstrap"]["state"]["marker_sha256"] == digest(built["marker"])
    assert BASE["bootstrap"]["mode"] == "fresh"


def test_bundle_builder_denies_reused_or_unselected_identifiers():
    from test_state_directory_runtime import BASE, ROOT_UUID, ROOT_PARTUUID
    from test_state_account_migration import HOST_UUID, FINGERPRINT
    inputs = {
        "installation_id": "b31db5af-20bb-4eb5-9755-e9ceba393198",
        "state_volume_id": "2e91d838-093a-4ae2-9c2a-a6162d13c0a4",
        "installation_record_id": "abf76c5d-7626-478e-b5ed-59a77ddf27ac",
        "authorization_id": "4c6ba68c-3477-4bdf-8dc5-bd52aad4f983",
        "root_fs_uuid": ROOT_UUID, "root_partuuid": ROOT_PARTUUID,
        "host_uuid": HOST_UUID, "fingerprint": FINGERPRINT,
        "registry_origin": "https://host-registry.hosts.zog-network-demo.uk",
    }
    bad = dict(inputs, state_volume_id=inputs["installation_id"])
    with pytest.raises(StateError):
        a.assemble_migration_bundle(BASE, **bad)
    bad = dict(inputs, registry_origin="http://untrusted.invalid")
    with pytest.raises(StateError):
        a.assemble_migration_bundle(BASE, **bad)
