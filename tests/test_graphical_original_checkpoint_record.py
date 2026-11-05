"""Original Task C checkpoint record continuation/reinitialization regressions.

All records/roles/identities are synthetic, never a real installed checkpoint.
"""
import copy
import json
import os
from pathlib import Path
import pytest

from zog.host_install import graphical_original_checkpoint_record as record
from zog.host_install import graphical_native_owner_install as owner
from test_graphical_native_owner_install import row

SCOPE = "sha256:" + "7"*64

def fresh(tmp_path):
    root = tmp_path / "protected-owner-ledger"
    root.mkdir(mode=0o700)
    return root, row()

def first(root, manifest, scope=SCOPE):
    return record.reserve_original_checkpoint(root, manifest,
        independently_selected_scope_sha256=scope, explicit_first_install=True)

def resume(root, manifest, scope=SCOPE):
    return record.continue_original_checkpoint(root, manifest,
        independently_selected_scope_sha256=scope)

def test_first_install_durable_exact_continuation_without_record_rewrite(tmp_path):
    root, manifest = fresh(tmp_path)
    assert first(root, manifest)["install_authorized"] is False
    before = (root/record.RECORD).read_bytes()
    inode = (root/record.RECORD).stat().st_ino
    assert resume(root, manifest)["status"] == "ORIGINAL_CHECKPOINT_CONTINUATION_MATCH_UNACCEPTED"
    assert resume(root, manifest)["ssm_authorized"] is False
    assert (root/record.RECORD).read_bytes() == before
    assert (root/record.RECORD).stat().st_ino == inode
    with pytest.raises(owner.InstallationHold):
        first(root, manifest)

@pytest.mark.parametrize("field,value",[
    ("account_id","999999999999"),
    ("region","eu-west-1"),
    ("bucket","different-original-checkpoint"),
    ("prefix","fixture/different/"),
    ("genesis_sha256","sha256:"+"8"*64),
    ("role_arn","arn:aws:iam::123456789012:role/OtherCheckpointRole"),
])
def test_substituted_original_checkpoint_parameters_fail_even_if_valid(field,value,tmp_path):
    root, manifest = fresh(tmp_path)
    first(root, manifest)
    changed = copy.deepcopy(manifest)
    changed["checkpoint_policy"][field] = value
    if field == "account_id":
        changed["ssm_policy"]["account_id"] = value
        changed["checkpoint_policy"]["role_arn"] = (
            "arn:aws:iam::999999999999:role/FixtureCheckpointRole")
        changed["ssm_policy"]["role_arn"] = (
            "arn:aws:iam::999999999999:role/FixtureSsmSenderRole")
    if field == "region":
        changed["ssm_policy"]["region"] = value
    with pytest.raises(owner.InstallationHold):
        resume(root, changed)

@pytest.mark.parametrize("field",["host_id","installation_id","state_volume_id"])
def test_changed_host_installation_state_denied(field,tmp_path):
    root, manifest = fresh(tmp_path)
    first(root, manifest)
    changed = copy.deepcopy(manifest)
    changed[field] = "d"*64
    with pytest.raises(owner.InstallationHold):
        resume(root,changed)

def test_original_scope_cannot_be_selected_from_replacement_gateway_request(tmp_path):
    root, manifest = fresh(tmp_path)
    first(root, manifest)
    with pytest.raises(owner.InstallationHold):
        resume(root, manifest, "sha256:" + "9"*64)

@pytest.mark.parametrize("missing",["record","reservation","both"])
def test_missing_original_record_never_initializes_on_continuation(tmp_path,missing):
    root, manifest=fresh(tmp_path)
    first(root,manifest)
    if missing in ("record","both"):
        (root/record.RECORD).unlink()
    if missing in ("reservation","both"):
        (root/record.RESERVATION).unlink()
    with pytest.raises(owner.InstallationHold):
        resume(root,manifest)
    if missing != "both":
        with pytest.raises(owner.InstallationHold):
            first(root,manifest)
    # If BOTH original native files are removed by a privileged administrator,
    # a local first-install API cannot prove historical existence. Work must
    # bind the retained Host installation to an independent immutable witness.

def test_interrupted_reservation_blocks_retry_and_resume(tmp_path):
    root, manifest=fresh(tmp_path)
    source=record._selected(manifest,original_scope_sha256=SCOPE)
    fd=record._directory(root)
    try:
        import hashlib
        record._write_exclusive(fd,record.RESERVATION,{
            "schema":record.RESERVATION_SCHEMA,
            "identity_sha256":"sha256:"+hashlib.sha256(record._canonical(source)).hexdigest()})
    finally:os.close(fd)
    with pytest.raises(owner.InstallationHold):
        resume(root,manifest)
    with pytest.raises(owner.InstallationHold):
        first(root,manifest)

@pytest.mark.parametrize("change",["mode","symlink","hardlink","bytes","duplicate"])
def test_tampered_or_unsafe_durable_record_denied(change,tmp_path):
    root,manifest=fresh(tmp_path)
    first(root,manifest)
    path=root/record.RECORD
    if change=="mode":
        path.chmod(0o644)
    elif change=="symlink":
        path.unlink();path.symlink_to(root/record.RESERVATION)
    elif change=="hardlink":
        os.link(path,root/"copied")
    elif change=="bytes":
        data=json.loads(path.read_text())
        data["checkpoint_bucket"]="another-bucket"
        path.write_text(json.dumps(data,sort_keys=True,separators=(",",":")))
    elif change=="duplicate":
        text=path.read_text()
        path.write_text(text[:-1]+',"checkpoint_bucket":"another-bucket"}')
    with pytest.raises(owner.InstallationHold):
        resume(root,manifest)

def test_no_auto_initialization_or_missing_directory(tmp_path):
    root,manifest=fresh(tmp_path)
    with pytest.raises(owner.InstallationHold):
        resume(root,manifest)
    with pytest.raises(owner.InstallationHold):
        record.reserve_original_checkpoint(root,manifest,
            independently_selected_scope_sha256=SCOPE)
    root.rmdir()
    with pytest.raises(owner.InstallationHold):
        first(root,manifest)
