"""Opt-in root-directory STATE contract and canonical lifecycle regressions.

Fixtures do not authenticate the retained registry Host. Root-capable tests
exercise a disposable filesystem directory, never /state on the runner.
"""
import copy
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from zog.host_install.state_contract import (
    StateError, canonical, digest, validate,
)
from zog.host_install.state_inspect import assess_root_directory, directory
from zog.host_install import state_provision

ROOT = Path(__file__).resolve().parents[1]
BASE = json.loads((ROOT / "examples/non-resident-state-v1/bundle.json").read_text())
ROOT_UUID = "11111111-1111-4111-8111-111111111111"
ROOT_PARTUUID = "22222222-2222-4222-8222-222222222222"


def directory_bundle():
    b=copy.deepcopy(BASE)
    marker=b["marker"]
    marker.update(schema=2,kind="zog-state-directory",backing_root="/",
                  filesystem_uuid=ROOT_UUID,partition_partuuid=ROOT_PARTUUID)
    state=b["bootstrap"]["state"]
    state.update(storage_backend="root-directory",filesystem_type="directory",
                 filesystem_uuid=ROOT_UUID,partition_partuuid=ROOT_PARTUUID,
                 marker_sha256=digest(marker))
    b["installation"]["installer_recorded"]["marker_sha256"]=digest(marker)
    b["bootstrap"]["installation_record"]["sha256"]=digest(b["installation"])
    return b


def topology():
    rows=[
        {"target":"/","root":"/","type":"ext4","device":"259:1",
         "options":["rw"],"super_options":["rw"]},
    ]
    devices=[{"maj:min":"259:1","type":"part","partuuid":ROOT_PARTUUID,
              "uuid":ROOT_UUID,"fstype":"ext4"}]
    return rows,devices


def test_volume_backend_untouched_and_directory_opt_in():
    volume=copy.deepcopy(BASE)
    validate(volume)
    assert volume["marker"]["kind"]=="zog-state-volume"
    b=directory_bundle()
    assert validate(b) is b
    assert b["bootstrap"]["state"]["filesystem_type"]=="directory"


@pytest.mark.parametrize("tamper", [
    "missing-backend", "wrong-type", "wrong-root", "marker-schema",
    "resident", "changed-fs", "changed-partuuid", "bad-digest",
])
def test_directory_schema_refuses_ambiguous_or_legacy_implicit_conversion(tamper):
    b=directory_bundle()
    if tamper=="missing-backend":del b["bootstrap"]["state"]["storage_backend"]
    elif tamper=="wrong-type":b["bootstrap"]["state"]["filesystem_type"]="ext4"
    elif tamper=="wrong-root":b["marker"]["backing_root"]="/var"
    elif tamper=="marker-schema":b["marker"]["schema"]=1
    elif tamper=="resident":b["installation"]["installation_mode"]="resident"
    elif tamper=="changed-fs":b["bootstrap"]["state"]["filesystem_uuid"]="33333333-3333-4333-8333-333333333333"
    elif tamper=="changed-partuuid":b["bootstrap"]["state"]["partition_partuuid"]="33333333-3333-4333-8333-333333333333"
    elif tamper=="bad-digest":b["bootstrap"]["state"]["marker_sha256"]="0"*64
    with pytest.raises(StateError):
        validate(b)


def test_directory_mount_checks_actual_host_root_and_no_state_mount():
    b=directory_bundle()
    rows,devices=topology()
    out=assess_root_directory(rows,devices,b["bootstrap"]["state"],"259:1")
    assert out["backend"]=="root-directory"
    assert out["device"]=="259:1"


@pytest.mark.parametrize("tamper", [
    "state-mount", "nested-mount", "wrong-root", "wrong-device",
    "ro", "wrong-uuid", "duplicate-partuuid", "root-is-overlay",
])
def test_directory_mount_denies_unproven_backing(tamper):
    b=directory_bundle()
    rows,devices=topology()
    if tamper=="state-mount":rows.append({**rows[0],"target":"/state"})
    elif tamper=="nested-mount":rows.append({**rows[0],"target":"/state/other"})
    elif tamper=="wrong-root":rows[0]["root"]="/subvolume"
    elif tamper=="wrong-device":rows[0]["device"]="259:2"
    elif tamper=="ro":rows[0]["options"]=["ro"]
    elif tamper=="wrong-uuid":devices[0]["uuid"]="33333333-3333-4333-8333-333333333333"
    elif tamper=="duplicate-partuuid":devices.append(dict(devices[0]))
    elif tamper=="root-is-overlay":rows[0]["type"]="overlay"
    with pytest.raises(StateError):
        assess_root_directory(rows,devices,b["bootstrap"]["state"],"259:1")


class Disposable:
    def __init__(self,path):
        self.fd=directory(str(path))
        self.bundle=directory_bundle()
    def recheck(self):
        assert os.fstat(self.fd).st_ino > 0
    def close(self):
        os.close(self.fd)


@pytest.mark.skipif(os.geteuid()!=0,reason="must use root-capable runner to validate layout ownership")
def test_root_capable_mountpoint_creation_is_idempotent_and_no_follow():
    with tempfile.TemporaryDirectory() as tmp:
        parent=Path(tmp)
        rootfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            state_provision.ensure_directory_mountpoint(rootfd)
            state_path=parent/"state"
            assert state_path.is_dir() and not state_path.is_symlink()
            assert state_path.stat().st_uid==0 and state_path.stat().st_mode & 0o777==0o755
            state_provision.ensure_directory_mountpoint(rootfd)
            state_path.rmdir()
            state_path.symlink_to(parent)
            with pytest.raises((StateError, OSError)):
                state_provision.ensure_directory_mountpoint(rootfd)
        finally:
            os.close(rootfd)


@pytest.mark.skipif(os.geteuid()!=0,reason="must use root-capable runner to validate layout ownership")
def test_root_capable_directory_preparation_is_idempotent_and_does_not_create_identity():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)/"selected-state"
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        c=Disposable(root)
        try:
            state_id=c.bundle["bootstrap"]["state"]["state_volume_id"]
            result=state_provision.prepare_tree(c,state_id)
            assert result["identity_created"] is False
            assert (root/".zog-state.json").read_bytes()==canonical(c.bundle["marker"])
            assert (root/".zog-prepared.json").is_file()
            assert not (root/"host-discover/identity").exists()
            state_provision.prepare_tree(c,state_id)
            assert (root/".zog-state.json").read_bytes()==canonical(c.bundle["marker"])
        finally:c.close()


@pytest.mark.skipif(os.geteuid()!=0,reason="must use root-capable runner to validate layout ownership")
def test_root_capable_unmarked_nonempty_directory_and_conflicting_marker_hold():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)/"selected-state"
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        (root/"unrelated-data").write_text("do not adopt")
        c=Disposable(root)
        try:
            with pytest.raises(StateError):
                state_provision.prepare_tree(c,c.bundle["bootstrap"]["state"]["state_volume_id"])
            assert not (root/".zog-state.json").exists()
        finally:c.close()
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)/"selected-state"
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        c=Disposable(root)
        try:
            (root/".zog-state.json").write_bytes(b"foreign")
            os.chmod(root/".zog-state.json",0o444)
            with pytest.raises(StateError):
                state_provision.prepare_tree(c,c.bundle["bootstrap"]["state"]["state_volume_id"])
        finally:c.close()

# A registry is not an installation or boot prerequisite on non-resident Hosts.
# Standalone operation is explicit; an absent registry cannot be upgraded into
# a remote-control grant from an untrusted station status or cached record.
from zog.host_install.state_gate import decide


def standalone_bundle(directory=True):
    b=directory_bundle() if directory else copy.deepcopy(BASE)
    b["bootstrap"]["registries"]=[]
    b["bootstrap"]["control_authority"]=None
    assert validate(b) is b
    return b


def standalone_evidence():
    return {
        "mount_verified":True,"accounts_verified":True,
        "storage_probe":"passed",
        "identity":{"status":"complete","initialization_id":None,
                    "candidates":1,"matches_expected":True},
        "authorization":{
            "verified_current_transaction":False,
            "installation_id":BASE["installation"]["installation_id"],
            "state_volume_id":BASE["bootstrap"]["state"]["state_volume_id"],
            "initialization_id":BASE["bootstrap"]["initialization"]["authorization_id"],
            "action":"none"},
        "schemas":{"identity":1,"trust":1,"control":1,"controller":1},
        "recovery_hold":False,
        "station":{"status":"unavailable","registry_id":None},
    }


@pytest.mark.parametrize("directory", [False,True])
def test_nonresident_local_state_and_identity_need_no_registry_or_external_signer(directory):
    b=standalone_bundle(directory)
    expected={"identity_action":"load-existing","code":"standalone-local-ready",
              "control_allowed":False}
    assert decide(b,standalone_evidence())==expected
    assert b["bootstrap"]["registries"]==[]
    assert b["bootstrap"]["control_authority"] is None


@pytest.mark.parametrize("attack",[
    "managed_authority_without_registry","registry_without_authority",
    "standalone_resident","unexpected_station_session",
    "unexpected_registry_id","wrong_identity","missing_storage",
    "local_recovery_hold","fresh_key_without_authorization",
])
def test_standalone_does_not_infer_management_or_bypass_identity_safety(attack):
    b=standalone_bundle()
    evidence=standalone_evidence()
    if attack=="managed_authority_without_registry":
        b["bootstrap"]["control_authority"]=copy.deepcopy(BASE["bootstrap"]["control_authority"])
    elif attack=="registry_without_authority":
        b["bootstrap"]["registries"]=copy.deepcopy(BASE["bootstrap"]["registries"])
    elif attack=="standalone_resident":
        b["installation"]["installation_mode"]="resident"
    elif attack=="unexpected_station_session":
        evidence["station"]["status"]="fresh"
    elif attack=="unexpected_registry_id":
        evidence["station"]["registry_id"]="primary"
    elif attack=="wrong_identity":
        evidence["identity"]["matches_expected"]=False
    elif attack=="missing_storage":
        evidence["mount_verified"]=False
    elif attack=="local_recovery_hold":
        evidence["recovery_hold"]=True
    elif attack=="fresh_key_without_authorization":
        evidence["identity"]["status"]="absent"
        evidence["identity"]["candidates"]=0
    if attack in (
            "managed_authority_without_registry","registry_without_authority",
            "standalone_resident","unexpected_station_session",
            "unexpected_registry_id"):
        with pytest.raises(StateError):
            decide(b,evidence)
    else:
        assert decide(b,evidence)["control_allowed"] is False
        assert decide(b,evidence)["identity_action"] != "load-existing"

def test_standalone_plan_never_creates_a_mount_or_registrar_prerequisite():
    from zog.host_install.non_resident import build_plan, validate_plan
    from zog.host_install import state_device
    b=standalone_bundle()
    plan=build_plan(b)
    assert validate_plan(plan) is plan
    assert plan["systemd"]["mount_unit"] is None
    assert plan["systemd"]["zog_service_ordering"]["requires"]==[]
    assert plan["state"]["independent_volume"] is False
    assert plan["execution"]["identity_initialization_authorized"] is False
    assert plan["state_initialization"]["policy"]=="explicit-install-transaction"
    for key,value in (
            ("mount_unit",{"name":"state.mount"}),
            ("zog_service_ordering",{"requires":["state.mount"],"after":[],
                                    "binds_to":[],"state_failure_blocks_zog_only":True})):
        altered=copy.deepcopy(plan)
        altered["systemd"][key]=value
        with pytest.raises(StateError):
            validate_plan(altered)
    # The legacy EBS device formatter must not consume a directory selection.
    with pytest.raises(StateError,match="state-backend"):
        state_device.build_plan(
            b,{},[],"serial:fake-disposable","vol-0123456789abcdef0")


@pytest.mark.skipif(os.geteuid()!=0,reason="root-only disposable standalone filesystem acceptance")
def test_root_capable_standalone_layout_and_offline_configuration_need_no_registrar():
    from zog.host_install.state_provision import stage_overlay, prepared_layout
    with tempfile.TemporaryDirectory() as tmp:
        b=standalone_bundle()
        result=stage_overlay(b,Path(tmp)/"overlay")
        assert result["identity_created"] is False
        assert result["slot_selected"] is False
        config=Path(tmp)/"overlay/etc/zog/host-install"
        bootstrap=json.loads((config/"bootstrap.json").read_text())
        assert bootstrap["registries"]==[]
        assert bootstrap["control_authority"] is None
        root=Path(tmp)/"state"
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        c=Disposable(root)
        try:
            c.bundle=b
            state_id=b["bootstrap"]["state"]["state_volume_id"]
            result=state_provision.prepare_tree(c,state_id)
            assert result["identity_created"] is False
            prepared_layout(c)
            state_provision.prepare_tree(c,state_id)
            assert not (root/"host-discover/identity").exists()
        finally:
            c.close()
