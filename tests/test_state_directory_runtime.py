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
