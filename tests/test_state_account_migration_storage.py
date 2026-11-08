"""Guarded root-owned migration-only canonical configuration/STATE publication.

Disposable fixtures do not touch /etc, /state, account DB or live identity.
"""
import copy
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_install import state_account_migration as migration
from zog.host_install import state_account_migration_storage as storage
from zog.host_install import state_provision
from zog.host_install.state_account_migration_consumer import CONSUMER_SELECTION
from zog.host_install.state_contract import StateError, canonical
from zog.host_install.state_inspect import directory
from test_state_account_migration import fixture as selected


@pytest.fixture
def prepared(tmp_path):
    if os.geteuid()!=0:
        pytest.skip("root-capable disposable storage fixture")
    data=selected()
    data["consumer_contract"]=dict(CONSUMER_SELECTION)
    plan=migration.review_source_migration(**data)
    root=tmp_path/"nonresident"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    # /state belongs to same temporary filesystem; not an independent mount.
    marker=root/"state"
    marker.mkdir(mode=0o755)
    marker.chmod(0o755)
    journal=tmp_path/"root-transaction.json"
    def phase(stage, *, tamper=None):
        index=migration.STAGES.index(stage)
        value={
            "schema":migration.JOURNAL_SCHEMA,
            "migration_id":plan["migration_id"],
            "plan_sha256":__import__("zog.host_install.state_contract",
                 fromlist=["digest"]).digest(plan),
            "status":"applying","completed":list(migration.STAGES[:index]),
            "active":stage,
        }
        if tamper is not None:value.update(tamper)
        journal.write_bytes(canonical(value))
        journal.chmod(0o600)
        return os.open(journal,os.O_RDONLY|os.O_NOFOLLOW)
    return data,plan,root,marker,phase


def test_publish_schema2_migration_configuration_and_layout_no_new_key(prepared):
    row,plan,root,state,phase=prepared
    fd=phase("canonical-configuration-published")
    try:
        result=storage.publish_migration_configuration(
            row["bundle"],plan,fd,disposable_root=root)
        assert result["status"]=="migration-configuration-published"
        assert result["native_accepted"] is False
        storage.publish_migration_configuration(
            row["bundle"],plan,fd,disposable_root=root)
    finally:os.close(fd)
    config=root/"etc/zog/host-install"
    for name in ("accounts","bootstrap","installation"):
        assert (config/(name+".json")).read_bytes()==canonical(
            row["bundle"][name])
    statefd=directory(str(state))
    context=SimpleNamespace(fd=statefd,bundle=row["bundle"],
                            mount={"backend":"root-directory"},
                            recheck=lambda:None)
    fd=phase("state-layout-prepared")
    try:
        result=storage.prepare_migration_layout(
            context,row["bundle"]["bootstrap"]["state"]["state_volume_id"],
            plan,fd)
        assert result["identity_created"] is False
        assert result["control_authorized"] is False
        storage.prepare_migration_layout(
            context,row["bundle"]["bootstrap"]["state"]["state_volume_id"],
            plan,fd)
    finally:os.close(fd);os.close(statefd)
    assert (state/".zog-state.json").read_bytes()==canonical(
        row["bundle"]["marker"])
    assert (state/".zog-prepared.json").exists()
    assert not (state/"host-discover/identity").exists()
    assert (state/"host-install/installations"/
            (row["bundle"]["installation"]["record_id"]+".json")).exists()


@pytest.mark.parametrize("tamper",(
    "wrong-stage","wrong-migration","wrong-digest","pending-rollback",
    "incomplete-prefix","foreign-state","unknown-record",
))
def test_migration_root_publication_rejects_unverified_stage(prepared,tamper):
    row,plan,root,state,phase=prepared
    selected_stage="canonical-configuration-published"
    changed={}
    if tamper=="wrong-stage":selected_stage="state-layout-prepared"
    elif tamper=="wrong-migration":changed["migration_id"]=(str(
        __import__("uuid").uuid4()))
    elif tamper=="wrong-digest":changed["plan_sha256"]="0"*64
    elif tamper=="pending-rollback":changed["status"]="rolling-back"
    elif tamper=="incomplete-prefix":changed["completed"]=[]
    elif tamper=="foreign-state":
        row["bundle"]["bootstrap"]["state"]["filesystem_uuid"]=str(
            __import__("uuid").uuid4())
    elif tamper=="unknown-record":
        (root/"etc/zog/host-install").mkdir(parents=True)
        (root/"etc/zog/host-install"/"foreign.json").write_text("unexpected")
    fd=phase(selected_stage,tamper=changed)
    try:
        with pytest.raises(StateError):
            storage.publish_migration_configuration(
                row["bundle"],plan,fd,disposable_root=root)
    finally:os.close(fd)


def test_direct_fresh_provisioner_cannot_initialize_migration(prepared):
    row,plan,root,state,phase=prepared
    statefd=directory(str(state))
    context=SimpleNamespace(fd=statefd,bundle=row["bundle"],
                            mount={"backend":"root-directory"},
                            recheck=lambda:None)
    try:
        with pytest.raises(StateError,match="volume-initialization-required"):
            state_provision.prepare_tree(
                context,row["bundle"]["bootstrap"]["state"]["state_volume_id"])
    finally:os.close(statefd)
    assert not (state/".zog-state.json").exists()
