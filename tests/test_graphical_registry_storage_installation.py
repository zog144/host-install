"""Source-only registry-installed storage; no block device or AWS changes."""
from pathlib import Path
import copy
import pytest

from zog.host_install import graphical_registry_storage_installation as i
from zog.host_install import graphical_readonly_trust_broker_install as broker
from test_graphical_protected_storage_admission import fixture as mount_fixture
from test_graphical_installation_storage_authority import selected as root_fixture

ROOT=Path(__file__).resolve().parents[1]
UPSTREAM=ROOT/"companions/root-control"


def fixture():
    source=root_fixture()
    request=source["request"]
    mount=mount_fixture()
    mount.update(
        mode="provision-separately-approved-new-scope",
        host_id=request["host_id"],
        installation_id=request["installation_id"],
        state_volume_id=request["state_volume_id"],
        scope_sha256=source["authority"]["installation_scope_sha256"],
        original_record_sha256=None,
        external_authorization_sha256=
            __import__("zog.root_control.graphical_operation_owner_source",
                       fromlist=["digest"]).digest(source["grant"]),
    )
    scope=(UPSTREAM/"src/zog/root_control/graphical_installation_storage_authority.py").read_bytes()
    checkpoint=(UPSTREAM/"src/zog/root_control/graphical_s3_installation_checkpoint.py").read_bytes()
    owner=(ROOT/"src/zog/host_install/systemd/zog-graphical-owner.service").read_bytes()
    trust=(ROOT/"src/zog/host_install/systemd/zog-graphical-trust.service").read_bytes()
    manifest={
        "schema":i.SCHEMA, "mode":i.MODE,
        **{k:source["registry"][k] for k in (
            "host_id","installation_id","state_volume_id",
            "registry_id","controller_id")},
        "registry_sha256":source["authority"]["registry_sha256"],
        "installation_scope_sha256":
            source["authority"]["installation_scope_sha256"],
        "root_storage_source_sha256":i.digest(scope),
        "root_checkpoint_source_sha256":i.digest(checkpoint),
        "signed_storage_approval_sha256":
            mount["external_authorization_sha256"],
        "anchor_identity_sha256":source["anchor"],
        "owner_unit_sha256":i.digest(owner),
        "broker_unit_sha256":i.digest(trust),
        "native_mounts_accepted":False,
        "native_storage_accepted":False,
        "owner_credentials_accepted":False,
        "ipc_accepted":False,
    }
    return manifest,source,mount,scope,checkpoint,owner,trust


def review(row):
    manifest,selected,mount,scope,checkpoint,owner,trust=row
    return i.review_registry_bound_storage(
        manifest,
        registered_installation=selected["registry"],
        pinned_registry_public=selected["registrar"],
        proposed_authority=selected["authority"],
        storage_approval=selected["grant"],
        pinned_operator_public=selected["operator"],
        independently_retained_anchor_sha256=selected["anchor"],
        mount_plan=mount,
        root_scope_module=scope, root_checkpoint_module=checkpoint,
        owner_unit=owner, broker_unit=trust, now=400)


def test_installer_selects_stable_registry_scope_before_approval():
    m=fixture()
    result=review(m)
    assert result["status"]==i.SOURCE_ONLY
    assert result["native_mounts_accepted"] is False
    assert result["native_storage_accepted"] is False
    assert result["owner_credentials_accepted"] is False
    assert result["ipc_accepted"] is False
    assert set(result["mount_unit_candidates"])=={
        "var-lib-zog-graphical-owner-ledger.mount",
        "var-lib-zog-graphical-owner-authority.mount"}
    assert m[0]["installation_scope_sha256"]==m[2]["scope_sha256"]


@pytest.mark.parametrize("tamper", (
    "wrong_scope", "wrong_registry", "wrong_mount_scope", "historical_adoption",
    "same_fs", "changed_owner_unit", "changed_broker_unit", "changed_root_source",
    "wrong_anchor", "wrong_grant", "owner_active", "ipc_claimed",
    "requires_in_service", "broker_missing_authority_mount",
))
def test_manifest_or_unit_replacement_fails_closed(tamper):
    m=list(fixture())
    selection,proof,plan,scope,checkpoint,owner,trust=m
    if tamper=="wrong_scope":
        selection["installation_scope_sha256"]="sha256:"+"f"*64
    elif tamper=="wrong_registry":
        selection["registry_id"]="e"*32
    elif tamper=="wrong_mount_scope":
        plan["scope_sha256"]="sha256:"+"f"*64
    elif tamper=="historical_adoption":
        plan["mode"]="adopt-existing-original"
    elif tamper=="same_fs":
        plan["mounts"][1]["filesystem_uuid"]=plan["mounts"][0]["filesystem_uuid"]
    elif tamper=="changed_owner_unit":
        m[5]+=b"\nReadWritePaths=/state"
    elif tamper=="changed_broker_unit":
        m[6]+=b"\nExecStart=/tmp/replaced"
    elif tamper=="changed_root_source":
        m[3]+=b"\n"
    elif tamper=="wrong_anchor":
        proof["anchor"]="sha256:"+"0"*64
    elif tamper=="wrong_grant":
        proof["grant"]["signature_ed25519"]="garbage"
    elif tamper=="owner_active":
        selection["owner_credentials_accepted"]=True
    elif tamper=="ipc_claimed":
        selection["ipc_accepted"]=True
    elif tamper=="requires_in_service":
        m[5]=owner.replace(
            b"RequiresMountsFor=/var/lib/zog-graphical-owner-ledger\n",b"")
        m[5]+=b"\nRequiresMountsFor=/var/lib/zog-graphical-owner-ledger"
        selection["owner_unit_sha256"]=i.digest(m[5])
    elif tamper=="broker_missing_authority_mount":
        m[6]=trust.replace(
            b"RequiresMountsFor=/var/lib/zog-graphical-owner-authority\n",b"")
        selection["broker_unit_sha256"]=i.digest(m[6])
    with pytest.raises(broker.BrokerInstallHeld):
        review(m)
