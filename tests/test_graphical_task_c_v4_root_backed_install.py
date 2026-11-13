"""Exact v4 root-backed three-owner source, no disks and no native GO."""
import base64
import copy
import importlib.util
from pathlib import Path

import pytest

from zog.host_install import graphical_task_c_v4_root_backed_install as review
from zog.host_install import graphical_task_c_v3_install_freeze as previous
from zog.root_control import graphical_task_c_root_backed_storage as root
from zog.root_control import graphical_task_c_trust_authority as trust
from zog.root_control import graphical_operation_owner_source as op
from zog.host_deploy.gateway import graphics_owner_trust_install as gateway
from test_graphical_task_c_v3_install_freeze import (
    selected as selected_v3, files_for, wheel_record)
from test_graphical_task_c_root_backed_storage import setup as signed_v4

BASE=Path(__file__).resolve().parents[1]
SYSTEMD=BASE/"src/zog/host_install/systemd"
ROOT_DIR=SYSTEMD/"root-backed"


def selected():
    row=selected_v3("root-directory",False)
    signed=signed_v4()
    owner=(ROOT_DIR/"zog-graphical-owner.service").read_bytes()
    broker=(ROOT_DIR/"zog-graphical-trust.service").read_bytes()
    verifier=(ROOT_DIR/"zog-graphical-owner-storage-verified.service").read_bytes()
    root_modules=files_for(trust.ROOT_V3_SOURCES)
    gateway_modules=files_for(gateway.SOURCES)
    state_modules=files_for(review.STATE_SOURCES)
    receipt_body={k:v for k,v in signed["receipt"].items()
                  if k!="signature_ed25519"}
    receipt_body.update(owner_unit_sha256=review.sha(owner),
                        broker_unit_sha256=review.sha(broker))
    receipt={**receipt_body,
        "signature_ed25519":base64.b64encode(
            signed["installer_private"].sign(
                root.COMMIT_DOMAIN+op.canonical(receipt_body))).decode("ascii")}
    authority=signed["authority"]
    approval=signed["approval"]
    plan={
        "schema":review.PLAN_SCHEMA,"mode":root.MODE,
        "root_filesystem_uuid":authority["root_filesystem_uuid"],
        "ledger_directory":root.LEDGER,
        "authority_directory":root.AUTHORITY,
        "ledger_directory_identity_sha256":
            receipt["ledger_directory_identity_sha256"],
        "authority_directory_identity_sha256":
            receipt["authority_directory_identity_sha256"],
        "installation_scope_sha256":authority["installation_scope_sha256"],
        "external_authorization_sha256":op.digest(approval)}
    gateway_row=row["gateway_selection"]
    gateway_row.update(
        schema=gateway.V4_SCHEMA,
        root_storage_mode=root.MODE,
        root_directory_plan_sha256=review.sha(op.canonical(plan)),
        verified_unit_sha256=review.sha(verifier),
        source_modules_sha256=review.source_digest(gateway_modules),
        installed_gateway_source_sha256=review.source_digest(gateway_modules),
        root_source_sha256=review.source_digest(root_modules),
        native_host_install_source_sha256=review.source_digest({
            name:state_modules[name] for name in gateway.HOST_INSTALL_V2_SOURCES}),
        service_sha256=review.sha(broker),
        original_checkpoint_sha256=op.digest(authority),
        storage_commit_sha256=op.digest(receipt),
        installation_scope_sha256=authority["installation_scope_sha256"],
        registry_sha256=authority["registry_sha256"],
        readonly_checkpoint_role_arn=authority["checkpoint_reader_role_arn"],
        owner_checkpoint_write_role_arn=authority["checkpoint_writer_role_arn"])
    records={name:wheel_record(modules) for name,modules in (
        ("root",root_modules),("gateway",gateway_modules),
        ("state",state_modules))}
    old=row["selection"]
    sel={key:value for key,value in old.items()
         if key not in ("mount_plan_sha256","native_mounts_accepted")}
    sel.update(
        schema=review.SCHEMA,
        root_revision=review.ROOT_HEAD,
        gateway_revision=review.GATEWAY_HEAD,
        state_revision=review.STATE_HEAD,
        root_sources_sha256=review.source_digest(root_modules),
        gateway_sources_sha256=review.source_digest(gateway_modules),
        state_sources_sha256=review.source_digest(state_modules),
        root_record_sha256=review.sha(records["root"]),
        gateway_record_sha256=review.sha(records["gateway"]),
        state_record_sha256=review.sha(records["state"]),
        owner_service_sha256=review.sha(owner),
        broker_service_sha256=review.sha(broker),
        verifier_service_sha256=review.sha(verifier),
        directory_plan_sha256=review.sha(op.canonical(plan)),
        storage_scope_sha256=authority["installation_scope_sha256"],
        storage_approval_sha256=op.digest(approval),
        storage_commit_sha256=op.digest(receipt),
        read_only_role_arn=authority["checkpoint_reader_role_arn"],
        writer_role_arn=authority["checkpoint_writer_role_arn"],
        **{k:False for k in review.DISABLED})
    row.update(
        selection=sel,root_modules=root_modules,gateway_modules=gateway_modules,
        state_modules=state_modules,root_record=records["root"],
        gateway_record=records["gateway"],state_record=records["state"],
        owner_service=owner,broker_service=broker,verifier_service=verifier,
        directory_plan=plan,gateway_selection=gateway_row,
        storage_registry=signed["old"]["registry"],
        pinned_registry_public=signed["old"]["registrar"],
        storage_authority=authority,signed_storage_approval=approval,
        pinned_operator_public=signed["operator"],
        retained_anchor_sha256=signed["old"]["anchor"],
        signed_install_commit=receipt,
        pinned_installer_public=signed["installer"],
        retained_install_commit_sha256=op.digest(receipt))
    row.pop("mount_plan")
    return row


def test_v4_root_backed_source_does_not_require_mounts_or_s3_issuance():
    row=selected()
    result=review.review_disabled_root_backed(**row)
    assert result["status"]==review.STATUS
    assert result["native_directory_accepted"] is False
    assert result["broker_active"] is False
    assert result["ssm_authorized"] is False
    assert root.LEDGER=="/var/lib/zog-owner-ledger"
    assert root.AUTHORITY=="/var/lib/zog-owner-authority"
    assert b"RequiresMountsFor=" not in row["owner_service"]
    assert b"RequiresMountsFor=" not in row["broker_service"]


@pytest.mark.parametrize("attack",(
    "wrong_mode","old_mount_plan","missing_verifier","changed_owner_unit",
    "changed_broker_unit","changed_root_source","changed_gateway_source",
    "changed_state_source","changed_record","changed_local_path",
    "swapped_roles","changed_external_claim","forged_native_result",
    "wrong_install_signature","wrong_commit_digest","wrong_root_uuid",
    "stale_old_v3_commit","missing_state","wrong_state_backend",
))
def test_v4_install_source_fails_closed_on_local_or_external_tamper(attack):
    row=selected()
    if attack=="wrong_mode":
        row["directory_plan"]["mode"]="separate-ebs"
    elif attack=="old_mount_plan":
        row["directory_plan"]["mounts"]=[{"path":root.LEDGER}]
    elif attack=="missing_verifier":
        row["verifier_service"]=b""
    elif attack=="changed_owner_unit":
        row["owner_service"]+=b"\nRequiresMountsFor=/var/lib/zog-owner-ledger\n"
    elif attack=="changed_broker_unit":
        row["broker_service"]+=b"\n# tampered"
    elif attack=="changed_root_source":
        name=next(iter(row["root_modules"]))
        row["root_modules"][name]+=b"\n# changed"
    elif attack=="changed_gateway_source":
        name=next(iter(row["gateway_modules"]))
        row["gateway_modules"][name]+=b"\n# changed"
    elif attack=="changed_state_source":
        name=next(iter(row["state_modules"]))
        row["state_modules"][name]+=b"\n# changed"
    elif attack=="changed_record":
        row["root_record"]+=b"\nunused,data"
    elif attack=="changed_local_path":
        row["directory_plan"]["ledger_directory"]="/state/owner"
    elif attack=="swapped_roles":
        row["gateway_selection"]["readonly_checkpoint_role_arn"]=row[
            "gateway_selection"]["owner_checkpoint_write_role_arn"]
    elif attack=="changed_external_claim":
        row["signed_storage_approval"]["checkpoint_prefix"]="changed/"
    elif attack=="forged_native_result":
        row["selection"]["ssm_authorized"]=True
    elif attack=="wrong_install_signature":
        row["signed_install_commit"]["signature_ed25519"]="AA=="
    elif attack=="wrong_commit_digest":
        row["retained_install_commit_sha256"]="sha256:"+"0"*64
    elif attack=="wrong_root_uuid":
        row["storage_authority"]["root_filesystem_uuid"]="no-uuid"
    elif attack=="stale_old_v3_commit":
        row["signed_install_commit"]["schema"] = (
            "zog-task-c-installation-storage-commit-v1")
    elif attack=="missing_state":
        row["state_bundle"]["bootstrap"]["state"].pop("state_volume_id")
    elif attack=="wrong_state_backend":
        row["selection"]["state_backend"]="wrong"
    with pytest.raises((ValueError, KeyError, TypeError)):
        review.review_disabled_root_backed(**row)


def test_legacy_v3_disabled_installer_cannot_consume_root_backed_plan():
    row=selected()
    row["selection"]["schema"]=previous.SCHEMA
    with pytest.raises((ValueError, KeyError, TypeError)):
        previous.review_disabled_v3_freeze(**{
            key:value for key,value in row.items() if key not in (
                "verifier_service","directory_plan")},
            mount_plan=row["directory_plan"])
