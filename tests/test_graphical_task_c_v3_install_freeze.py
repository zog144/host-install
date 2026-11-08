"""Exact three-owner v3 source freeze: synthetic approvals, real module bytes.

No tests mount /state, publish a wheel to an installed Host or grant SSM.
The RECORD fixtures are source consistency checks, not installed attestation.
"""
import base64
import copy
import csv
import hashlib
import importlib.util
import io
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.host_install import graphical_task_c_v3_install_freeze as freeze
from zog.host_install import graphical_readonly_trust_broker_install as broker
from zog.host_install.state_contract import digest as state_digest, validate
from zog.root_control import graphical_task_c_trust_authority as root
from zog.root_control import graphical_installation_storage_authority as storage
from zog.root_control import graphical_operation_owner_source as op
from zog.host_deploy.gateway import graphics_owner_trust_install as gateway
from test_graphical_registry_storage_installation import (
    signed_install_fixture, fixture as registered_fixture)
from test_graphical_task_c_local_identity import selected_local
from test_graphics_owner_trust_v3_install import selection as gateway_fixture

BASE = Path(__file__).resolve().parents[1]
NONRESIDENT = __import__("json").loads(
    (BASE/"examples/non-resident-state-v1/bundle.json").read_text())


def wheel_record(modules):
    """Synthetic PEP 427 RECORD fixture for exact, checked module bytes."""
    output=io.StringIO()
    writer=csv.writer(output,lineterminator="\n")
    for name, data in sorted(modules.items()):
        digest=base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        writer.writerow((name.replace(".","/")+".py",
                         "sha256="+digest,str(len(data))))
    return output.getvalue().encode("utf-8")


def files_for(names):
    return {name: Path(importlib.util.find_spec(name).origin).read_bytes()
            for name in sorted(names)}


def configuration(backend,state_fs_uuid,install_uuid=None,state_uuid=None):
    b=copy.deepcopy(NONRESIDENT)
    if install_uuid:
        b["installation"]["installation_id"]=install_uuid
        b["bootstrap"]["installation_id"]=install_uuid
        b["marker"]["installation_id"]=install_uuid
    if state_uuid:
        b["bootstrap"]["state"]["state_volume_id"]=state_uuid
        b["marker"]["state_volume_id"]=state_uuid
    b["marker"]["filesystem_uuid"]=state_fs_uuid
    b["bootstrap"]["state"]["filesystem_uuid"]=state_fs_uuid
    if backend=="root-directory":
        b["marker"].update(schema=2,kind="zog-state-directory",backing_root="/")
        b["bootstrap"]["state"].update(
            storage_backend="root-directory",filesystem_type="directory")
    b["installation"]["installer_recorded"]["marker_sha256"]=state_digest(
        b["marker"])
    b["bootstrap"]["state"]["marker_sha256"]=state_digest(b["marker"])
    b["bootstrap"]["installation_record"]["sha256"]=state_digest(
        b["installation"])
    validate(b)
    return b


def selected(backend="root-directory",local=False):
    roots=files_for(root.ROOT_V3_SOURCES)
    gateways=files_for(gateway.SOURCES)
    states=files_for(freeze.STATE_SOURCES)
    owner=(BASE/"src/zog/host_install/systemd/zog-graphical-owner.service").read_bytes()
    owner_sock=(BASE/"src/zog/host_install/systemd/zog-graphical-owner.socket").read_bytes()
    service=(BASE/"src/zog/host_install/systemd/zog-graphical-trust.service").read_bytes()
    socket=(BASE/"src/zog/host_install/systemd/zog-graphical-trust.socket").read_bytes()
    if local:
        row=selected_local()
        identity=row["registry"]
        authority=row["authority"]
        approval=row["grant"]
        operator=row["operator"]
        registry_public=None
        signer=Ed25519PrivateKey.generate()
        pub=signer.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        mount=registered_fixture()[2]
        mount["state_fs_uuid"]=row["receipt"]["state_fs_uuid"]
        mount.update(
            mode="provision-separately-approved-new-scope",
            host_id=identity["host_id"],
            installation_id=identity["installation_id"],
            state_volume_id=identity["state_volume_id"],
            scope_sha256=authority["installation_scope_sha256"],
            original_record_sha256=None,
            external_authorization_sha256=op.digest(approval),
        )
        receipt={**{
            k:v for k,v in row["receipt"].items()
            if k!="signature_ed25519"},
            "state_fs_uuid":mount["state_fs_uuid"],
            "ledger_fs_uuid":mount["mounts"][0]["filesystem_uuid"],
            "authority_fs_uuid":mount["mounts"][1]["filesystem_uuid"],
            "owner_unit_sha256":freeze.sha(owner),
            "broker_unit_sha256":freeze.sha(service)}
        receipt["signature_ed25519"]=base64.b64encode(signer.sign(
            __import__("zog.root_control.graphical_installation_storage_commit",
                       fromlist=["DOMAIN"]).DOMAIN+op.canonical(receipt))).decode("ascii")
        config=configuration(backend,mount["state_fs_uuid"],
            identity["host_install_installation_uuid"],
            identity["host_install_state_uuid"])
        config["bootstrap"]["registries"]=[]
        config["bootstrap"]["control_authority"]=None
        validate(config)
        anchor=authority["anchor_identity_sha256"]
    else:
        state,receipt,pub,_=signed_install_fixture()
        selection,source,mount,*_=state
        identity=source["registry"]
        authority=source["authority"]
        approval=source["grant"]
        operator=source["operator"]
        registry_public=source["registrar"]
        anchor=source["anchor"]
        config=configuration(backend,mount["state_fs_uuid"])
    p=copy.deepcopy(mount)
    gateway_row=list(gateway_fixture())
    gateway_selection=gateway_row[0]
    gateway_selection.update(
        root_source_sha256=freeze.source_digest(roots),
        native_host_install_source_sha256=freeze.source_digest({
            k: states[k] for k in gateway.HOST_INSTALL_V2_SOURCES}),
        original_checkpoint_sha256=op.digest(authority),
        registry_sha256=authority["registry_sha256"],
        installation_scope_sha256=authority["installation_scope_sha256"],
        storage_commit_sha256=op.digest(receipt),
        source_modules_sha256=freeze.source_digest(gateways),
        installed_gateway_source_sha256=freeze.source_digest(gateways),
        service_sha256=freeze.sha(service),
        socket_sha256=freeze.sha(socket),
        host_id=identity["host_id"],installation_id=identity["installation_id"],
        state_volume_id=identity["state_volume_id"],
        readonly_checkpoint_role_arn=authority["checkpoint_reader_role_arn"],
        owner_checkpoint_write_role_arn=authority["checkpoint_writer_role_arn"],
    )
    records={key:wheel_record(raw) for key,raw in (
        ("root",roots),("gateway",gateways),("state",states))}
    freeze_selection={
        "schema":freeze.SCHEMA,
        "root_revision":freeze.ROOT_HEAD,
        "gateway_revision":freeze.GATEWAY_HEAD,
        "state_revision":freeze.STATE_HEAD,
        "state_backend":backend,
        "root_sources_sha256":freeze.source_digest(roots),
        "gateway_sources_sha256":freeze.source_digest(gateways),
        "state_sources_sha256":freeze.source_digest(states),
        "root_record_sha256":freeze.sha(records["root"]),
        "gateway_record_sha256":freeze.sha(records["gateway"]),
        "state_record_sha256":freeze.sha(records["state"]),
        "owner_service_sha256":freeze.sha(owner),
        "owner_socket_sha256":freeze.sha(owner_sock),
        "broker_service_sha256":freeze.sha(service),
        "broker_socket_sha256":freeze.sha(socket),
        "mount_plan_sha256":freeze.sha(op.canonical(p)),
        "storage_scope_sha256":authority["installation_scope_sha256"],
        "storage_approval_sha256":op.digest(approval),
        "storage_commit_sha256":op.digest(receipt),
        "read_only_role_arn":authority["checkpoint_reader_role_arn"],
        "writer_role_arn":authority["checkpoint_writer_role_arn"],
        "owner_ssm_role_arn":gateway_selection["owner_ssm_role_arn"],
        **{key:False for key in freeze.DISABLED},
    }
    return {
        "selection":freeze_selection,"root_modules":roots,
        "gateway_modules":gateways,"state_modules":states,
        "root_record":records["root"],
        "gateway_record":records["gateway"],
        "state_record":records["state"],
        "owner_service":owner,"owner_socket":owner_sock,
        "broker_service":service,"broker_socket":socket,
        "state_bundle":config,"mount_plan":p,
        "gateway_selection":gateway_selection,
        "storage_registry":identity,
        "pinned_registry_public":registry_public,
        "storage_authority":authority,
        "signed_storage_approval":approval,
        "pinned_operator_public":operator,
        "retained_anchor_sha256":anchor,
        "signed_install_commit":receipt,
        "pinned_installer_public":pub,
        "retained_install_commit_sha256":op.digest(receipt),
        "now":100000,
    }


@pytest.mark.parametrize("backend",("mounted-volume","root-directory"))
@pytest.mark.parametrize("local",(False,True))
def test_v3_exact_three_owner_selection_has_no_activation(backend,local):
    record=selected(backend,local)
    result=freeze.review_disabled_v3_freeze(**record)
    assert result["status"]==freeze.STATUS
    assert result["state_backend"]==backend
    assert all(result[key] is False for key in (
        "native_state_accepted","native_mounts_accepted",
        "native_wheel_record_accepted","native_credential_accepted",
        "owner_active","broker_active","ssm_authorized"))


@pytest.mark.parametrize("tamper",(
    "root_bytes","gateway_bytes","state_bytes","root_record","gateway_record",
    "state_record","owner_service","owner_socket","broker_service",
    "broker_socket","wrong_root_pin","wrong_gateway_pin","wrong_state_pin",
    "directory_switch","same_protected_mount","state_mount_collision",
    "unapproved_claim","swapped_reader_writer","broker_owner_ssm",
    "retained_commit","approval_signature","installed_boolean",
    "wrong_local_install_uuid","wrong_local_state_uuid","legacy_downshift",
    "gateway_scope","gateway_root_snapshot",
    "unexpected_local_enrollment","reused_state_partuuid",
))
def test_three_owner_freeze_denies_source_or_identity_substitution(tamper):
    row=selected("root-directory",local=True)
    if tamper=="root_bytes":
        key=next(iter(row["root_modules"]))
        row["root_modules"][key]+=b"\n# replacement"
    elif tamper=="gateway_bytes":
        key=next(iter(row["gateway_modules"]))
        row["gateway_modules"][key]+=b"\n# replacement"
    elif tamper=="state_bytes":
        row["state_modules"]["zog.host_install.state_inspect"]+=b"\n# replaced"
    elif tamper in ("root_record","gateway_record","state_record"):
        row[tamper]+=b"\nincorrect,line,extra"
    elif tamper in ("owner_service","owner_socket","broker_service","broker_socket"):
        row[tamper]+=b"\n# unselected"
    elif tamper=="wrong_root_pin":
        row["selection"]["root_revision"]="0"*40
    elif tamper=="wrong_gateway_pin":
        row["selection"]["gateway_revision"]="0"*40
    elif tamper=="wrong_state_pin":
        row["selection"]["state_revision"]="0"*40
    elif tamper=="directory_switch":
        row["selection"]["state_backend"]="mounted-volume"
    elif tamper=="same_protected_mount":
        row["mount_plan"]["mounts"][1]["filesystem_uuid"]=(
            row["mount_plan"]["mounts"][0]["filesystem_uuid"])
    elif tamper=="state_mount_collision":
        row["mount_plan"]["mounts"][1]["filesystem_uuid"]=(
            row["mount_plan"]["state_fs_uuid"])
    elif tamper=="unapproved_claim":
        row["signed_storage_approval"]["expires_at"]=1
    elif tamper=="swapped_reader_writer":
        row["selection"]["read_only_role_arn"]=(
            row["selection"]["writer_role_arn"])
    elif tamper=="broker_owner_ssm":
        row["gateway_selection"]["readonly_checkpoint_role_arn"]=(
            row["gateway_selection"]["owner_ssm_role_arn"])
    elif tamper=="retained_commit":
        row["signed_install_commit"]["accepted_at"]+=1
    elif tamper=="approval_signature":
        row["signed_storage_approval"]["signature_ed25519"]="AA=="
    elif tamper=="installed_boolean":
        row["selection"]["native_state_accepted"]=True
    elif tamper=="wrong_local_install_uuid":
        row["storage_registry"]["host_install_installation_uuid"]=(
            "44444444-4444-4444-8444-444444444444")
    elif tamper=="wrong_local_state_uuid":
        row["storage_registry"]["host_install_state_uuid"]=(
            "44444444-4444-4444-8444-444444444444")
    elif tamper=="legacy_downshift":
        row["pinned_registry_public"]=b"0"*32
    elif tamper=="gateway_scope":
        row["gateway_selection"]["installation_scope_sha256"]="sha256:"+"e"*64
    elif tamper=="gateway_root_snapshot":
        row["gateway_selection"]["root_source_sha256"]="sha256:"+"d"*64
    elif tamper=="unexpected_local_enrollment":
        row["state_bundle"]["bootstrap"]["registries"]=copy.deepcopy(
            NONRESIDENT["bootstrap"]["registries"])
        row["state_bundle"]["bootstrap"]["control_authority"]=copy.deepcopy(
            NONRESIDENT["bootstrap"]["control_authority"])
    elif tamper=="reused_state_partuuid":
        row["mount_plan"]["mounts"][0]["block_partuuid"]=(
            row["state_bundle"]["bootstrap"]["state"]["partition_partuuid"])
    with pytest.raises((broker.BrokerInstallHeld,ValueError)):
        freeze.review_disabled_v3_freeze(**row)


def test_missing_wheel_record_or_wrong_hash_cannot_select_installer():
    row=selected()
    raw=row["state_record"].decode()
    one=next(iter(row["state_modules"]))
    key=one.replace(".","/")+".py"
    assert key in raw
    for replacement in (raw.replace("sha256=","sha512=",1),
                        raw.replace(key,key+"-renamed",1),
                        raw+raw.splitlines(keepends=True)[0],
                        raw.replace("\n",",\n",1)):
        with pytest.raises(broker.BrokerInstallHeld):
            freeze.verify_wheel_record(replacement.encode(),row["state_modules"])

def test_built_wheels_have_exact_source_bytes_and_real_pep427_record():
    """Optional CI validation against freshly built *uninstalled* wheels."""
    import zipfile
    wheel_dir=os.environ.get("V3_WHEEL_DIR")
    if not wheel_dir:
        pytest.skip("actual wheel build evidence supplied only by pinned CI")
    evidence=selected("root-directory",local=True)
    for key in (
        "root_sources_sha256", "gateway_sources_sha256", "state_sources_sha256",
        "owner_service_sha256", "owner_socket_sha256", "broker_service_sha256",
        "broker_socket_sha256",
    ):
        print("freeze",key+"="+evidence["selection"][key],flush=True)
    for distribution,modules in (
        ("root_control",evidence["root_modules"]),
        ("host_deploy",evidence["gateway_modules"]),
        ("host_install",evidence["state_modules"]),
    ):
        choices=list(Path(wheel_dir).glob(distribution+"-*.whl"))
        assert len(choices)==1,(distribution,choices)
        with zipfile.ZipFile(choices[0]) as archive:
            names=archive.namelist()
            records=[path for path in names if path.endswith(".dist-info/RECORD")]
            assert len(records)==1
            for name,source in modules.items():
                path=name.replace(".","/")+".py"
                assert archive.read(path)==source,(distribution,name)
            digest=freeze.verify_wheel_record(archive.read(records[0]),modules)
            print(distribution,"wheel_sha256="+freeze.sha(choices[0].read_bytes()),
                  "RECORD_sha256="+digest,flush=True)
