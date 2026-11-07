"""Registrar-signed UUID-to-opaque-ID bridge, never a conversion or native receipt."""
import base64
import copy
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.host_install import graphical_registry_identity_mapping as m
from zog.host_install import graphical_readonly_trust_broker_install as b
from test_graphical_installation_storage_authority import selected

def fixture():
    source=selected()
    registry=source["registry"]
    private=Ed25519PrivateKey.generate()
    pub=private.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    old={
        "host_uuid":"11111111-1111-4111-8111-111111111111",
        "fingerprint":registry["host_fingerprint"][7:],
        "installation_uuid":"22222222-2222-4222-8222-222222222222",
        "state_uuid":"33333333-3333-4333-8333-333333333333",
    }
    evidence={
        "host_uuid":old["host_uuid"],"aws_instance_id":"i-0123456789abcdef0",
        "aws_region":"us-east-1","volume_id":"vol-0123456789abcdef0",
        "filesystem_uuid":"44444444-4444-4444-8444-444444444444",
        "partuuid":"55555555-5555-4555-8555-555555555555",
        "state_receipt_sha256":"sha256:"+"a"*64,
        "mountpoint":"/state","mounted":True,
    }
    body={
        "schema":m.SCHEMA,
        "legacy_host_uuid":old["host_uuid"],
        "legacy_fingerprint":old["fingerprint"],
        "legacy_installation_uuid":old["installation_uuid"],
        "legacy_state_uuid":old["state_uuid"],
        "aws_instance_id":evidence["aws_instance_id"],
        "aws_region":evidence["aws_region"],
        "state_volume_aws_id":evidence["volume_id"],
        "state_filesystem_uuid":evidence["filesystem_uuid"],
        "state_partuuid":evidence["partuuid"],
        "state_receipt_sha256":evidence["state_receipt_sha256"],
        "registered_host_id":registry["host_id"],
        "installation_id":registry["installation_id"],
        "state_volume_id":registry["state_volume_id"],
        "registry_id":registry["registry_id"],
        "controller_id":registry["controller_id"],
        "registry_public_sha256":m.sha(source["registrar"]),
        "registrar_public_sha256":m.sha(pub),
        "signed_registry_sha256":m.sha(m.canonical(registry)),
    }
    signed={**body,"signature_ed25519":base64.b64encode(
        private.sign(m.DOMAIN+m.canonical(body))).decode("ascii")}
    return signed,registry,old,pub,source["registrar"],evidence

def check(state):
    signed,registered,old,pub,registry_pub,evidence=state
    return m.verify_mapping(signed_mapping=signed,
        registered_installation=registered,original_discover_binding=old,
        pinned_registrar_public=pub,pinned_registry_public=registry_pub,
        independently_observed_state=evidence)

def test_native_uuid_fingerprint_mapping_is_explicitly_signed_and_not_native_acceptance():
    result=check(fixture())
    assert result["status"]=="REGISTRY_IDENTITY_MAPPING_SOURCE_VALIDATED_ONLY"
    assert all(v is False for k,v in result.items() if k!="status")

def test_missing_state_cannot_authenticate_selected_registry_host():
    row=list(fixture())
    row[5]=None
    with pytest.raises(b.BrokerInstallHeld):
        check(row)

@pytest.mark.parametrize("change",[
    "wrong_uuid","wrong_fingerprint","changed_opaque_id",
    "wrong_state_volume","wrong_instance","wrong_mount","wrong_fs",
    "wrong_partuuid","other_host_state","wrong_registrar","wrong_registry_key",
    "changed_registry_signature","tampered_signature","unsigned",
    "conversion_attempt","duplicate_key"])
def test_registry_identity_handoff_refuses_unproven_mapping(change):
    row=list(fixture())
    row=[copy.deepcopy(x) for x in row]
    signed,registered,old,pub,registry_pub,evidence=row
    if change=="wrong_uuid":old["host_uuid"]="66666666-6666-4666-8666-666666666666"
    if change=="wrong_fingerprint":old["fingerprint"]="f"*64
    if change=="changed_opaque_id":signed["registered_host_id"]="f"*64
    if change=="wrong_state_volume":evidence["volume_id"]="vol-00000000000000000"
    if change=="wrong_instance":evidence["aws_instance_id"]="i-00000000000000000"
    if change=="wrong_mount":evidence["mountpoint"]="/tmp/borrowed"
    if change=="wrong_fs":evidence["filesystem_uuid"]="66666666-6666-4666-8666-666666666666"
    if change=="wrong_partuuid":evidence["partuuid"]="66666666-6666-4666-8666-666666666666"
    if change=="other_host_state":evidence["host_uuid"]="66666666-6666-4666-8666-666666666666"
    if change=="wrong_registrar":row[3]=b"0"*32
    if change=="wrong_registry_key":row[4]=b"0"*32
    if change=="changed_registry_signature":registered["signature_ed25519"]="AA=="
    if change=="tampered_signature":signed["signature_ed25519"]=base64.b64encode(b"0"*64).decode()
    if change=="unsigned":signed.pop("signature_ed25519")
    if change=="conversion_attempt":signed["registered_host_id"]=old["host_uuid"].replace("-","").ljust(64,"0")
    if change=="duplicate_key":signed["unknown"]=True
    with pytest.raises(b.BrokerInstallHeld):
        check(row)


def test_unsigned_identity_producer_preserves_authentic_legacy_and_v3_ids():
    signed,registry,old,registrar,registry_key,evidence=fixture()
    output=m.prepare_mapping_for_registrar(
        original_discover_binding=old,registered_installation=registry,
        independently_observed_state=evidence,
        pinned_registrar_public=registrar,pinned_registry_public=registry_key)
    assert output["status"]=="UNSIGNED_REGISTRAR_CANDIDATE_ONLY"
    assert output["body"]=={k:v for k,v in signed.items() if k!="signature_ed25519"}
    assert output["domain"]==m.DOMAIN
    assert output["canonical_bytes"]==m.canonical(output["body"])
    assert output["mapping_signed"] is False
    assert output["native_accepted"] is False

def test_unsigned_producer_holds_absent_state_and_false_scope_mapping():
    signed,registry,old,registrar,registry_key,evidence=fixture()
    for changed in (None,{"mountpoint":"/state","mounted":False},
                    {**evidence,"host_uuid":"66666666-6666-4666-8666-666666666666"}):
        with pytest.raises(b.BrokerInstallHeld):
            m.prepare_mapping_for_registrar(
                original_discover_binding=old,registered_installation=registry,
                independently_observed_state=changed,
                pinned_registrar_public=registrar,pinned_registry_public=registry_key)
