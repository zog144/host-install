import copy
import pytest
from zog.host_install import graphical_owner_install_admission as admission

def candidate():
    return {
        "schema":admission.SCHEMA,
        "enabled":False,"native_accepted":False,
        "root_owner_source":admission.ROOT_OWNER_SOURCE,
        "ledger_source":admission.ROOT_LEDGER_CANDIDATE,
        "gateway_handoff_source":admission.DEPLOY_HANDOFF_SOURCE,
        "host_id":"a"*64,"installation_id":"b"*64,"state_volume_id":"c"*64,
        "authority_epoch":2,
        "socket_path":"/run/zog/graphical-operation-owner.sock",
        "socket_uid":0,"socket_gid":2346,"socket_mode":0o660,
        "owner_binary_sha256":"d"*64,"owner_unit_sha256":"e"*64,
        "owner_wheel_record_sha256":"f"*64,
        "gateway_uid":2345,"gateway_gid":2345,
        "owner_uid":0,"owner_gid":0,
        "gateway_aws_principal":"arn:aws:iam::123456789012:role/GatewayOnly",
        "owner_aws_principal":"arn:aws:iam::123456789012:role/OwnerOnly",
        "owner_role_trust_identity":"1"*64,
        "gateway_ssm_allowed":False,
        "gateway_assume_owner_allowed":False,
        "gateway_imds_owner_allowed":False,
        "owner_send_document_arn":"arn:aws:ssm:us-east-1:123456789012:document/ZogFixedGraphical",
        "owner_target_instance_id":"i-0123456789abcdef0",
        "independent_ledger_storage_id":"2"*64,
        "external_highwater_pin_sha256":"3"*64,
        "operator_public_pin_sha256":"4"*64,
        "original_operation_map_sha256":"5"*64,
        "real_gateway_send_denial_receipt":None,
        "real_gateway_sts_denial_receipt":None,
        "owner_send_acceptance_receipt":None,
    }

def test_disabled_only_and_no_claimed_native_go():
    result=admission.validate_disabled_install_manifest(candidate())
    assert result["install_authorized"] is False
    assert result["ssm_send_authorized"] is False

@pytest.mark.parametrize("key,value",[
    ("enabled",True),("native_accepted",True),
    ("gateway_ssm_allowed",True),("gateway_assume_owner_allowed",True),
    ("gateway_imds_owner_allowed",True),
    ("gateway_aws_principal","arn:aws:iam::123456789012:role/OwnerOnly"),
    ("owner_aws_principal","arn:aws:iam::123456789012:role/GatewayOnly"),
    ("socket_mode",0o666),("socket_uid",2345),("owner_uid",2345),
    ("gateway_uid",0),("gateway_gid",0),("socket_gid",0),
    ("authority_epoch",0),
    ("owner_binary_sha256","0"*64),
    ("root_owner_source","0"*40),
    ("ledger_source","0"*40),
    ("state_volume_id","0"*64),
    ("independent_ledger_storage_id","missing"),
    ("owner_send_document_arn","AWS-RunShellScript"),
    ("owner_target_instance_id","i-attacker"),
    ("real_gateway_send_denial_receipt",{"status":"denied"}),
    ("owner_send_acceptance_receipt",{"status":"sent"}),
    ("real_gateway_sts_denial_receipt",{"status":"denied"}),
])
def test_all_unsafe_source_or_native_promotions_fail(key,value):
    item=candidate()
    item[key]=value
    with pytest.raises(admission.NativeGraphicalHold):
        admission.validate_disabled_install_manifest(item)

def test_missing_required_boundary_cannot_be_guessed():
    item=candidate()
    del item["owner_role_trust_identity"]
    with pytest.raises(admission.NativeGraphicalHold):
        admission.validate_disabled_install_manifest(item)
