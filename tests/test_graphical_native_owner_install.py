"""Source-only host-install contract for selected graphical root owner."""
from pathlib import Path
import copy
import pytest
from zog.host_install import graphical_native_owner_install as contract

ROOT=Path(__file__).resolve().parents[1]

def row():
    return {
        "schema":contract.SCHEMA,
        "root_source_revision":"3caa4d1c6fcfb5f52a81ed701f8e0ad609406599",
        "root_modules":list(contract.ROOT_MODULES),
        "host_id":"a"*64,"installation_id":"b"*64,"state_volume_id":"c"*64,
        "boot_id":"boot-test-not-native",
        "owner_identity":"root-graphical-sender-only",
        "gateway_identity":"unprivileged-ssm-denied-gateway",
        "gateway_uid":1200,"gateway_gid":1210,
        "root_uid":0,"socket":contract.SOCKET,
        "socket_mode":"0660","socket_group":"zog-graphical-client",
        "ledger":contract.LEDGER,"checkpoint":contract.CHECKPOINT,
        "credential_source":contract.CREDS,
        "credential_target":contract.CRED_MOUNT,
        "gateway_state_mount":"/state",
        "separate_mounts_verified":False,
        "source_record_verified":False,
        "operator_identity_approved":False,
        "gateway_iam_explicit_deny_verified":False,
        "gateway_imds_and_sts_denial_verified":False,
        "owner_aws_session_separate_verified":False,
        "nonrollbackable_highwater_verified":False,
        "status":"NOT_ACTIVATED","socket_enabled":False,
        "service_enabled":False,"ssm_admitted":False
    }

def unit_texts():
    d=ROOT/"src/zog/host_install/systemd"
    return {"zog-graphical-owner.service":
            (d/"zog-graphical-owner.service").read_text(),
            "zog-graphical-owner.socket":
            (d/"zog-graphical-owner.socket").read_text()}

def test_disabled_native_owner_contract_source_handoff():
    source=contract.validate_install_contract(row())
    assert source["status"]=="NOT_ACTIVATED"
    assert contract.verify_unit_sources(*(
        unit_texts()[k] for k in (
        "zog-graphical-owner.service","zog-graphical-owner.socket"))) == (
        "protected-source-units-reviewed-not-enabled")
    evidence=contract.inspect_installed_evidence(
        manifest=source,
        installed_root_sha256={x:"b"*64 for x in contract.ROOT_MODULES},
        units=unit_texts(),
        mount_identities={"gateway":"one","ledger":"two","checkpoint":"three"},
        aws_identity={"gateway_principal":"gateway-user",
                      "owner_principal":"protected-owner-role",
                      "gateway_send_denied":False,
                      "owner_only_session":False})
    assert evidence["native_service_enabled"] is False if "native_service_enabled" in evidence else evidence["enabled"] is False
    assert evidence["aws_send_admitted"] is False

@pytest.mark.parametrize("key,value",[
    ("root_uid",1000),("gateway_uid",0),("gateway_gid",0),
    ("owner_identity","unprivileged-ssm-denied-gateway"),
    ("socket","/tmp/gateway-picked.sock"),
    ("socket_mode","0666"),("socket_group","gateway"),
    ("ledger","/state/gateway-ledger"),
    ("checkpoint","/state/gateway-ledger"),
    ("credential_source","/home/gateway/.aws"),
    ("credential_target","/tmp/shared-aws.json"),
    ("status","READY"),("socket_enabled",True),
    ("service_enabled",True),("ssm_admitted",True),
    ("gateway_iam_explicit_deny_verified",True),
    ("gateway_imds_and_sts_denial_verified",True),
    ("nonrollbackable_highwater_verified",True),
    ("operator_identity_approved",True),
    ("root_source_revision","0"*40),
])
def test_untrusted_installer_selection_and_premature_authority_denied(key,value):
    attempt=row();attempt[key]=value
    with pytest.raises(contract.InstallationHold):
        contract.validate_install_contract(attempt)

def test_separate_iam_policy_refuses_ssm_sts_and_passrole():
    p=contract.required_gateway_denial()
    result=contract.verify_gateway_denial_policy(p)
    assert result["aws_iam_verified"] is False
    for action in ("ssm:SendCommand","sts:AssumeRole","iam:PassRole"):
        attempt=copy.deepcopy(p)
        attempt["Statement"][0]["Action"].remove(action)
        with pytest.raises(contract.InstallationHold):
            contract.verify_gateway_denial_policy(attempt)
    p["Statement"][0]["Effect"]="Allow"
    with pytest.raises(contract.InstallationHold):
        contract.verify_gateway_denial_policy(p)

def test_service_cannot_be_automatically_enabled_or_use_ambient_aws():
    units=unit_texts()
    service=units["zog-graphical-owner.service"]
    socket=units["zog-graphical-owner.socket"]
    for altered in (service+"\nWantedBy=multi-user.target",
                    service+"\nEnvironmentFile=/home/gateway/aws",
                    service.replace("User=root","User=host-deploy"),
                    service.replace("LoadCredential=","# LoadCredential="),
                    service.replace("ReadWritePaths=","# ReadWritePaths=")):
        with pytest.raises(contract.InstallationHold):
            contract.verify_unit_sources(altered,socket)
    for altered in (socket.replace("SocketMode=0660","SocketMode=0666"),
                    socket.replace("SocketGroup=zog-graphical-client",
                                   "SocketGroup=users"),
                    socket+"\nWantedBy=sockets.target"):
        with pytest.raises(contract.InstallationHold):
            contract.verify_unit_sources(service,altered)

def test_same_disk_both_owner_domains_not_accepted():
    x=row()
    with pytest.raises(contract.InstallationHold):
        contract.inspect_installed_evidence(
            manifest=x,
            installed_root_sha256={z:"b"*64 for z in contract.ROOT_MODULES},
            units=unit_texts(),
            mount_identities={"gateway":"one","ledger":"two",
                              "checkpoint":"two"},
            aws_identity={"gateway_principal":"gateway-user",
                          "owner_principal":"protected-owner",
                          "gateway_send_denied":False,
                          "owner_only_session":False})


def test_only_task_c_stream_unix_endpoint_is_selected():
    units=unit_texts()
    service=units[contract.SERVICE]
    socket=units[contract.SOCKET_UNIT]
    assert contract.SOCKET=="/run/zog/graphical-operation-owner.sock"
    assert "ListenStream="+contract.SOCKET in socket
    assert "Accept=no" in socket
    assert "ListenSequentialPacket=" not in socket
    assert "zog.root_control.graphical_task_c_service" in service
    assert "zog.root_control.graphical_owner_service" not in service
    assert "WantedBy=" not in service+socket
    assert contract.verify_unit_sources(service,socket).endswith("not-enabled")


@pytest.mark.parametrize("legacy",(
    "ListenSequentialPacket=/run/zog/graphical-owner.sock",
    "ListenStream=/run/zog/graphical-owner.sock",
    "ListenSequentialPacket=/run/zog/graphical-operation-owner.sock",
))
def test_previous_unreviewed_owner_socket_is_rejected(legacy):
    units=unit_texts()
    socket=units[contract.SOCKET_UNIT]
    fixed="ListenStream="+contract.SOCKET
    with pytest.raises(contract.InstallationHold):
        contract.verify_unit_sources(
            units[contract.SERVICE],socket.replace(fixed,legacy))


def test_single_task_c_installed_service_cannot_select_legacy_seqpacket_sender():
    units=unit_texts()
    with pytest.raises(contract.InstallationHold):
        contract.verify_unit_sources(
            units[contract.SERVICE].replace(
                "zog.root_control.graphical_task_c_service",
                "zog.root_control.graphical_owner_service"),
            units[contract.SOCKET_UNIT])


def test_task_c_source_contract_requires_original_identity_and_owner_signed_mapping():
    # This tests installed source *selection*, not authentic Work evidence.
    assert "zog.root_control.graphical_task_c_owner" in contract.ROOT_MODULES
    assert "zog.root_control.graphical_task_c_service" in contract.ROOT_MODULES
    selection=contract.validate_install_contract(row())
    assert not selection["service_enabled"] and not selection["ssm_admitted"]
    assert not selection["source_record_verified"]
    assert not selection["nonrollbackable_highwater_verified"]
