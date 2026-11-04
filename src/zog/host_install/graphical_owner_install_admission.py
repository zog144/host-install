"""Fail-closed host-install graphical owner native-install admission manifest.

Not a privileged installer. An effective IAM policy, real process credentials
and independently durable authority cannot be established by a JSON manifest.
No function creates storage, starts services or approves an SSM send.
"""
from __future__ import annotations
import re
import stat

SCHEMA="zog-graphical-owner-native-install-admission-v1"
ROOT_OWNER_SOURCE="ad5985ee602f24cbb5d45ef259c31d6c5a13e386"
ROOT_LEDGER_CANDIDATE="664245a573e28383b7c64b7fec235c8ed5cffb19"
DEPLOY_HANDOFF_SOURCE="c3e597f09965680587c97dbe6f7b5ee18d52e9a9"
FIELDS={"schema","enabled","native_accepted","root_owner_source",
        "ledger_source","gateway_handoff_source","host_id",
        "installation_id","state_volume_id","authority_epoch",
        "socket_path","socket_uid","socket_gid","socket_mode",
        "owner_binary_sha256","owner_unit_sha256","owner_wheel_record_sha256",
        "gateway_uid","gateway_gid","owner_uid","owner_gid",
        "gateway_aws_principal","owner_aws_principal",
        "owner_role_trust_identity","gateway_ssm_allowed",
        "gateway_assume_owner_allowed","gateway_imds_owner_allowed",
        "owner_send_document_arn","owner_target_instance_id",
        "independent_ledger_storage_id","external_highwater_pin_sha256",
        "operator_public_pin_sha256","original_operation_map_sha256",
        "real_gateway_send_denial_receipt","real_gateway_sts_denial_receipt",
        "owner_send_acceptance_receipt"}
HEX64=re.compile(r"[0-9a-f]{64}\Z")
AWS_ROLE=re.compile(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+\Z")
SSM_DOC=re.compile(r"arn:aws:ssm:[a-z0-9-]+:[0-9]{12}:document/[A-Za-z0-9_.-]+\Z")
INSTANCE=re.compile(r"i-[a-f0-9]{8,17}\Z")

class NativeGraphicalHold(ValueError):pass
def deny(msg):raise NativeGraphicalHold(msg)

def validate_disabled_install_manifest(item):
    if type(item) is not dict or set(item)!=FIELDS or item["schema"]!=SCHEMA:
        deny("missing exact protected graphical owner installer fields")
    for field,expected in (("enabled",False),("native_accepted",False),
                           ("gateway_ssm_allowed",False),
                           ("gateway_assume_owner_allowed",False),
                           ("gateway_imds_owner_allowed",False),
                           ("socket_path","/run/zog/graphical-operation-owner.sock"),
                           ("root_owner_source",ROOT_OWNER_SOURCE),
                           ("ledger_source",ROOT_LEDGER_CANDIDATE),
                           ("gateway_handoff_source",DEPLOY_HANDOFF_SOURCE),
                           ("socket_uid",0),("socket_mode",0o660),
                           ("owner_uid",0),("owner_gid",0)):
        if item[field]!=expected:deny("unselected privileged source or send boundary: "+field)
    if (type(item["gateway_uid"]) is not int or item["gateway_uid"]<=0
            or type(item["gateway_gid"]) is not int or item["gateway_gid"]<=0
            or type(item["socket_gid"]) is not int or item["socket_gid"]<=0
            or type(item["authority_epoch"]) is not int or item["authority_epoch"]<1):
        deny("missing separate gateway and privileged owner account")
    for name in ("host_id","installation_id","state_volume_id",
                 "owner_binary_sha256","owner_unit_sha256",
                 "owner_wheel_record_sha256","independent_ledger_storage_id",
                 "external_highwater_pin_sha256","operator_public_pin_sha256",
                 "original_operation_map_sha256"):
        if type(item[name]) is not str or not HEX64.fullmatch(item[name]):
            deny("missing exact installed identity/pin: "+name)
    if (type(item["gateway_aws_principal"]) is not str
            or not AWS_ROLE.fullmatch(item["gateway_aws_principal"])
            or type(item["owner_aws_principal"]) is not str
            or not AWS_ROLE.fullmatch(item["owner_aws_principal"])
            or item["owner_aws_principal"]==item["gateway_aws_principal"]
            or type(item["owner_role_trust_identity"]) is not str
            or not HEX64.fullmatch(item["owner_role_trust_identity"])
            or type(item["owner_send_document_arn"]) is not str
            or not SSM_DOC.fullmatch(item["owner_send_document_arn"])
            or type(item["owner_target_instance_id"]) is not str
            or not INSTANCE.fullmatch(item["owner_target_instance_id"])):
        deny("owner and gateway IAM principals are not independently selected")
    # Never accept self-reported IAM success or identity. Only a native Work
    # actor can make these receipts available after actual STS/IAM/IMDS probes.
    for key in ("real_gateway_send_denial_receipt",
                "real_gateway_sts_denial_receipt","owner_send_acceptance_receipt"):
        if item[key] is not None:deny("fabricated native SSM acceptance evidence")
    return {"status":"DISABLED_SOURCE_MANIFEST_ONLY",
            "install_authorized":False,"service_start_authorized":False,
            "ssm_send_authorized":False}
