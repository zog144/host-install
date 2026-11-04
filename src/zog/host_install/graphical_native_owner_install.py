"""Installed native graphical owner layout and separate AWS authority contract.

Offline readiness validation only; no real STATE provisioning, AWS IAM writes,
credential issuance, systemctl start, key fabrication or role expansion.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

SCHEMA = "zog-graphical-native-owner-install-contract-v1"
ROOT_SOURCE = "zog144/root-control"
SELECTED_ROOT_SHA = "3b16621e5ac56e6052c722d86ab8fc61e2e8320f"
ROOT_MODULES = (
    "zog.root_control.graphical_native_owner",
    "zog.root_control.graphical_owner_checkpoint",
    "zog.root_control.graphical_owner_service",
    "zog.root_control.graphical_task_c_owner",
    "zog.root_control.graphical_task_c_service",
)
SOCKET = "/run/zog/graphical-operation-owner.sock"
OWNER_CONFIG = "/etc/zog/graphical-owner/installation.json"
LEDGER = "/var/lib/zog-graphical-owner-ledger"
CHECKPOINT = "/var/lib/zog-graphical-owner-checkpoint"
CREDS = "/var/lib/zog-graphical-owner-credential-source/aws-session.json"
CRED_MOUNT = "/run/credentials/zog-graphical-owner.service/aws-session.json"
SERVICE = "zog-graphical-owner.service"
SOCKET_UNIT = "zog-graphical-owner.socket"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class InstallationHold(ValueError):
    pass


def hold():
    raise InstallationHold("protected graphical native owner installation not admitted")


def validate_install_contract(row):
    if (type(row) is not dict or set(row) != {
            "schema", "root_source_revision", "root_modules",
            "host_id", "installation_id", "state_volume_id", "boot_id",
            "owner_identity", "gateway_identity", "gateway_uid", "gateway_gid",
            "root_uid", "socket", "socket_mode", "socket_group",
            "ledger", "checkpoint", "credential_source", "credential_target",
            "gateway_state_mount", "separate_mounts_verified",
            "source_record_verified", "operator_identity_approved",
            "gateway_iam_explicit_deny_verified",
            "gateway_imds_and_sts_denial_verified",
            "owner_aws_session_separate_verified",
            "nonrollbackable_highwater_verified",
            "status", "socket_enabled", "service_enabled", "ssm_admitted"} or
            row["schema"] != SCHEMA or
            type(row["root_source_revision"]) is not str or
            not HEX40.fullmatch(row["root_source_revision"]) or
            row["root_source_revision"] != SELECTED_ROOT_SHA or
            row["root_modules"] != list(ROOT_MODULES) or
            any(type(row[k]) is not str or not HEX64.fullmatch(row[k])
                for k in ("host_id", "installation_id","state_volume_id")) or
            type(row["boot_id"]) is not str or not row["boot_id"] or
            type(row["owner_identity"]) is not str or not row["owner_identity"] or
            type(row["gateway_identity"]) is not str or not row["gateway_identity"] or
            row["owner_identity"] == row["gateway_identity"] or
            row["root_uid"] != 0 or
            type(row["gateway_uid"]) is not int or row["gateway_uid"] < 1000 or
            type(row["gateway_gid"]) is not int or row["gateway_gid"] < 1 or
            row["socket"] != SOCKET or row["socket_mode"] != "0660" or
            row["socket_group"] != "zog-graphical-client" or
            row["ledger"] != LEDGER or row["checkpoint"] != CHECKPOINT or
            row["credential_source"] != CREDS or
            row["credential_target"] != CRED_MOUNT or
            type(row["gateway_state_mount"]) is not str or
            not row["gateway_state_mount"].startswith("/") or
            row["gateway_state_mount"] in (LEDGER,CHECKPOINT) or
            row["status"] != "NOT_ACTIVATED" or
            row["socket_enabled"] is not False or
            row["service_enabled"] is not False or
            row["ssm_admitted"] is not False):
        hold()
    gates = (
        "separate_mounts_verified", "source_record_verified",
        "operator_identity_approved", "gateway_iam_explicit_deny_verified",
        "gateway_imds_and_sts_denial_verified",
        "owner_aws_session_separate_verified",
        "nonrollbackable_highwater_verified",
    )
    if any(type(row[k]) is not bool for k in gates):
        hold()
    if any(row[k] for k in gates):
        # No caller can represent an unexecuted native gate as successful.
        # Native Work must provide independently authenticated receipts
        # through a separate privileged installation/activation operation.
        hold()
    return json.loads(json.dumps(row,sort_keys=True))


def verify_unit_sources(service, socket_unit):
    """Fail closed on a unit that silently enables service or broad SSM auth."""
    required_service=(
        "User=root", "Group=root",
        "ExecStart=/usr/bin/python3 -I -m zog.root_control.graphical_task_c_service",
        "LoadCredential=aws-session.json:"+CREDS,
        "RequiresMountsFor="+LEDGER+" "+CHECKPOINT,
        "NoNewPrivileges=yes", "ProtectSystem=strict",
        "ReadWritePaths="+LEDGER+" "+CHECKPOINT,
        "CapabilityBoundingSet=", "Sockets="+SOCKET_UNIT,
    )
    required_socket=(
        "ListenStream="+SOCKET,
        "SocketUser=root", "SocketGroup=zog-graphical-client",
        "SocketMode=0660", "Service="+SERVICE, "Accept=no",
    )
    if (type(service) is not str or type(socket_unit) is not str or
            any(x not in service.splitlines() for x in required_service) or
            any(x not in socket_unit.splitlines() for x in required_socket) or
            "EnvironmentFile=" in service or "AWS_PROFILE=" in service or
            "ExecStartPost=" in service or "WantedBy=" in service or
            "WantedBy=" in socket_unit or
            "Accept=yes" in socket_unit or
            "ListenSequentialPacket=" in socket_unit or
            "/run/zog/graphical-owner.sock" in socket_unit or
            "zog.root_control.graphical_owner_service" in service):
        hold()
    return "protected-source-units-reviewed-not-enabled"


def required_gateway_denial():
    # This is a testable *minimum IAM policy*. Merely generating the JSON
    # does not apply or verify the actual role's identity policy, permissions
    # boundary, STS trust policies, IMDS access or AWS resource policies.
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid":"DenyGraphicalGatewayDirectSSMAndEscalation",
            "Effect":"Deny",
            "Action":["ssm:SendCommand","sts:AssumeRole","iam:PassRole"],
            "Resource":"*",
        }],
    }


def verify_gateway_denial_policy(policy):
    if policy != required_gateway_denial():
        hold()
    return {"status": "policy-source-reviewed-not-applied",
            "aws_iam_verified": False, "native_service_enabled": False}


def inspect_installed_evidence(*, manifest, installed_root_sha256, units,
                               mount_identities, aws_identity):
    """Read-only synthetic input contract; no self-issued native PASS."""
    validate_install_contract(manifest)
    if (type(installed_root_sha256) is not dict or
            set(installed_root_sha256) != set(ROOT_MODULES) or
            any(type(v) is not str or not HEX64.fullmatch(v)
                for v in installed_root_sha256.values()) or
            type(units) is not dict or set(units) != {SERVICE,SOCKET_UNIT} or
            type(mount_identities) is not dict or
            set(mount_identities) != {"gateway","ledger","checkpoint"} or
            len(set(mount_identities.values())) != 3 or
            type(aws_identity) is not dict or
            set(aws_identity) != {"gateway_principal", "owner_principal",
                                 "gateway_send_denied", "owner_only_session"} or
            aws_identity["gateway_principal"] == aws_identity["owner_principal"]):
        hold()
    verify_unit_sources(units[SERVICE], units[SOCKET_UNIT])
    if (aws_identity["gateway_send_denied"] is not False or
            aws_identity["owner_only_session"] is not False):
        # A synthetic inspector must not mint authority from supplied booleans.
        hold()
    return {"status": "native-owner-installation-evidence-source-only",
            "enabled": False, "installed_source_accepted": False,
            "external_highwater_accepted": False, "aws_send_admitted": False}
