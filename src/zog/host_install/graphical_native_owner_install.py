"""Disabled Task C protected owner source installation and IAM boundary.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.
Strict offline selection; no STATE creation, AWS changes, credential issuance,
systemctl activation or self-issued native evidence is permitted.
"""
from __future__ import annotations

import json
import re

SCHEMA = "zog-graphical-native-owner-install-contract-v2"
ROOT_SOURCE = "zog144/root-control"
SELECTED_ROOT_SHA = "5ad7d5ed72d1b72edc767a658de28506791a74d4"
ROOT_MODULES = (
    "zog.root_control.graphical_operation_owner_source",
    "zog.root_control.graphical_native_owner",
    "zog.root_control.graphical_owner_service",
    "zog.root_control.graphical_s3_checkpoint",
    "zog.root_control.graphical_task_c_owner",
    "zog.root_control.graphical_task_c_origin",
    "zog.root_control.graphical_task_c_runtime",
    "zog.root_control.graphical_task_c_native",
    "zog.root_control.graphical_task_c_service",
)
SOCKET = "/run/zog/graphical-operation-owner.sock"
OWNER_CONFIG = "/etc/zog/graphical-owner/task-c-runtime.json"
OPERATOR_PIN = "/etc/zog/graphical-owner/operator-public.key"
ORIGIN_ISSUER_PIN = "/etc/zog/graphical-owner/origin-issuer-public.key"
ORIGIN_EVIDENCE = "/etc/zog/graphical-owner/original-github-evidence.json"
OBSERVATION_PRIVATE = "/etc/zog/graphical-owner/observation-private.key"
LEDGER = "/var/lib/zog-graphical-owner-ledger"
CHECKPOINT = "s3-append-only-v1"
CREDS = "/var/lib/zog-graphical-owner-credential-source/aws-session.json"
CRED_MOUNT = "/run/credentials/zog-graphical-owner.service/aws-session.json"
CHECKPOINT_CREDS = "/var/lib/zog-graphical-owner-credential-source/checkpoint-session.json"
CHECKPOINT_CRED_MOUNT = "/run/credentials/zog-graphical-owner.service/checkpoint-session.json"
SERVICE = "zog-graphical-owner.service"
SOCKET_UNIT = "zog-graphical-owner.socket"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@-]{1,64}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
INSTANCE = re.compile(r"i-[a-f0-9]{16,17}\Z")


class InstallationHold(ValueError):
    pass


def hold():
    raise InstallationHold("protected graphical Task C installation remains disabled")


def _match(v, pattern):
    return type(v) is str and pattern.fullmatch(v) is not None


def validate_install_contract(row):
    expected = {
        "schema", "root_source_revision", "root_modules",
        "host_id", "installation_id", "state_volume_id", "boot_id",
        "owner_identity", "gateway_identity", "gateway_uid", "gateway_gid",
        "gateway_cgroup", "gateway_executable_sha256",
        "root_uid", "socket", "socket_mode", "socket_group",
        "ledger", "checkpoint", "gateway_state_mount", "owner_config",
        "operator_pin", "origin_issuer_pin", "origin_evidence",
        "observation_private", "credential_source", "credential_target",
        "checkpoint_credential_source", "checkpoint_credential_target",
        "checkpoint_policy", "ssm_policy",
        "operator_public_sha256", "origin_issuer_public_sha256",
        "origin_evidence_sha256", "observation_public_sha256",
        "separate_mounts_verified", "source_record_verified",
        "original_github_verified", "operator_identity_approved",
        "gateway_iam_explicit_deny_verified",
        "gateway_imds_and_sts_denial_verified",
        "owner_aws_session_separate_verified",
        "nonrollbackable_highwater_verified", "checkpoint_iam_verified",
        "status", "socket_enabled", "service_enabled", "ssm_admitted",
    }
    if (type(row) is not dict or set(row) != expected
            or row["schema"] != SCHEMA
            or row["root_source_revision"] != SELECTED_ROOT_SHA
            or row["root_modules"] != list(ROOT_MODULES)
            or any(not _match(row[k], HEX64)
                   for k in ("host_id", "installation_id", "state_volume_id"))
            or type(row["boot_id"]) is not str or not row["boot_id"]
            or type(row["owner_identity"]) is not str
            or not row["owner_identity"]
            or type(row["gateway_identity"]) is not str
            or not row["gateway_identity"]
            or row["owner_identity"] == row["gateway_identity"]
            or row["root_uid"] != 0
            or type(row["gateway_uid"]) is not int or row["gateway_uid"] < 1000
            or type(row["gateway_gid"]) is not int or row["gateway_gid"] < 1
            or type(row["gateway_cgroup"]) is not str
            or not row["gateway_cgroup"].startswith("/system.slice/")
            or not row["gateway_cgroup"].endswith(".service")
            or row["socket"] != SOCKET or row["socket_mode"] != "0660"
            or row["socket_group"] != "zog-graphical-client"
            or row["ledger"] != LEDGER or row["checkpoint"] != CHECKPOINT
            or type(row["gateway_state_mount"]) is not str
            or not row["gateway_state_mount"].startswith("/")
            or row["gateway_state_mount"] == LEDGER
            or any(row[field] != value for field, value in (
                ("owner_config", OWNER_CONFIG),
                ("operator_pin", OPERATOR_PIN),
                ("origin_issuer_pin", ORIGIN_ISSUER_PIN),
                ("origin_evidence", ORIGIN_EVIDENCE),
                ("observation_private", OBSERVATION_PRIVATE),
                ("credential_source", CREDS),
                ("credential_target", CRED_MOUNT),
                ("checkpoint_credential_source", CHECKPOINT_CREDS),
                ("checkpoint_credential_target", CHECKPOINT_CRED_MOUNT)))
            or any(not _match(row[k], SHA) for k in (
                "gateway_executable_sha256", "operator_public_sha256",
                "origin_issuer_public_sha256", "origin_evidence_sha256",
                "observation_public_sha256"))
            or row["status"] != "NOT_ACTIVATED"
            or row["socket_enabled"] is not False
            or row["service_enabled"] is not False
            or row["ssm_admitted"] is not False):
        hold()

    checkpoint, ssm = row["checkpoint_policy"], row["ssm_policy"]
    if (type(checkpoint) is not dict or set(checkpoint) != {
                "bucket","prefix","account_id","region","genesis_sha256","role_arn"}
            or type(ssm) is not dict or set(ssm) != {
                "account_id","region","instance_id","role_arn"}
            or type(checkpoint["bucket"]) is not str or
            not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",checkpoint["bucket"])
            or type(checkpoint["prefix"]) is not str
            or not re.fullmatch(r"[a-z0-9/-]{1,160}",checkpoint["prefix"])
            or not checkpoint["prefix"].endswith("/")
            or "//" in checkpoint["prefix"]
            or not _match(checkpoint["genesis_sha256"], SHA)
            or not _match(checkpoint["region"], REGION)
            or not _match(ssm["region"], REGION)
            or not _match(ssm["instance_id"], INSTANCE)
            or not _match(checkpoint["role_arn"], ROLE)
            or not _match(ssm["role_arn"], ROLE)
            or checkpoint["role_arn"] == ssm["role_arn"]
            or not _match(checkpoint["account_id"], re.compile(r"[0-9]{12}\Z"))
            or checkpoint["account_id"] != ssm["account_id"]
            or checkpoint["region"] != ssm["region"]
            or checkpoint["role_arn"].split(":")[4] != checkpoint["account_id"]
            or ssm["role_arn"].split(":")[4] != ssm["account_id"]):
        hold()
    gates = (
        "separate_mounts_verified", "source_record_verified",
        "original_github_verified", "operator_identity_approved",
        "gateway_iam_explicit_deny_verified",
        "gateway_imds_and_sts_denial_verified",
        "owner_aws_session_separate_verified",
        "nonrollbackable_highwater_verified", "checkpoint_iam_verified",
    )
    if any(type(row[k]) is not bool or row[k] is not False for k in gates):
        # Caller-supplied True cannot mint a trusted native acceptance receipt.
        hold()
    return json.loads(json.dumps(row, sort_keys=True))


def verify_unit_sources(service, socket_unit):
    """Require single disabled stream owner and two separate private sessions."""
    required_service = (
        "User=root", "Group=root",
        "ExecStart=/usr/bin/python3 -I -m zog.root_control.graphical_task_c_service",
        "LoadCredential=aws-session.json:" + CREDS,
        "LoadCredential=checkpoint-session.json:" + CHECKPOINT_CREDS,
        "RequiresMountsFor=" + LEDGER,
        "ReadWritePaths=" + LEDGER,
        "NoNewPrivileges=yes", "ProtectSystem=strict",
        "CapabilityBoundingSet=", "Sockets=" + SOCKET_UNIT,
    )
    required_socket = (
        "ListenStream=" + SOCKET,
        "SocketUser=root", "SocketGroup=zog-graphical-client",
        "SocketMode=0660", "Service=" + SERVICE, "Accept=no",
    )
    if (type(service) is not str or type(socket_unit) is not str
            or any(v not in service.splitlines() for v in required_service)
            or any(v not in socket_unit.splitlines() for v in required_socket)
            or {x for x in service.splitlines() if x.startswith("LoadCredential=")}
               != {required_service[3], required_service[4]}
            or "EnvironmentFile=" in service or "AWS_PROFILE=" in service
            or "ExecStartPost=" in service or "WantedBy=" in service
            or "WantedBy=" in socket_unit
            or "Accept=yes" in socket_unit
            or "ListenSequentialPacket=" in socket_unit
            or "/run/zog/graphical-owner.sock" in socket_unit
            or "zog.root_control.graphical_owner_service" in service
            or "/var/lib/zog-graphical-owner-checkpoint" in service
            or "[Install]" in service or "[Install]" in socket_unit):
        hold()
    return "protected-source-units-reviewed-not-enabled"


def required_gateway_denial():
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyGraphicalGatewayDirectSSMAndEscalation",
            "Effect": "Deny",
            "Action": ["ssm:SendCommand", "sts:AssumeRole", "iam:PassRole"],
            "Resource": "*",
        }],
    }


def verify_gateway_denial_policy(policy):
    if policy != required_gateway_denial():
        hold()
    return {"status":"policy-source-reviewed-not-applied",
            "aws_iam_verified":False, "native_service_enabled":False}


def inspect_installed_evidence(*, manifest, installed_root_sha256, units,
                               mount_identities, aws_identity):
    """No synthetic manifest or boolean authorizes installation or SSM."""
    validate_install_contract(manifest)
    if (type(installed_root_sha256) is not dict
            or set(installed_root_sha256) != set(ROOT_MODULES)
            or any(not _match(v, HEX64)
                   for v in installed_root_sha256.values())
            or type(units) is not dict
            or set(units) != {SERVICE, SOCKET_UNIT}
            or type(mount_identities) is not dict
            or set(mount_identities) != {"gateway", "ledger"}
            or mount_identities["gateway"] == mount_identities["ledger"]
            or type(aws_identity) is not dict
            or set(aws_identity) != {
                "gateway_principal", "checkpoint_principal",
                "ssm_principal", "gateway_send_denied",
                "gateway_checkpoint_denied", "owner_only_session"}
            or len({aws_identity["gateway_principal"],
                    aws_identity["checkpoint_principal"],
                    aws_identity["ssm_principal"]}) != 3):
        hold()
    verify_unit_sources(units[SERVICE], units[SOCKET_UNIT])
    if any(aws_identity[k] is not False for k in (
            "gateway_send_denied", "gateway_checkpoint_denied",
            "owner_only_session")):
        hold()
    return {"status": "native-owner-installation-evidence-source-only",
            "enabled": False, "installed_source_accepted": False,
            "external_highwater_accepted": False, "aws_send_admitted": False}
