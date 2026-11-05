"""Disabled source selection of independently protected Task C trust broker.

The source validator cannot install a wheel, attest its RECORD, authorize an
original operation, select a live gateway, create pins or grant AWS rights.
All positive native decisions remain with independently authenticated Work.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

OWNER_SOURCE = "5ad7d5ed72d1b72edc767a658de28506791a74d4"
ROOT_PROVIDER_SOURCE = "c8d654c0d6eb29a692ab30e1ad604a76b5d4d754"
BROKER_SOURCE = "76416b9d7ef64aac17b75b6ce06b98244fd487e0"
SCHEMA = "zog-task-c-readonly-broker-disabled-selection-v1"
ROOT_MODULE = "zog.root_control.graphical_task_c_trust_authority"
ROOT_AUTHORITY = "/var/lib/zog-graphical-owner-authority"
ORIGINAL_LEDGER = "/var/lib/zog-graphical-owner-ledger"
ORIGINAL_ANCHOR = ROOT_AUTHORITY + "/original-checkpoint-installation.external-anchor"
APPROVED_PIN = ROOT_AUTHORITY + "/trust-broker-approval.json"
GATEWAY_PUBLIC_PIN = "/etc/zog/graphical-owner/gateway-trust-pin.json"
SIGNER_SOURCE = "/etc/zog/graphical-owner/trust-broker-private.key"
READ_SOURCE = "/var/lib/zog-graphical-trust-credential-source/read-only-checkpoint.json"
SIGNER_TARGET = "/run/credentials/zog-graphical-trust.service/broker-private.key"
READ_TARGET = "/run/credentials/zog-graphical-trust.service/read-only-checkpoint.json"
BROKER_PYTHON = "/opt/zog/graphical-trust/venv/bin/python3"
SERVICE = "zog-graphical-trust.service"
SOCKET = "zog-graphical-trust.socket"
SOCKET_PATH = "/run/zog/graphical-owner-trust.sock"

ROOT = Path(__file__).resolve().parents[4]
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9_+=,.@-]{1,64}\Z")
FIELDS = frozenset((
    "schema", "original_owner_source", "root_provider_source",
    "broker_source", "original_checkpoint_sha256", "approved_pin_sha256",
    "broker_purpose_approval_sha256", "root_provider_module_sha256",
    "broker_source_module_sha256", "broker_service_sha256",
    "broker_socket_sha256", "broker_wheel_record_sha256",
    "root_wheel_record_sha256", "original_anchor_path",
    "broker_purpose_approval_path", "gateway_public_pin_path",
    "broker_signer_source", "broker_signer_target",
    "readonly_session_source", "readonly_session_target",
    "broker_python", "readonly_role_arn", "writer_role_arn",
    "ssm_role_arn", "state", "socket_enabled", "service_enabled",
    "broker_admitted", "gateway_credentials_denied", "installed_record_accepted",
))


class BrokerInstallHeld(ValueError):
    pass


def hold():
    raise BrokerInstallHeld("original Task C read-only trust broker not installed or admitted")


def sha(raw):
    if type(raw) is not bytes:
        hold()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_service(service, socket_unit):
    if type(service) is not bytes or type(socket_unit) is not bytes:
        hold()
    try:
        lines = service.decode("utf-8").splitlines()
        slines = socket_unit.decode("utf-8").splitlines()
    except UnicodeError:
        hold()
    requirements = (
        "Type=exec", "User=root", "Group=root",
        "ExecStart=" + BROKER_PYTHON +
        " -I -m zog.host_deploy.gateway.graphics_owner_trust_daemon",
        "LoadCredential=read-only-checkpoint.json:" + READ_SOURCE,
        "LoadCredential=broker-private.key:" + SIGNER_SOURCE,
        "Sockets=" + SOCKET, "NoNewPrivileges=yes",
        "ProtectSystem=strict", "CapabilityBoundingSet=", "AmbientCapabilities=",
        "RequiresMountsFor=" + ORIGINAL_LEDGER,
        "RequiresMountsFor=" + ROOT_AUTHORITY,
    )
    required_socket = (
        "ListenStream=" + SOCKET_PATH,
        "SocketUser=root", "SocketGroup=zog-graphical-client",
        "SocketMode=0660", "Accept=no", "Service=" + SERVICE,
        "FileDescriptorName=trust-history",
    )
    if (any(k not in lines for k in requirements)
            or any(k not in slines for k in required_socket)
            or [v for v in lines if v.startswith("ExecStart=")] != [requirements[3]]
            or {v for v in lines if v.startswith("LoadCredential=")} !=
                {requirements[4], requirements[5]}
            or any(v.startswith("ReadWritePaths=") for v in lines)
            or any(v.startswith("EnvironmentFile=") for v in lines)
            or any(v.startswith("[Install]") or "WantedBy=" in v
                   for v in lines + slines)
            or "Accept=yes" in slines or
            any(v.startswith("ListenSequentialPacket=") for v in slines)):
        hold()


def review_disabled_source(selection, *, root_module, broker_modules,
                           service, socket_unit, original_record,
                           broker_manifest):
    """Exact candidate bytes only, never a trusted live installed package."""
    from zog.host_deploy.gateway import (
        graphics_owner_trust_install as upstream,
    )
    if (type(selection) is not dict or set(selection) != FIELDS
            or selection["schema"] != SCHEMA
            or selection["original_owner_source"] != OWNER_SOURCE
            or selection["root_provider_source"] != ROOT_PROVIDER_SOURCE
            or selection["broker_source"] != BROKER_SOURCE
            or selection["original_anchor_path"] != ORIGINAL_ANCHOR
            or selection["broker_purpose_approval_path"] != APPROVED_PIN
            or selection["gateway_public_pin_path"] != GATEWAY_PUBLIC_PIN
            or selection["broker_signer_source"] != SIGNER_SOURCE
            or selection["broker_signer_target"] != SIGNER_TARGET
            or selection["readonly_session_source"] != READ_SOURCE
            or selection["readonly_session_target"] != READ_TARGET
            or selection["broker_python"] != BROKER_PYTHON
            or selection["state"] != "NOT_INSTALLED"
            or any(selection[k] is not False for k in (
                "socket_enabled", "service_enabled", "broker_admitted",
                "gateway_credentials_denied", "installed_record_accepted"))
            or type(root_module) is not bytes or len(root_module) < 100
            or type(broker_modules) is not dict
            or set(broker_modules) != upstream.SOURCES
            or not all(type(x) is bytes and x for x in broker_modules.values())
            or any(type(selection[k]) is not str or SHA.fullmatch(selection[k]) is None
                   for k in (
                       "original_checkpoint_sha256", "approved_pin_sha256",
                       "broker_purpose_approval_sha256",
                       "root_provider_module_sha256",
                       "broker_source_module_sha256",
                       "broker_service_sha256", "broker_socket_sha256",
                       "broker_wheel_record_sha256", "root_wheel_record_sha256"))
            or sha(root_module) != selection["root_provider_module_sha256"]
            or sha(service) != selection["broker_service_sha256"]
            or sha(socket_unit) != selection["broker_socket_sha256"]
            or type(broker_manifest) is not dict
            or broker_manifest.get("root_source_revision") != OWNER_SOURCE
            or broker_manifest.get("gateway_source_revision") != BROKER_SOURCE
            or broker_manifest.get("runtime_python") != BROKER_PYTHON
            or broker_manifest.get("original_checkpoint_sha256") !=
                selection["original_checkpoint_sha256"]
            or broker_manifest.get("source_modules_sha256") !=
                selection["broker_source_module_sha256"]
            or broker_manifest.get("service_sha256") !=
                selection["broker_service_sha256"]
            or broker_manifest.get("socket_sha256") !=
                selection["broker_socket_sha256"]
            or type(original_record) is not dict
            or original_record.get("root_source_revision") != OWNER_SOURCE):
        hold()
    roles = (
        selection["readonly_role_arn"],
        selection["writer_role_arn"],
        selection["ssm_role_arn"],
    )
    if (any(type(r) is not str or ROLE.fullmatch(r) is None for r in roles)
            or len(set(roles)) != 3
            or selection["writer_role_arn"] !=
               original_record.get("checkpoint_role_arn")
            or roles != (
                broker_manifest.get("readonly_checkpoint_role_arn"),
                broker_manifest.get("owner_checkpoint_write_role_arn"),
                broker_manifest.get("owner_ssm_role_arn"))
            or len({ROLE.fullmatch(r).group(1) for r in roles}) != 1
            or ROLE.fullmatch(roles[0]).group(1) !=
               original_record.get("checkpoint_account_id")):
        hold()
    _validate_service(service, socket_unit)
    try:
        result = upstream.validate_disabled_selection(
            broker_manifest, actual_modules=broker_modules,
            service=service, socket_unit=socket_unit,
            original_checkpoint_record=original_record)
    except (upstream.BrokerInstallHold, KeyError, TypeError, ValueError):
        hold()
    if result["native_broker_installed"] is not False:
        hold()
    # A signed purpose approval, pin and individual RECORDs are still
    # independently Work-authenticated; their *declared* hashes are not a grant.
    return {
        "status": "SOURCE_REVIEW_ONLY",
        "native_install_accepted": False,
        "original_authority_accepted": False,
        "readonly_credential_accepted": False,
        "independent_pin_accepted": False,
        "service_activation_accepted": False,
        "gateway_denial_verified": False,
    }
