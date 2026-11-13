"""Disabled exact-head Task C v3 installer reconciliation for three owners.

This is an offline SOURCE selection. Source tree bytes, wheel RECORD entries,
unit/socket bytes, storage approval and original commit must independently
match; the function never creates a key, mounts, S3 checkpoint, service, or
operation grant. Root-control performs native STATE inspection at use time.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import re

from . import graphical_protected_storage_admission as protected
from . import graphical_readonly_trust_broker_install as broker
from . import graphical_registry_storage_installation as registry
from . import graphical_native_owner_install as native_owner
from .state_contract import validate as validate_state, canonical as state_canonical

ROOT_HEAD = "935e2764c227b0d8036015d9d11e7419b3afd5e0"
GATEWAY_HEAD = "95ff98327ed9730774fdaa5d6f588ac8c63b8ad6"
STATE_HEAD = "aaccfdb2852532a9667682938937afe768dbc821"
SCHEMA = "zog-task-c-three-owner-disabled-install-freeze-v1"
STATUS = "THREE_OWNER_V3_SOURCE_FROZEN_NATIVE_DISABLED"
STATE_SOURCES = frozenset((
    "zog.host_install.state_contract",
    "zog.host_install.state_gate",
    "zog.host_install.state_inspect",
    "zog.host_install.state_provision",
    "zog.host_install.graphical_protected_storage_admission",
))
FIELDS = frozenset((
    "schema", "root_revision", "gateway_revision", "state_revision",
    "state_backend", "root_sources_sha256", "gateway_sources_sha256",
    "state_sources_sha256", "root_record_sha256",
    "gateway_record_sha256", "state_record_sha256",
    "owner_service_sha256", "owner_socket_sha256",
    "broker_service_sha256", "broker_socket_sha256",
    "mount_plan_sha256", "storage_scope_sha256", "storage_approval_sha256",
    "storage_commit_sha256", "read_only_role_arn",
    "writer_role_arn", "owner_ssm_role_arn",
    "native_state_accepted", "native_mounts_accepted",
    "native_wheel_record_accepted", "credentials_accepted",
    "broker_enabled", "owner_enabled", "socket_enabled",
    "ssm_authorized",
))
DISABLED = (
    "native_state_accepted", "native_mounts_accepted",
    "native_wheel_record_accepted", "credentials_accepted",
    "broker_enabled", "owner_enabled", "socket_enabled", "ssm_authorized",
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def hold():
    broker.hold()


def sha(raw):
    if type(raw) is not bytes:
        hold()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def source_digest(modules):
    if type(modules) is not dict or not modules:
        hold()
    if any(type(key) is not str or type(data) is not bytes or not data
           for key, data in modules.items()):
        hold()
    return sha(b"".join(name.encode("ascii") + b"\0" + modules[name] + b"\0"
                        for name in sorted(modules)))


def verify_wheel_record(record_bytes, modules):
    """Check PEP 427 wheel RECORD against selected actual .py bytes.

    This checks RECORD consistency, not the provenance of installed bytes.
    The native installer must independently attest the wheel, installation
    path, RECORD inode, and complete installed distribution before activation.
    """
    if type(record_bytes) is not bytes or len(record_bytes) > 262144:
        hold()
    try:
        text = record_bytes.decode("utf-8")
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeError, csv.Error):
        hold()
    if len(rows) > 4096:
        hold()
    observed = {}
    for row in rows:
        if len(row) != 3 or row[0] in observed or row[0].startswith("/") or (
                "\\" in row[0] or any(part in ("", ".", "..")
                                          for part in row[0].split("/"))):
            hold()
        observed[row[0]] = row[1:]
    for name, data in modules.items():
        if not name.startswith("zog.") or not re.fullmatch(
                r"zog(?:\.[a-z][a-z0-9_]*)+", name):
            hold()
        path = name.replace(".", "/") + ".py"
        if path not in observed:
            hold()
        encoded, size = observed[path]
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        if encoded != "sha256=" + expected or size != str(len(data)):
            hold()
    return sha(record_bytes)


def _unit_source(owner_service, owner_socket, broker_service, broker_socket):
    if any(type(raw) is not bytes for raw in
           (owner_service, owner_socket, broker_service, broker_socket)):
        hold()
    # Reuse the two independent existing owner and broker source validators.
    native_owner.verify_unit_sources(
        owner_service.decode("utf-8"), owner_socket.decode("utf-8"))
    broker._validate_service(broker_service, broker_socket)
    for raw, is_owner in ((owner_service, True), (broker_service, False)):
        registry._requires_mounts_in_unit(
            raw, [broker.ORIGINAL_LEDGER, broker.ROOT_AUTHORITY],
            owner=is_owner)
    socket_text = (owner_socket.decode("utf-8"),
                   broker_socket.decode("utf-8"))
    if ("/run/zog/graphical-operation-owner.sock" not in socket_text[0]
            or broker.SOCKET_PATH not in socket_text[1]
            or any("[Install]" in x or "WantedBy=" in x for x in socket_text)):
        hold()


def review_disabled_v3_freeze(
    selection, *, root_modules, gateway_modules, state_modules,
    root_record, gateway_record, state_record,
    owner_service, owner_socket, broker_service, broker_socket,
    state_bundle, mount_plan, gateway_selection,
    storage_registry, pinned_registry_public,
    storage_authority, signed_storage_approval, pinned_operator_public,
    retained_anchor_sha256, signed_install_commit, pinned_installer_public,
    retained_install_commit_sha256, now,
):
    """Only a source-tested signed storage establishment, never runtime GO.

    A local unsigned installation selection is permitted *only* explicitly:
    its Host/STATE UUIDs must match canonical host-install configuration.
    The operator-signed storage approval and protected installer commit remain.
    """
    from zog.root_control import (
        graphical_installation_storage_authority as root,
        graphical_installation_storage_commit as root_commit,
        graphical_operation_owner_source as op,
        graphical_task_c_trust_authority as trust,
    )
    from zog.host_deploy.gateway import graphics_owner_trust_install as deploy

    if (type(selection) is not dict or set(selection) != FIELDS
            or selection["schema"] != SCHEMA
            or (selection["root_revision"], selection["gateway_revision"],
                selection["state_revision"]) != (
                    ROOT_HEAD, GATEWAY_HEAD, STATE_HEAD)
            or any(selection[k] is not False for k in DISABLED)
            or type(root_modules) is not dict
            or set(root_modules) != set(trust.ROOT_V3_SOURCES)
            or type(gateway_modules) is not dict
            or set(gateway_modules) != deploy.SOURCES
            or type(state_modules) is not dict
            or set(state_modules) != STATE_SOURCES
            or any(not DIGEST.fullmatch(selection[k]) for k in (
                "root_sources_sha256", "gateway_sources_sha256",
                "state_sources_sha256", "root_record_sha256",
                "gateway_record_sha256", "state_record_sha256",
                "owner_service_sha256", "owner_socket_sha256",
                "broker_service_sha256", "broker_socket_sha256",
                "mount_plan_sha256", "storage_scope_sha256",
                "storage_approval_sha256", "storage_commit_sha256"))):
        hold()
    if (source_digest(root_modules) != selection["root_sources_sha256"]
            or source_digest(gateway_modules) !=
                selection["gateway_sources_sha256"]
            or source_digest(state_modules) != selection["state_sources_sha256"]
            or verify_wheel_record(root_record, root_modules) !=
                selection["root_record_sha256"]
            or verify_wheel_record(gateway_record, gateway_modules) !=
                selection["gateway_record_sha256"]
            or verify_wheel_record(state_record, state_modules) !=
                selection["state_record_sha256"]
            or any(sha(raw) != selection[key] for raw, key in (
                (owner_service, "owner_service_sha256"),
                (owner_socket, "owner_socket_sha256"),
                (broker_service, "broker_service_sha256"),
                (broker_socket, "broker_socket_sha256")))
            or type(mount_plan) is not dict
            or sha(op.canonical(mount_plan)) != selection["mount_plan_sha256"]):
        hold()
    _unit_source(owner_service, owner_socket, broker_service, broker_socket)
    # Backend comes from canonical host-install, not gateway/SSM metadata.
    validate_state(state_bundle)
    selected_state = state_bundle["bootstrap"]["state"]
    backend = selected_state.get("storage_backend", "mounted-volume")
    if (selection["state_backend"] != backend
            or backend not in ("root-directory", "mounted-volume")
            or mount_plan.get("state_fs_uuid") != selected_state["filesystem_uuid"]
            or mount_plan.get("mode") != "provision-separately-approved-new-scope"):
        hold()
    protected.plan_protected_mounts(mount_plan)
    if any(row["block_partuuid"] == selected_state["partition_partuuid"]
           for row in mount_plan["mounts"]):
        # A protected mount must not reuse the Host root/STATE partition.
        hold()
    local = (type(storage_registry) is dict
             and storage_registry.get("schema") == root.LOCAL_SCHEMA)
    if local:
        if (state_bundle["bootstrap"]["registries"] != []
                or state_bundle["bootstrap"]["control_authority"] is not None
                or state_bundle["installation"]["installation_mode"] != "non-resident"
                or storage_registry.get("host_install_installation_uuid") !=
                    state_bundle["bootstrap"]["installation_id"]
                or storage_registry.get("host_install_state_uuid") !=
                    selected_state["state_volume_id"]
                or pinned_registry_public is not None):
            hold()
    else:
        # Do not silently switch a standalone Host into the legacy signed
        # registry backend because a gateway supplied a registry-shaped JSON.
        if (not state_bundle["bootstrap"]["registries"]
                or type(state_bundle["bootstrap"]["control_authority"]) is not dict):
            hold()
    # A locally selected Host has no registrar signature. A legacy managed
    # registry can still be verified only in its explicitly selected mode.
    try:
        proof = root.verify_installation_storage_selection(
            registry=storage_registry, pinned_registry_public=pinned_registry_public,
            authority=storage_authority,
            signed_storage_approval=signed_storage_approval,
            pinned_operator_public=pinned_operator_public,
            independently_retained_anchor_sha256=retained_anchor_sha256,
            now=signed_install_commit["accepted_at"], allow_local=local)
        root_commit.verify_installed_storage_commit(
            registered_installation=storage_registry,
            pinned_registry_public=pinned_registry_public,
            storage_authority=storage_authority,
            signed_storage_approval=signed_storage_approval,
            pinned_operator_public=pinned_operator_public,
            independently_retained_anchor_sha256=retained_anchor_sha256,
            receipt=signed_install_commit, pinned_installer_public=pinned_installer_public,
            independently_retained_commit_sha256=retained_install_commit_sha256,
            now=now, allow_local=local)
    except op.OperationDenied:
        hold()
    if (proof["installation_scope_sha256"] != selection["storage_scope_sha256"]
            or op.digest(signed_storage_approval) != selection["storage_approval_sha256"]
            or op.digest(signed_install_commit) != selection["storage_commit_sha256"]
            or mount_plan["scope_sha256"] != selection["storage_scope_sha256"]
            or mount_plan["external_authorization_sha256"] !=
                selection["storage_approval_sha256"]
            or any(mount_plan[k] != storage_registry[k] for k in
                   ("host_id", "installation_id", "state_volume_id"))
            or signed_install_commit["state_fs_uuid"] !=
                selected_state["filesystem_uuid"]
            or signed_install_commit["owner_unit_sha256"] !=
                selection["owner_service_sha256"]
            or signed_install_commit["broker_unit_sha256"] !=
                selection["broker_service_sha256"]):
        hold()
    role_reader = storage_authority["checkpoint_reader_role_arn"]
    role_writer = storage_authority["checkpoint_writer_role_arn"]
    role_ssm = gateway_selection["owner_ssm_role_arn"]
    if (len({role_reader, role_writer, role_ssm}) != 3
            or (selection["read_only_role_arn"], selection["writer_role_arn"],
                selection["owner_ssm_role_arn"]) != (
                    role_reader, role_writer, role_ssm)
            or gateway_selection["root_source_sha256"] !=
                selection["root_sources_sha256"]
            or gateway_selection["native_host_install_source_sha256"] !=
                source_digest({name: state_modules[name]
                               for name in deploy.HOST_INSTALL_V2_SOURCES})
            or gateway_selection["storage_commit_sha256"] !=
                selection["storage_commit_sha256"]
            or gateway_selection["installation_scope_sha256"] !=
                selection["storage_scope_sha256"]):
        hold()
    delegated = deploy.validate_disabled_v3_selection(
        gateway_selection, actual_modules=gateway_modules,
        installed_root_modules=root_modules,
        installed_host_install_modules={
            k: state_modules[k] for k in deploy.HOST_INSTALL_V2_SOURCES},
        service=broker_service, socket_unit=broker_socket,
        installation_storage_record=storage_authority,
        storage_commit=signed_install_commit)
    if (delegated["ssm_authorized"] is not False
            or delegated["broker_admitted"] is not False):
        hold()
    # All source tests must stay separate from the installed live readback
    # require_live_backend_bound_identity and actual S3/IAM/SSM acceptance.
    return {
        "status": STATUS, "state_backend": backend,
        "root_source_sha256": selection["root_sources_sha256"],
        "gateway_source_sha256": selection["gateway_sources_sha256"],
        "host_install_source_sha256": selection["state_sources_sha256"],
        "native_state_accepted": False,
        "native_mounts_accepted": False,
        "native_wheel_record_accepted": False,
        "native_credential_accepted": False,
        "owner_active": False, "broker_active": False, "ssm_authorized": False,
    }
