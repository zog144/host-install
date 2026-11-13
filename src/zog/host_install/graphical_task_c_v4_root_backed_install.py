"""Task C v4 root-backed disabled installation, no dedicated EBS requirement.

Validates source bytes / PEP 427 RECORD fixtures / operator-signed storage
approval / installer commit / protected service unit bytes. No provisioning,
key creation, S3 genesis, IAM grant, service enable or native acceptance.
Historical v3 two-filesystem selection remains an entirely separate API.
"""
from __future__ import annotations

from . import graphical_task_c_v3_install_freeze as previous
from .state_contract import validate as validate_state, StateError
from . import graphical_readonly_trust_broker_install as broker

SCHEMA = "zog-task-c-root-backed-three-owner-disabled-install-v4"
PLAN_SCHEMA = "zog-task-c-root-backed-directory-plan-v2"
STATUS = "ROOT_BACKED_THREE_OWNER_SOURCE_ONLY_NATIVE_DISABLED"
ROOT_HEAD = "f2c765cc38a666b60a09729cd16ab63102ca1dd5"
GATEWAY_HEAD = "7cf4dd4a5e1967035d724462ba3ddff10f8fbefa"
# The independently reviewed host-install STATE source, not the mutable
# candidate PR head, is pinned here. New versioned source bytes are also
# validated using STATE_SOURCES and wheel RECORD.
STATE_HEAD = previous.STATE_HEAD
STATE_SOURCES = previous.STATE_SOURCES
DISABLED = (
    "native_state_accepted", "native_directory_accepted",
    "native_wheel_record_accepted", "credentials_accepted",
    "broker_enabled", "owner_enabled", "socket_enabled",
    "ssm_authorized",
)
FIELDS = (previous.FIELDS - {"mount_plan_sha256", "native_mounts_accepted"}) | {
    "directory_plan_sha256", "verifier_service_sha256",
    "native_directory_accepted",
}
PLAN_FIELDS = frozenset((
    "schema", "mode", "root_filesystem_uuid", "ledger_directory",
    "authority_directory", "ledger_directory_identity_sha256",
    "authority_directory_identity_sha256", "installation_scope_sha256",
    "external_authorization_sha256",
))
sha = previous.sha
source_digest = previous.source_digest
verify_wheel_record = previous.verify_wheel_record


def hold():
    broker.hold()


def _validate_root_units(owner_service, owner_socket, broker_service,
                         broker_socket, verifier_service):
    from zog.root_control import graphical_task_c_root_backed_storage as root
    from zog.root_control import graphical_operation_owner_source as op
    if any(type(item) is not bytes or not item for item in
           (owner_service, owner_socket, broker_service, broker_socket,
            verifier_service)):
        hold()
    try:
        owner = owner_service.decode("utf-8")
        trust = broker_service.decode("utf-8")
        verifier = verifier_service.decode("utf-8")
        sockets = (owner_socket.decode("utf-8"),
                   broker_socket.decode("utf-8"))
    except UnicodeError:
        hold()
    owner_lines = owner.splitlines()
    trust_lines = trust.splitlines()
    verifier_lines = verifier.splitlines()
    required = "zog-graphical-owner-storage-verified.service"
    if (any("RequiresMountsFor=" in item for item in
            owner_lines + trust_lines + verifier_lines)
            or any("[Install]" in item or "WantedBy=" in item for item in
                   owner_lines + trust_lines + verifier_lines +
                   list(sockets))
            or any(name not in owner_lines for name in (
                "User=root", "Group=root", "NoNewPrivileges=yes",
                "ProtectSystem=strict",
                "ReadWritePaths=" + root.LEDGER,
                "Requires=" + required,
                "LoadCredential=aws-session.json:"+
                    "/var/lib/zog-graphical-owner-credential-source/aws-session.json",
                "LoadCredential=checkpoint-session.json:"+
                    "/var/lib/zog-graphical-owner-credential-source/checkpoint-session.json"))
            or any(name not in trust_lines for name in (
                "User=root", "Group=root", "NoNewPrivileges=yes",
                "ProtectSystem=strict",
                "ReadOnlyPaths=" + root.LEDGER,
                "ReadOnlyPaths=" + root.AUTHORITY,
                "Requires=zog-graphical-trust.socket " + required,
                "LoadCredential=read-only-checkpoint.json:"+
                    "/var/lib/zog-graphical-trust-credential-source/read-only-checkpoint.json",
                "LoadCredential=broker-private.key:"+
                    "/etc/zog/graphical-owner/trust-broker-private.key"))
            or any(name not in verifier_lines for name in (
                "Type=oneshot", "User=root", "Group=root",
                "NoNewPrivileges=yes", "ProtectSystem=strict",
                "CapabilityBoundingSet=",
                "ReadOnlyPaths=" + root.LEDGER,
                "ReadOnlyPaths=" + root.AUTHORITY,
                "ExecStart=/opt/zog/graphical-owner/venv/bin/python3"
                  " -I -m zog.root_control.graphical_task_c_root_storage_verify"))
            or any(line.startswith("LoadCredential=") for line in verifier_lines)
            or any(line.startswith("ReadWritePaths=") for line in trust_lines +
                   verifier_lines)
            or any(line.startswith("LoadCredential=aws-session.json:")
                   or line.startswith("LoadCredential=checkpoint-session.json:")
                   for line in trust_lines)
            or any("ssm:SendCommand" in line for line in trust_lines)
            or any("ListenStream=/run/zog/graphical-operation-owner.sock"
                   not in sock for sock in sockets[:1])
            or any("ListenStream=/run/zog/graphical-owner-trust.sock"
                   not in sock for sock in sockets[1:])):
        hold()
    for unit in (owner, trust):
        head, marker, tail = unit.partition("[Service]")
        if (not marker or required not in head or
                "After=" not in head or
                required not in head or
                "NoNewPrivileges=yes" not in tail):
            hold()
    if "Type=oneshot" not in verifier_lines or "Before=" not in verifier:
        hold()


def review_disabled_root_backed(
    selection, *, root_modules, gateway_modules, state_modules,
    root_record, gateway_record, state_record,
    owner_service, owner_socket, broker_service, broker_socket,
    verifier_service, state_bundle, directory_plan, gateway_selection,
    storage_registry, pinned_registry_public,
    storage_authority, signed_storage_approval, pinned_operator_public,
    retained_anchor_sha256, signed_install_commit, pinned_installer_public,
    retained_install_commit_sha256, now,
):
    from zog.root_control import graphical_task_c_root_backed_storage as root
    from zog.root_control import graphical_task_c_trust_authority as trust
    from zog.root_control import graphical_installation_storage_authority as storage
    from zog.root_control import graphical_operation_owner_source as op
    from zog.host_deploy.gateway import graphics_owner_trust_install as deploy

    if (type(selection) is not dict or set(selection) != FIELDS
            or selection.get("schema") != SCHEMA
            or (selection.get("root_revision"),
                selection.get("gateway_revision"),
                selection.get("state_revision")) !=
                (ROOT_HEAD, GATEWAY_HEAD, STATE_HEAD)
            or any(selection.get(k) is not False for k in DISABLED)
            or type(root_modules) is not dict
            or set(root_modules) != set(trust.ROOT_V3_SOURCES)
            or type(gateway_modules) is not dict
            or set(gateway_modules) != deploy.SOURCES
            or type(state_modules) is not dict
            or set(state_modules) != STATE_SOURCES
            or any(not previous.DIGEST.fullmatch(selection.get(k, ""))
                   for k in (
                       "root_sources_sha256","gateway_sources_sha256",
                       "state_sources_sha256","root_record_sha256",
                       "gateway_record_sha256","state_record_sha256",
                       "owner_service_sha256","owner_socket_sha256",
                       "broker_service_sha256","broker_socket_sha256",
                       "verifier_service_sha256","directory_plan_sha256",
                       "storage_scope_sha256","storage_approval_sha256",
                       "storage_commit_sha256"))
            or type(directory_plan) is not dict
            or set(directory_plan) != PLAN_FIELDS
            or directory_plan.get("schema") != PLAN_SCHEMA
            or directory_plan.get("mode") != root.MODE
            or directory_plan.get("ledger_directory") != root.LEDGER
            or directory_plan.get("authority_directory") != root.AUTHORITY
            or type(state_bundle) is not dict
            or sha(op.canonical(directory_plan)) !=
                selection["directory_plan_sha256"]):
        hold()
    if (source_digest(root_modules) != selection["root_sources_sha256"]
            or source_digest(gateway_modules) !=
                selection["gateway_sources_sha256"]
            or source_digest(state_modules) !=
                selection["state_sources_sha256"]
            or verify_wheel_record(root_record, root_modules) !=
                selection["root_record_sha256"]
            or verify_wheel_record(gateway_record, gateway_modules) !=
                selection["gateway_record_sha256"]
            or verify_wheel_record(state_record, state_modules) !=
                selection["state_record_sha256"]
            or any(sha(raw) != selection[k] for raw, k in (
                (owner_service, "owner_service_sha256"),
                (owner_socket, "owner_socket_sha256"),
                (broker_service, "broker_service_sha256"),
                (broker_socket, "broker_socket_sha256"),
                (verifier_service, "verifier_service_sha256")))):
        hold()
    _validate_root_units(owner_service, owner_socket, broker_service,
                         broker_socket, verifier_service)
    try:
        validate_state(state_bundle)
    except (StateError, ValueError, KeyError, TypeError):
        hold()
    selected_state = state_bundle["bootstrap"]["state"]
    backend = selected_state.get("storage_backend", "mounted-volume")
    if (selection["state_backend"] != backend
            or backend not in ("root-directory", "mounted-volume")):
        hold()
    local = (type(storage_registry) is dict
             and storage_registry.get("schema") == storage.LOCAL_SCHEMA)
    if local:
        if (pinned_registry_public is not None
                or storage_registry.get("host_install_installation_uuid") !=
                   state_bundle["bootstrap"]["installation_id"]
                or storage_registry.get("host_install_state_uuid") !=
                   selected_state["state_volume_id"]):
            hold()
    try:
        verified = root.verify_root_backed_commit(
            registry=storage_registry,
            pinned_registry_public=pinned_registry_public,
            authority=storage_authority,
            signed_storage_approval=signed_storage_approval,
            pinned_operator_public=pinned_operator_public,
            independently_retained_anchor_sha256=retained_anchor_sha256,
            receipt=signed_install_commit,
            pinned_installer_public=pinned_installer_public,
            independently_retained_commit_sha256=
                retained_install_commit_sha256,
            now=now, allow_local=local,
            verify_directories=False)
    except op.OperationDenied:
        hold()
    if (directory_plan["root_filesystem_uuid"] !=
            storage_authority["root_filesystem_uuid"]
            or directory_plan["installation_scope_sha256"] !=
                verified["installation_scope_sha256"]
            or directory_plan["external_authorization_sha256"] !=
                op.digest(signed_storage_approval)
            or any(directory_plan[k] != signed_install_commit[k]
                   for k in ("ledger_directory_identity_sha256",
                             "authority_directory_identity_sha256"))
            or selection["storage_scope_sha256"] !=
                verified["installation_scope_sha256"]
            or selection["storage_approval_sha256"] !=
                op.digest(signed_storage_approval)
            or selection["storage_commit_sha256"] !=
                op.digest(signed_install_commit)
            or signed_install_commit["owner_unit_sha256"] !=
                selection["owner_service_sha256"]
            or signed_install_commit["broker_unit_sha256"] !=
                selection["broker_service_sha256"]):
        hold()
    if (type(gateway_selection) is not dict
            or gateway_selection.get("schema") != deploy.V4_SCHEMA
            or gateway_selection.get("root_storage_mode") != root.MODE
            or gateway_selection.get("root_directory_plan_sha256") !=
                selection["directory_plan_sha256"]
            or gateway_selection.get("verified_unit_sha256") !=
                selection["verifier_service_sha256"]
            or gateway_selection.get("storage_commit_sha256") !=
                selection["storage_commit_sha256"]
            or gateway_selection.get("installation_scope_sha256") !=
                selection["storage_scope_sha256"]
            or gateway_selection.get("root_source_sha256") !=
                selection["root_sources_sha256"]
            or gateway_selection.get("native_host_install_source_sha256") !=
                source_digest({name: state_modules[name]
                               for name in deploy.HOST_INSTALL_V2_SOURCES})):
        hold()
    if (len({selection["read_only_role_arn"],selection["writer_role_arn"],
             selection["owner_ssm_role_arn"]}) != 3
            or (selection["read_only_role_arn"],
                selection["writer_role_arn"]) !=
                (storage_authority["checkpoint_reader_role_arn"],
                 storage_authority["checkpoint_writer_role_arn"])
            or gateway_selection.get("owner_ssm_role_arn") !=
                selection["owner_ssm_role_arn"]):
        hold()
    verified_broker = deploy.validate_disabled_v4_selection(
        gateway_selection, actual_modules=gateway_modules,
        installed_root_modules=root_modules,
        installed_host_install_modules={
            name: state_modules[name] for name in deploy.HOST_INSTALL_V2_SOURCES},
        service=broker_service, socket_unit=broker_socket,
        installation_storage_record=storage_authority,
        storage_commit=signed_install_commit,
        root_directory_plan=directory_plan, verified_unit=verifier_service)
    if (verified_broker["broker_admitted"] is not False
            or verified_broker["ssm_authorized"] is not False):
        hold()
    return {"status": STATUS, "state_backend": backend,
            "root_source_sha256":selection["root_sources_sha256"],
            "gateway_source_sha256":selection["gateway_sources_sha256"],
            "host_install_source_sha256":selection["state_sources_sha256"],
            "native_directory_accepted":False,
            "native_wheel_record_accepted":False,
            "native_credentials_accepted":False,
            "owner_active":False, "broker_active":False,
            "ssm_authorized":False}
