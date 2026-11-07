"""Install-time registry-bound Task C storage selection, source-only.

No request/cataloque/approval digest is used to *select* backing storage.
Two independent protected mounts and an exact signed new-storage proposal are
reviewed without formatting disks, creating S3 genesis, installing an anchor,
or enabling the owner/broker/SSM sender. Each operation remains separately
signed, claimed and revoked by root-control.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import graphical_protected_storage_admission as mounts
from . import graphical_readonly_trust_broker_install as broker


SCHEMA = "zog-task-c-registry-bound-storage-install-review-v1"
FIELDS = frozenset((
    "schema", "mode", "host_id", "installation_id", "state_volume_id",
    "registry_id", "controller_id",
    "registry_sha256", "installation_scope_sha256",
    "root_storage_source_sha256", "root_checkpoint_source_sha256",
    "signed_storage_approval_sha256", "anchor_identity_sha256",
    "owner_unit_sha256", "broker_unit_sha256",
    "native_mounts_accepted", "native_storage_accepted",
    "owner_credentials_accepted", "ipc_accepted",
))
MODE = "prospective-installation-storage"
SOURCE_ONLY = "REGISTRY_BOUND_INSTALLATION_SOURCE_ONLY"


def _hold():
    broker.hold()


def digest(data):
    if type(data) is not bytes:
        _hold()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _requires_mounts_in_unit(unit, paths, *, owner):
    if type(unit) is not bytes or not unit:
        _hold()
    try:
        text = unit.decode("utf-8")
    except UnicodeError:
        _hold()
    if (text.count("[Unit]") != 1 or text.count("[Service]") != 1
            or text.index("[Unit]") > text.index("[Service]")
            or "[Install]" in text or "WantedBy=" in text):
        _hold()
    unit_lines = text.split("[Service]", 1)[0].splitlines()
    service_lines = text.split("[Service]", 1)[1].splitlines()
    if (any("RequiresMountsFor=" + path not in unit_lines for path in paths)
            or any(row.startswith("RequiresMountsFor=") for row in service_lines)
            or "User=root" not in service_lines
            or "Group=root" not in service_lines
            or "NoNewPrivileges=yes" not in service_lines
            or "ProtectSystem=strict" not in service_lines):
        _hold()
    if owner:
        if (not any(line.startswith("LoadCredential=aws-session.json:")
                    for line in service_lines)
                or not any(line.startswith("LoadCredential=checkpoint-session.json:")
                           for line in service_lines)
                or any(line.startswith("LoadCredential=broker-private.key:")
                       for line in service_lines)):
            _hold()
    else:
        if (not any(line.startswith("LoadCredential=read-only-checkpoint.json:")
                    for line in service_lines)
                or not any(line.startswith("LoadCredential=broker-private.key:")
                           for line in service_lines)
                or any(line.startswith("LoadCredential=aws-session.json:")
                       for line in service_lines)):
            _hold()


def review_registry_bound_storage(
    selection, *, registered_installation, pinned_registry_public,
    proposed_authority, storage_approval, pinned_operator_public,
    independently_retained_anchor_sha256, mount_plan,
    root_scope_module, root_checkpoint_module,
    owner_unit, broker_unit, now,
):
    """No caller-set success flag and no implied native installation receipt."""
    from zog.root_control import graphical_installation_storage_authority as root
    from zog.root_control import graphical_operation_owner_source as operation

    if (type(selection) is not dict or set(selection) != FIELDS
            or selection["schema"] != SCHEMA
            or selection["mode"] != MODE
            or any(selection[key] is not False for key in (
                "native_mounts_accepted", "native_storage_accepted",
                "owner_credentials_accepted", "ipc_accepted"))
            or type(root_scope_module) is not bytes
            or type(root_checkpoint_module) is not bytes
            or len(root_scope_module) < 100
            or len(root_checkpoint_module) < 100
            or digest(root_scope_module) !=
                selection["root_storage_source_sha256"]
            or digest(root_checkpoint_module) !=
                selection["root_checkpoint_source_sha256"]
            or digest(owner_unit) != selection["owner_unit_sha256"]
            or digest(broker_unit) != selection["broker_unit_sha256"]):
        _hold()
    try:
        proof = root.verify_installation_storage_selection(
            registry=registered_installation,
            pinned_registry_public=pinned_registry_public,
            authority=proposed_authority,
            signed_storage_approval=storage_approval,
            pinned_operator_public=pinned_operator_public,
            independently_retained_anchor_sha256=
                independently_retained_anchor_sha256, now=now)
    except operation.OperationDenied:
        _hold()  # Normalize upstream refusal to the installer hold contract.
    for key in ("host_id", "installation_id", "state_volume_id",
                "registry_id", "controller_id"):
        if selection[key] != registered_installation.get(key):
            _hold()
    if (selection["registry_sha256"] != proof["registry_sha256"]
            or selection["installation_scope_sha256"] !=
                proof["installation_scope_sha256"]
            or selection["signed_storage_approval_sha256"] !=
                root._digest(storage_approval)
            or selection["anchor_identity_sha256"] !=
                independently_retained_anchor_sha256):
        _hold()
    if (type(mount_plan) is not dict
            or mount_plan.get("schema") != mounts.SCHEMA
            or mount_plan.get("mode") !=
                "provision-separately-approved-new-scope"
            or any(mount_plan.get(k) != registered_installation[k]
                   for k in ("host_id", "installation_id", "state_volume_id"))
            or mount_plan.get("scope_sha256") !=
                proof["installation_scope_sha256"]
            or mount_plan.get("original_record_sha256") is not None
            or mount_plan.get("external_authorization_sha256") !=
                root._digest(storage_approval)):
        _hold()
    result = mounts.plan_protected_mounts(mount_plan)
    if result["new_scope_authorized"] is not False:
        _hold()
    # V3 owner reads the signed storage authority and independent anchor
    # before using the selected S3 session, not only its local claims ledger.
    _requires_mounts_in_unit(
        owner_unit, [broker.ORIGINAL_LEDGER, broker.ROOT_AUTHORITY],
        owner=True)
    _requires_mounts_in_unit(
        broker_unit, [broker.ORIGINAL_LEDGER, broker.ROOT_AUTHORITY],
        owner=False)
    return {
        "status": SOURCE_ONLY,
        "installation_scope_sha256": proof["installation_scope_sha256"],
        "registry_sha256": proof["registry_sha256"],
        "mount_unit_candidates": mounts.disabled_mount_unit_candidates(mount_plan),
        "native_mounts_accepted": False,
        "native_storage_accepted": False,
        "owner_credentials_accepted": False,
        "ipc_accepted": False,
        "owner_active": False,
        "broker_active": False,
        "ssm_authorized": False,
    }



def review_signed_registry_install_commit(
    selection, *, registered_installation, pinned_registry_public,
    proposed_authority, storage_approval, pinned_operator_public,
    independently_retained_anchor_sha256, mount_plan,
    root_scope_module, root_checkpoint_module,
    owner_unit, broker_unit, signed_install_commit,
    pinned_installer_public, independently_retained_commit_sha256, now,
):
    """A historical installer commit is not a reusable per-operation approval.

    Exact signed acceptance time is verified within the original 15-minute
    storage-establishment grant, while current time may be later (reboot).
    Separate Work must still prove *actual* mounted volume UUIDs and S3 data.
    """
    from zog.root_control import graphical_installation_storage_commit as root_commit
    from zog.root_control import graphical_operation_owner_source as operation

    if type(signed_install_commit) is not dict or type(
            signed_install_commit.get("accepted_at")) is not int:
        _hold()
    review_registry_bound_storage(
        selection, registered_installation=registered_installation,
        pinned_registry_public=pinned_registry_public,
        proposed_authority=proposed_authority,
        storage_approval=storage_approval,
        pinned_operator_public=pinned_operator_public,
        independently_retained_anchor_sha256=independently_retained_anchor_sha256,
        mount_plan=mount_plan, root_scope_module=root_scope_module,
        root_checkpoint_module=root_checkpoint_module,
        owner_unit=owner_unit, broker_unit=broker_unit,
        now=signed_install_commit["accepted_at"])
    try:
        proof = root_commit.verify_installed_storage_commit(
            registered_installation=registered_installation,
            pinned_registry_public=pinned_registry_public,
            storage_authority=proposed_authority,
            signed_storage_approval=storage_approval,
            pinned_operator_public=pinned_operator_public,
            independently_retained_anchor_sha256=independently_retained_anchor_sha256,
            receipt=signed_install_commit,
            pinned_installer_public=pinned_installer_public,
            independently_retained_commit_sha256=
                independently_retained_commit_sha256, now=now)
    except operation.OperationDenied:
        _hold()
    mounted = {record["path"]: record for record in mount_plan["mounts"]}
    if (signed_install_commit["ledger_fs_uuid"] !=
            mounted[broker.ORIGINAL_LEDGER]["filesystem_uuid"]
            or signed_install_commit["authority_fs_uuid"] !=
            mounted[broker.ROOT_AUTHORITY]["filesystem_uuid"]
            or signed_install_commit["state_fs_uuid"] !=
            mount_plan["state_fs_uuid"]
            or signed_install_commit["owner_unit_sha256"] !=
                selection["owner_unit_sha256"]
            or signed_install_commit["broker_unit_sha256"] !=
                selection["broker_unit_sha256"]
            or proof["installation_scope_sha256"] !=
                selection["installation_scope_sha256"]):
        _hold()
    return {
        "status": "SIGNED_INSTALLATION_COMMIT_SOURCE_ONLY",
        "installation_scope_sha256": proof["installation_scope_sha256"],
        "mounts_observed_native": False,
        "genesis_observed_native": False,
        "external_anchor_observed_native": False,
        "owner_credentials_accepted": False,
        "owner_ipc_accepted": False,
        "service_placement_accepted": False,
    }
