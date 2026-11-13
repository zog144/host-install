"""Task C protected backing mounts: explicit provisioning or read-only adoption.

Source-only, never formats a device, mounts a path or invents history.
Retained original adoption requires authenticated upstream S3 history and an
independent anchor before Work may accept its identity. An empty device never
becomes the historical original checkpoint.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

from . import graphical_readonly_trust_broker_install as broker

SCHEMA = "zog-task-c-protected-storage-plan-v1"
PATHS = (broker.ORIGINAL_LEDGER, broker.ROOT_AUTHORITY)
MODE = frozenset(("adopt-existing-original", "provision-separately-approved-new-scope"))
HEX = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\Z")
FIELDS = frozenset(("schema", "mode", "host_id", "installation_id",
    "state_volume_id", "state_fs_uuid", "scope_sha256",
    "original_record_sha256", "external_authorization_sha256", "mounts",
    "history_authenticated", "anchor_authenticated", "operator_approved"))
MOUNT_FIELDS = frozenset(("path", "filesystem_uuid", "block_partuuid",
    "expected_source", "filesystem_type", "writable", "mount_options"))

def _hold():
    broker.hold()

def plan_protected_mounts(plan):
    """Validate a *proposal*, never declare it native-accepted.

    Each protected store must have distinct dedicated backed storage, not a
    directory or bind of /state or of its peer. A proposed scope is never a
    positive installer authorization. Work must authenticate actual UUIDs,
    PARTUUIDs, mount identity and existing remote chain independently.
    """
    if (type(plan) is not dict or set(plan) != FIELDS
            or plan["schema"] != SCHEMA or plan["mode"] not in MODE
            or any(type(plan[k]) is not str or not HEX.fullmatch(plan[k])
                   for k in ("host_id", "installation_id", "state_volume_id"))
            or type(plan["state_fs_uuid"]) is not str
            or not UUID.fullmatch(plan["state_fs_uuid"])
            or type(plan["scope_sha256"]) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", plan["scope_sha256"])
            or plan["scope_sha256"] == "sha256:"+"0"*64
            or type(plan["mounts"]) is not list or len(plan["mounts"]) != 2
            or any(type(plan[k]) is not bool or plan[k] is not False
                   for k in ("history_authenticated", "anchor_authenticated",
                             "operator_approved"))):
        _hold()
    by_path = {}
    for m in plan["mounts"]:
        if (type(m) is not dict or set(m) != MOUNT_FIELDS
                or m.get("path") not in PATHS or m["path"] in by_path
                or type(m["filesystem_uuid"]) is not str
                or not UUID.fullmatch(m["filesystem_uuid"])
                or type(m["block_partuuid"]) is not str
                or not UUID.fullmatch(m["block_partuuid"])
                or type(m["expected_source"]) is not str
                or m["expected_source"] != "/dev/disk/by-uuid/" + m["filesystem_uuid"]
                or m["filesystem_type"] not in ("ext4", "xfs")
                or m["writable"] is not True
                or m["mount_options"] != ["nodev", "nosuid"]):
            _hold()
        by_path[m["path"]] = m
    if set(by_path) != set(PATHS):
        _hold()
    uuids = [plan["state_fs_uuid"]] + [
        by_path[k]["filesystem_uuid"] for k in PATHS]
    if len(set(uuids)) != 3:
        _hold()
    if by_path[PATHS[0]]["block_partuuid"] == by_path[PATHS[1]]["block_partuuid"]:
        _hold()

    if plan["mode"] == "adopt-existing-original":
        if (type(plan["original_record_sha256"]) is not str
                or not re.fullmatch(r"sha256:[0-9a-f]{64}",
                                     plan["original_record_sha256"])
                or plan["original_record_sha256"] == "sha256:"+"0"*64
                or plan["external_authorization_sha256"] is not None):
            _hold()
        status = "ORIGINAL_HISTORY_AND_INDEPENDENT_ANCHOR_REQUIRED"
    else:
        if (plan["original_record_sha256"] is not None
                or type(plan["external_authorization_sha256"]) is not str
                or not re.fullmatch(r"sha256:[0-9a-f]{64}",
                                     plan["external_authorization_sha256"])
                or plan["external_authorization_sha256"] == "sha256:"+"0"*64):
            _hold()
        status = "NEW_SCOPE_NOT_ORIGINAL_CONTINUITY"
    return {"status":status,"native_mounts_accepted":False,
            "original_history_accepted":False, "new_scope_authorized":False,
            "service_activation_authorized":False,"ssm_authorized":False}

def inspect_actual_mounts(plan):
    """Read only the *actual* local mount namespace; fail closed on aliases.

    This is an independent negative check, not a substitute for Work's block
    UUID/PARTUUID, mount namespace, external anchor and S3 history attestation.
    """
    proposal = plan_protected_mounts(plan)
    mounts = {row["path"]:row for row in plan["mounts"]}
    stats=[]
    for path in PATHS:
        p=Path(path)
        try:
            st=p.lstat()
            if (not stat.S_ISDIR(st.st_mode) or p.is_symlink()
                    or not os.path.ismount(p)
                    or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022):
                _hold()
            stats.append(st)
        except OSError:
            _hold()
    # Local root-directory STATE is deliberately *not* a separate mount.
    # Do not accept a caller's 'mounted' flag: host-install reopens the actual
    # canonical configuration, marker and filesystem namespace in-process.
    from .state_inspect import inspect_live
    try:
        with inspect_live() as context:
            context.recheck()
            selected = context.bundle["bootstrap"]["state"]
            if (selected["filesystem_uuid"] != plan["state_fs_uuid"]
                    or selected.get("storage_backend", "mounted-volume") not in (
                        "mounted-volume", "root-directory")):
                _hold()
            backend = selected.get("storage_backend", "mounted-volume")
            state = os.fstat(context.fd)
            if (backend == "mounted-volume") != os.path.ismount("/state"):
                _hold()
            if len({state.st_dev, stats[0].st_dev, stats[1].st_dev}) != 3:
                _hold()
            context.recheck()
    except (OSError, ValueError, KeyError, TypeError):
        _hold()
    return {**proposal,"status":"MOUNT_NAMESPACE_OBSERVED_NATIVE_IDENTITY_UNACCEPTED",
            "state_backend":backend}

def disabled_mount_unit_candidates(plan):
    """Render reviewer-readable exact mount unit candidate bytes; do not install.

    Work must separately prove exclusive stable block UUID/PARTUUID, inspect
    existing contents BEFORE mounting (mounts hide files), and authorize
    adoption versus fresh explicit scope. No generator output is native evidence.
    """
    plan_protected_mounts(plan)
    files = {}
    for mount in plan["mounts"]:
        path = mount["path"]
        name = path.strip("/").replace("/", "-") + ".mount"
        text = (
            "# SOURCE CANDIDATE ONLY; native Work must authenticate backing device.\n"
            "[Unit]\n"
            "Description=Protected Task C dedicated historical authority storage\n"
            "Before=zog-graphical-trust.service\n"
            "\n[Mount]\n"
            "What=" + mount["expected_source"] + "\n"
            "Where=" + path + "\n"
            "Type=" + mount["filesystem_type"] + "\n"
            "Options=nodev,nosuid\n"
            "DirectoryMode=0700\n"
            "TimeoutSec=30\n"
        )
        files[name] = text
    if len(files) != 2:
        _hold()
    return files
