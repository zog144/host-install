"""Explicit host-registry legacy-to-directory STATE migration source contract.

NO native mutator is installed here. The journal executor accepts a disposable
backend in tests; it deliberately has no Linux accounts, systemd or identity
adapter. Native execution must wait for a separately verified host-discover
consumer that can read *the same* legacy key under /state without generating
another identity. No root signing or Command Center enrollment is involved.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid

from .state_contract import ACCOUNTS, StateError, canonical, decode, digest, require, validate
from .state_inspect import assess_root_directory

SCHEMA = "zog-host-registry-directory-state-account-migration-v1"
JOURNAL_SCHEMA = "zog-host-registry-state-account-journal-v1"
STAGES = (
    "service-stopped",
    "archive-group-remapped",
    "host-discover-account-remapped",
    "missing-accounts-created",
    "state-layout-prepared",
    "identity-moved",
    "configuration-path-switched",
    "systemd-path-switched",
    "service-restored",
)
LEGACY_UID = 991
LEGACY_GID = 991
LEGACY_ARCHIVE_GID = 990
TARGET_UID = 970
TARGET_GID = 970
TARGET_ARCHIVE_GID = 972
SOURCE = "/var/lib/host-discover/identity"
DESTINATION = "/state/host-discover/identity"
CREDENTIALS = "/var/lib/host-discover/credentials"
DESTINATIONS = "/var/lib/host-discover/beacon-destinations.json"
CONFIGURATION = "/etc/host-discover/configuration.json"
SELECTED_UNIT = "host-discover.service"
REQUIRED_IDENTITY_FILES = frozenset(("key.lock", "identity.pem", "binding.json"))
OPTIONAL_IDENTITY_FILES = frozenset(("registry-ca.pem",))
ALLOWED_IDENTITY_FILES = REQUIRED_IDENTITY_FILES | OPTIONAL_IDENTITY_FILES
PATH_CHANGE_FIELDS = frozenset(("identity_directory",))
HEX = re.compile(r"[0-9a-f]{64}\Z")


def _uid(value):
    return type(value) is int and 0 <= value <= 65535


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, AttributeError, TypeError):
        return False


def _digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _decode_config(raw):
    require(type(raw) is bytes and len(raw) <= 65536,
            "migration-config", "bounded configuration bytes required")
    return decode(raw)


def changed_configuration(raw, *, old=SOURCE, new=DESTINATION):
    """Preserve every other byte, including registry endpoint and trust fields.

    JSON must contain the identity_directory assignment exactly once. This is
    an exact-span rewrite, not a parse/pretty-print of potentially secret config.
    """
    before = _decode_config(raw)
    require(type(before) is dict and before.get("identity_directory") == old
            and before.get("credential_directory") == CREDENTIALS,
            "migration-config", "legacy config paths not exactly selected")
    needle = re.compile(rb'("identity_directory"\s*:\s*)"' +
                        re.escape(old.encode("ascii")) + rb'"')
    matches = list(needle.finditer(raw))
    require(len(matches) == 1, "migration-config",
            "identity_directory requires one unambiguous JSON assignment")
    target = raw[:matches[0].start()] + matches[0].group(1) + b'"' + new.encode("ascii") + b'"' + raw[matches[0].end():]
    after = _decode_config(target)
    require(set(before) == set(after) and
            all(before[k] == after[k] for k in before if k not in PATH_CHANGE_FIELDS)
            and after["identity_directory"] == new and
            after["credential_directory"] == CREDENTIALS,
            "migration-config", "non-path configuration changed")
    return target


def changed_unit_dropin():
    """Explicit drop-in clearing old writable paths, retaining credentials."""
    return (
        "[Service]\n"
        "ReadWritePaths=\n"
        "ReadWritePaths=/state/host-discover/identity /var/lib/host-discover/credentials\n"
    ).encode("ascii")


def _check_inventory(inventory):
    """Source-only metadata input, not proof that a Host was inspected."""
    require(type(inventory) is dict and
            set(inventory) == set(ALLOWED_IDENTITY_FILES) | {"credential_files", "destinations"},
            "migration-inventory", "closed identity file inventory required")
    for name in ALLOWED_IDENTITY_FILES:
        row = inventory[name]
        require((row is None and name in OPTIONAL_IDENTITY_FILES)
                or (type(row) is dict and set(row) == {
                    "kind", "uid", "gid", "mode", "links", "dev", "inode"
                } and row["kind"] == "file" and row["uid"] == LEGACY_UID
                    and row["gid"] == LEGACY_GID and row["mode"] == 0o600
                    and row["links"] == 1 and _uid(row["dev"])
                    and _uid(row["inode"]) and row["inode"] > 0),
                "migration-inventory", "unsafe legacy identity entry")
    creds = inventory["credential_files"]
    require(type(creds) is dict and len(creds) <= 128,
            "migration-inventory", "credential inventory must be bounded")
    for name, row in creds.items():
        require(type(name) is str and re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name)
                and name not in (".", "..") and type(row) is dict
                and row == {"kind":"file", "uid":LEGACY_UID,
                            "gid":LEGACY_ARCHIVE_GID,
                            "mode":0o640, "links":1},
                "migration-inventory", "unknown/symlink/hardlinked credentials")
    d = inventory["destinations"]
    require(type(d) is dict and d == {
        "kind":"file", "uid":LEGACY_UID, "gid":LEGACY_GID,
        "mode":0o600, "links":1},
        "migration-inventory", "unexpected destinations ownership")


def _accounts(snapshot):
    """Explicit collision preflight; no ordinary ensure_accounts() rewrite."""
    require(type(snapshot) is dict
            and set(snapshot) == {"users", "groups", "uid_index", "gid_index"},
            "migration-accounts", "closed account snapshot required")
    users, groups = snapshot["users"], snapshot["groups"]
    require(type(users) is dict and type(groups) is dict,
            "migration-accounts", "account indexes required")
    expected_user = {
        "uid":LEGACY_UID,"gid":LEGACY_GID,
        "home":"/home/host-discover","shell":"/sbin/nologin",
        "groups":["archive-consumers"],
    }
    require(users.get("host-discover") == expected_user
            and "box-control" not in users
            and groups.get("host-discover") == LEGACY_GID
            and groups.get("archive-consumers") == LEGACY_ARCHIVE_GID
            and "box-control" not in groups and "host-control" not in groups,
            "migration-accounts", "unrecognized legacy account mapping")
    ui, gi = snapshot["uid_index"], snapshot["gid_index"]
    require(type(ui) is dict and type(gi) is dict
            and ui.get(str(LEGACY_UID)) == "host-discover"
            and gi.get(str(LEGACY_GID)) == "host-discover"
            and gi.get(str(LEGACY_ARCHIVE_GID)) == "archive-consumers"
            and all(str(x) not in ui for x in (970,971,972,973))
            and all(str(x) not in gi for x in (970,971,972,973)),
            "migration-accounts", "target numeric IDs occupied or legacy IDs changed")
    return ACCOUNTS


def review_source_migration(bundle, *, migration_id, root_observation,
                            account_snapshot, file_inventory,
                            configuration_bytes, binding,
                            public_identity_witness, unit_bytes,
                            service_snapshot, consumer_contract=None):
    """Validate only selected facts. Output is NOT an authenticated native GO.

    Root/identity inputs must be independently re-observed by a privileged
    native adapter before any mutation; do not treat caller JSON as evidence.
    The consumer contract is intentionally unselected until host-discover owns
    the legacy-key migration API. A caller boolean cannot override this HOLD.
    """
    validate(bundle)
    b, ins, marker = bundle["bootstrap"],bundle["installation"],bundle["marker"]
    require(ins["installation_mode"] == "non-resident"
            and ins["operation"] == "migration" and b["mode"] == "migration"
            and marker["schema"] == 2 and marker["kind"] == "zog-state-directory"
            and b["state"]["storage_backend"] == "root-directory"
            and _uuid(migration_id),
            "migration-selection", "canonical non-resident migration bundle required")
    expected_host = b["initialization"]["expected_host_uuid"]
    expected_fp = b["initialization"]["expected_fingerprint"]
    require(_uuid(expected_host) and type(expected_fp) is str and HEX.fullmatch(expected_fp),
            "migration-identity", "existing Host binding required")
    require(type(binding) is dict and set(binding) == {"host_id", "fingerprint"}
            and binding["host_id"] == expected_host
            and binding["fingerprint"] == expected_fp
            and public_identity_witness == expected_fp,
            "migration-identity", "pre-existing binding and public fingerprint disagree")
    require(type(root_observation) is dict and
            set(root_observation) == {"mounts", "devices", "root_device", "state_exists"},
            "migration-root", "exact root observation required")
    require(root_observation["state_exists"] is False,
            "migration-state", "/state must be absent at first preflight")
    backing = assess_root_directory(root_observation["mounts"],
                                    root_observation["devices"], b["state"],
                                    root_observation["root_device"])
    require(backing["type"] in ("xfs", "ext4"),"migration-root","root backing required")
    _accounts(account_snapshot)
    _check_inventory(file_inventory)
    cfg = _decode_config(configuration_bytes)
    require(cfg.get("host_id") == expected_host and
            type(cfg.get("server")) is str and cfg["server"].startswith("https://")
            and cfg.get("identity_directory") == SOURCE
            and cfg.get("credential_directory") == CREDENTIALS,
            "migration-registry", "existing host-discover endpoint/binding not selected")
    target_bytes = changed_configuration(configuration_bytes)
    require(type(unit_bytes) is bytes and len(unit_bytes) <= 65536
            and b"User=host-discover" in unit_bytes.splitlines()
            and b"Group=host-discover" in unit_bytes.splitlines()
            and b"SupplementaryGroups=archive-consumers" in unit_bytes.splitlines()
            and b"ReadWritePaths=/var/lib/host-discover/identity /var/lib/host-discover/credentials" in unit_bytes.splitlines()
            and b"[Service]" in unit_bytes,
            "migration-unit", "installed service template not selected")
    require(type(service_snapshot) is dict and
            set(service_snapshot) == {"active", "enabled"} and
            all(type(x) is bool for x in service_snapshot.values()),
            "migration-service", "both original service states required")
    require(consumer_contract is None,
            "migration-consumer", "only a reviewed consumer revision may remove this HOLD")
    # Digests of public configuration and unit, NEVER key/credential bytes.
    plan = {
        "schema":SCHEMA, "migration_id":migration_id,
        "installation_id":b["installation_id"],
        "state_volume_id":b["state"]["state_volume_id"],
        "host_uuid":expected_host, "public_fingerprint":expected_fp,
        "root_fs_uuid":b["state"]["filesystem_uuid"],
        "root_partuuid":b["state"]["partition_partuuid"],
        "registry_origin":cfg["server"], "root_fs_type":backing["type"],
        "configuration_before_sha256":_digest_bytes(configuration_bytes),
        "configuration_after_sha256":_digest_bytes(target_bytes),
        "unit_before_sha256":_digest_bytes(unit_bytes),
        "unit_dropin_sha256":_digest_bytes(changed_unit_dropin()),
        "bundle_sha256":digest(bundle),
        "service_was_active":service_snapshot["active"],
        "service_was_enabled":service_snapshot["enabled"],
        "status":"SOURCE_REVIEW_NATIVE_CONSUMER_HOLD",
    }
    return plan


class MigrationJournal:
    """Durable step fencing for an injected backend with verified before/after.

    A retry never reissues a step in an unknown state. This engine cannot mutate
    Linux accounts on its own. Root-owned production use MUST install a separately
    approved guarded native backend, unavailable in this source candidate.
    """
    def __init__(self, root, plan, backend, *, require_root=True):
        self.root=Path(root)
        self.plan=plan
        self.backend=backend
        self.require_root=require_root
        require(type(plan) is dict and plan.get("schema")==SCHEMA
                and _uuid(plan.get("migration_id")) and
                plan.get("status")=="SOURCE_REVIEW_NATIVE_CONSUMER_HOLD",
                "migration-journal", "exact reviewed plan required")
        require(not require_root or os.geteuid()==0,"root-required","migration journal requires root")

    def _files(self):
        info=self.root.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and info.st_uid==os.geteuid()
                and stat.S_IMODE(info.st_mode)==0o700,
                "migration-journal", "protected journal directory required")
        return self.root/"transaction.json", self.root/".transaction.lock"

    def _save(self, row):
        target,_=self._files()
        tmp=self.root/".transaction.pending"
        payload=canonical(row)
        fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.write(fd,payload)
            os.fsync(fd)
        finally:os.close(fd)
        os.replace(tmp,target)
        d=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(d)
        finally:os.close(d)

    def _open(self):
        target,lock=self._files()
        fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        require(os.fstat(fd).st_nlink==1 and
                stat.S_IMODE(os.fstat(fd).st_mode)==0o600 and
                os.fstat(fd).st_uid==os.geteuid(),"migration-journal","unsafe lock")
        fcntl.flock(fd,fcntl.LOCK_EX)
        pending=self.root/".transaction.pending"
        if pending.exists():
            info=pending.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
                    and info.st_uid==os.geteuid()
                    and stat.S_IMODE(info.st_mode)==0o600,
                    "migration-journal","unsafe pending journal")
            candidate=decode(pending.read_bytes())
            require(type(candidate) is dict
                    and candidate.get("schema")==JOURNAL_SCHEMA
                    and candidate.get("migration_id")==self.plan["migration_id"]
                    and candidate.get("plan_sha256")==digest(self.plan)
                    and candidate.get("status") in
                        ("applying","complete","rolling-back","rolled-back")
                    and type(candidate.get("completed")) is list
                    and candidate["completed"]==list(
                        STAGES[:len(candidate["completed"])])
                    and candidate.get("active") in (None,*STAGES),
                    "migration-journal","unrecognized pending intent")
            if target.exists():
                prior=decode(target.read_bytes())
                require(type(prior) is dict
                        and prior.get("schema")==JOURNAL_SCHEMA
                        and prior.get("migration_id")==candidate["migration_id"]
                        and prior.get("plan_sha256")==candidate["plan_sha256"]
                        and prior.get("status") in
                            ("applying","complete","rolling-back","rolled-back"),
                        "migration-journal","pending transaction conflicts")
                # Save always writes the newer journal and fsyncs before the
                # rename; the native backend will still recheck every phase.
                require(not (prior.get("status")=="rolled-back"
                             and candidate["status"]=="applying"),
                        "migration-journal","pending journal reverses rollback")
            os.replace(pending,target)
            d=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(d)
            finally:os.close(d)
        if target.exists():
            info=target.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid()
                    and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,
                    "migration-journal","unsafe journal entry")
            row=decode(target.read_bytes())
            require(type(row) is dict
                    and set(row)=={"schema","migration_id","plan_sha256",
                                   "status","completed","active"}
                    and row["schema"]==JOURNAL_SCHEMA
                    and row["migration_id"]==self.plan["migration_id"]
                    and row["plan_sha256"]==digest(self.plan)
                    and row["status"] in ("applying","complete","rolling-back","rolled-back")
                    and type(row["completed"]) is list
                    and row["completed"]==list(STAGES[:len(row["completed"])])
                    and row["active"] in (None,*STAGES),
                    "migration-journal","foreign, changed or conflicting transaction")
        else:
            row={"schema":JOURNAL_SCHEMA,"migration_id":self.plan["migration_id"],
                 "plan_sha256":digest(self.plan),"status":"applying",
                 "completed":[],"active":None}
            self._save(row)
        return fd,row

    def execute(self, *, rollback=False, checkpoint=lambda phase:None):
        fd,row=self._open()
        try:
            require(not (row["status"]=="rolling-back" and not rollback)
                    and not (row["status"]=="rolled-back" and not rollback),
                    "migration-direction", "rollback cannot become a new apply")
            if rollback:
                require(row["status"]!="rolled-back" or all(
                    self.backend.state(stage)=="before" for stage in STAGES),
                    "migration-recovery","rolled-back state changed")
                row["status"]="rolling-back"
                self._save(row)
                for stage in reversed(STAGES):
                    state=self.backend.state(stage)
                    require(state in ("before","after"),"migration-recovery",
                            "unknown stage during rollback")
                    if state=="after":
                        row["active"]=stage
                        self._save(row)
                        checkpoint("rollback-before:"+stage)
                        self.backend.undo(stage)
                        require(self.backend.state(stage)=="before",
                                "migration-recovery","rollback postcondition failed")
                        checkpoint("rollback-after:"+stage)
                        row["active"]=None
                        self._save(row)
                row.update(status="rolled-back",active=None,completed=[])
            else:
                require(row["status"] in ("applying","complete"),"migration-direction",
                        "invalid migration direction")
                if row["status"]=="complete":
                    require(all(self.backend.state(stage)=="after" for stage in STAGES),
                            "migration-recovery","completed installation changed")
                    return {"status":"complete","migration_id":row["migration_id"],
                            "native_accepted":False,"service_activation_authorized":False}
                for stage in STAGES:
                    state=self.backend.state(stage)
                    require(state in ("before","after"),"migration-recovery",
                            "unrecognized partial or conflicting stage")
                    if stage in row["completed"]:
                        require(state=="after","migration-recovery",
                                "completed stage was reverted independently")
                    if state=="before":
                        row.update(status="applying",active=stage)
                        self._save(row)
                        checkpoint("apply-before:"+stage)
                        self.backend.apply(stage)
                        require(self.backend.state(stage)=="after",
                                "migration-recovery","stage postcondition failed")
                        checkpoint("apply-after:"+stage)
                    if stage not in row["completed"]:
                        require(row["completed"]==list(STAGES[:len(row["completed"])]),
                                "migration-journal","nonlinear completion")
                        row["completed"].append(stage)
                    row["active"]=None
                    self._save(row)
                row.update(status="complete",active=None)
            self._save(row)
            return {"status":row["status"],"migration_id":row["migration_id"],
                    "native_accepted":False,"service_activation_authorized":False}
        finally:os.close(fd)
