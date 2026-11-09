"""Root-owned, explicitly invoked admission of one registry STATE migration.

Local trust model: root OS administrator + protected fixed-path selection +
operator-confirmed preview digest. No external registrar or signer. This is
not independent proof that a human approved it: Work must authenticate its
administrative session/selection before invoking --admit.

No native account, daemon, identity, /state, or systemd mutation is possible
from this module. The initial protected journal is the only published fence.
"""
import argparse
import hashlib
from importlib import resources
import json
import os
import re
import stat

from .state_account_migration import _uuid
from .state_account_migration_admission import (
    assemble_migration_bundle, review_admission, initial_journal,
)
from .state_account_migration_completion import (
    original_witness_from_fd, open_original_legacy_identity_fd,
    publish_original_witness,
)
from .state_account_migration_live import (
    LiveNativeMigrationEvidence, _read_file,
)
from .state_contract import StateError, canonical, decode, digest, require
from .state_io import ensure_directory, lock, publish, raw

APPROVAL_PATH = "/root/zog-host-install-registry-migration-approval.json"
TRANSACTION_PARENT = "/var/lib/zog-host-install/migrations"
OPERATOR_SCHEMA = "zog-registry-migration-local-operator-selection-v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
FIELDS = frozenset({
    "schema", "migration_id", "installation_id", "state_volume_id",
    "installation_record_id", "authorization_id", "root_fs_uuid",
    "root_partuuid", "host_uuid", "fingerprint", "registry_origin",
    "identity_inode", "credential_inodes", "file_inventory_sha256",
    "configuration_sha256", "unit_sha256", "account_snapshot_sha256",
    "candidate_executable_sha256", "candidate_interpreter_sha256",
    "authorization_reference", "approved_admission_sha256",
})


def _pair(value):
    return (type(value) is list and len(value) == 2
            and all(type(n) is int and n > 0 for n in value))


def check_selection(selection):
    """Closed metadata-only operator selection, not self-authenticating."""
    uuids = ("migration_id", "installation_id", "state_volume_id",
             "installation_record_id", "authorization_id",
             "root_fs_uuid", "root_partuuid", "host_uuid")
    hashes = ("fingerprint", "file_inventory_sha256",
              "configuration_sha256", "unit_sha256",
              "account_snapshot_sha256", "candidate_executable_sha256",
              "candidate_interpreter_sha256")
    require(type(selection) is dict and set(selection) == FIELDS
            and selection.get("schema") == OPERATOR_SCHEMA
            and all(_uuid(selection.get(k)) for k in uuids)
            and len(set(selection[k] for k in uuids)) == len(uuids)
            and all(type(selection.get(k)) is str and
                    HEX.fullmatch(selection[k]) for k in hashes)
            and _pair(selection.get("identity_inode"))
            and type(selection.get("credential_inodes")) is dict
            and 0 < len(selection["credential_inodes"]) <= 128
            and all(type(name) is str and NAME.fullmatch(name)
                    and name not in (".", "..") and _pair(value)
                    for name, value in selection["credential_inodes"].items())
            and type(selection.get("registry_origin")) is str
            and selection["registry_origin"].startswith("https://")
            and not selection["registry_origin"].endswith("/")
            and type(selection.get("authorization_reference")) is str
            and re.fullmatch(r"[A-Za-z0-9_.:/-]{8,256}",
                             selection["authorization_reference"])
            and (selection.get("approved_admission_sha256") is None
                 or (type(selection["approved_admission_sha256"]) is str
                     and HEX.fullmatch(selection["approved_admission_sha256"]))),
            "migration-approval", "unreviewed operator selection")
    return selection


def operator_selection_from_protected_file():
    require(os.geteuid() == 0, "root-required",
            "only a local root administrator can admit a migration")
    raw_bytes = _read_file(APPROVAL_PATH)
    return check_selection(decode(raw_bytes))


def _template():
    """Validated shipped source template, never an operator-supplied bundle."""
    with resources.files("zog.host_install").joinpath(
            "migration-template.json").open("rb") as opened:
        raw_bytes = opened.read(65537)
    require(0 < len(raw_bytes) <= 65536,
            "migration-template", "invalid packaged template")
    return decode(raw_bytes)


def evaluate(selection, observation):
    """Verify every selected claim against fresh locally obtained evidence.

    Tests may pass disposable evidence; production explicitly requires the
    exact LiveNativeMigrationEvidence class and re-observes under owner lock.
    """
    selected = check_selection(selection)
    require(type(observation) is dict and
            set(observation) == {"source_inputs", "runtime",
                                 "identity_inodes", "credential_inodes",
                                 "root_device"},
            "migration-issuer", "complete independent observation required")
    original = observation["source_inputs"]
    require(selected["identity_inode"] ==
                observation["identity_inodes"]["directory"]
            and selected["credential_inodes"] == observation["credential_inodes"]
            and selected["file_inventory_sha256"] ==
                digest(original["file_inventory"])
            and selected["configuration_sha256"] ==
                hashlib.sha256(original["configuration_bytes"]).hexdigest()
            and selected["unit_sha256"] ==
                hashlib.sha256(original["unit_bytes"]).hexdigest()
            and selected["account_snapshot_sha256"] ==
                digest(original["account_snapshot"])
            and original["binding"] == {
                "host_id": selected["host_uuid"],
                "fingerprint": selected["fingerprint"],
            },
            "migration-issuer", "original Host evidence differs from approved selection")
    bundle = assemble_migration_bundle(
        _template(),
        installation_id=selected["installation_id"],
        state_volume_id=selected["state_volume_id"],
        installation_record_id=selected["installation_record_id"],
        authorization_id=selected["authorization_id"],
        root_fs_uuid=selected["root_fs_uuid"],
        root_partuuid=selected["root_partuuid"],
        host_uuid=selected["host_uuid"],
        fingerprint=selected["fingerprint"],
        registry_origin=selected["registry_origin"])
    admission = review_admission(
        bundle, original, observation["runtime"],
        original_identity_inodes=observation["identity_inodes"],
        original_credential_inodes=observation["credential_inodes"],
        authorization_reference=selected["authorization_reference"])
    require(admission["runtime"]["executable_sha256"] ==
                selected["candidate_executable_sha256"]
            and admission["runtime"]["interpreter_sha256"] ==
                selected["candidate_interpreter_sha256"],
            "migration-issuer", "installed candidate not operator-selected")
    return bundle, admission


def _protected_dir(fd, *, mode=0o700, expected_device=None):
    s = os.fstat(fd)
    require(stat.S_ISDIR(s.st_mode)
            and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) ==
                (0, 0, mode)
            and (expected_device is None or s.st_dev == expected_device),
            "migration-issuer", "protected journal ancestor or mount differs")


def _open_approved_journal_parent(root_device):
    """Create only the protected journal parents on selected host-root backing."""
    require(os.geteuid() == 0, "root-required", "root-only journal issuer")
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = root
    opened = []
    try:
        require(os.fstat(root).st_dev == root_device,
                "migration-issuer", "selected root device changed")
        for part in ("var", "lib"):
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW, dir_fd=current)
            s = os.fstat(next_fd)
            require(stat.S_ISDIR(s.st_mode) and s.st_uid == s.st_gid == 0
                    and not s.st_mode & 0o022 and s.st_dev == root_device,
                    "migration-issuer", "unsafe ancestor for protected journal")
            opened.append(next_fd)
            current = next_fd
        for part in ("zog-host-install", "migrations"):
            next_fd = ensure_directory(current, part, 0, 0, 0o700)
            _protected_dir(next_fd, expected_device=root_device)
            opened.append(next_fd)
            current = next_fd
        result = os.dup(current)
        return result
    finally:
        for fd in reversed(opened):
            os.close(fd)
        os.close(root)


def _publish_records(parent_fd, migration_id, *, bundle, admission, witness,
                     checkpoint=lambda _: None):
    """Publish exact bytes with the CALLER HOLDING the durable global lock.

    A pending file at a known stage is reconciled by state_io.publish, while
    unexpected names, conflicting bytes or a second migration all deny.
    """
    require(os.geteuid() == 0 and _uuid(migration_id)
            and admission["plan"]["migration_id"] == migration_id,
            "migration-issuer", "wrong protected transaction")
    _protected_dir(parent_fd)
    names = set(os.listdir(parent_fd))
    require(names <= {".admission.lock", migration_id,
                     ".pending-dir." + migration_id},
            "migration-issuer", "conflicting migration transaction exists")
    txfd = ensure_directory(parent_fd, migration_id, 0, 0, 0o700)
    try:
        _protected_dir(txfd, expected_device=os.fstat(parent_fd).st_dev)
        require(set(os.listdir(parent_fd)) ==
                {".admission.lock", migration_id},
                "migration-issuer", "foreign transaction or pending stage")
        expected = {
            "bundle.json": canonical(bundle),
            "plan.json": canonical(admission["plan"]),
            "admission.json": canonical(admission),
            "original.json": canonical(witness),
            "transaction.json": canonical(initial_journal(admission)),
        }
        recognized = (set(expected) |
                      {".pending." + name for name in expected})
        require(set(os.listdir(txfd)) <= recognized,
                "migration-issuer", "foreign transaction entry")
        for name in ("bundle.json", "plan.json", "admission.json"):
            publish(txfd, name, expected[name], 0o600,
                    checkpoint=checkpoint)
        publish_original_witness(txfd, witness, checkpoint=checkpoint)
        # An incomplete admission can never have an executable journal.
        publish(txfd, "transaction.json",
                expected["transaction.json"], 0o600,
                checkpoint=checkpoint)
        require(set(os.listdir(txfd)) == set(expected),
                "migration-issuer", "orphaned publication remains")
        os.fsync(txfd)
        os.fsync(parent_fd)
    finally:
        os.close(txfd)
    return {
        "status": "initial-admission-recorded",
        "migration_id": migration_id,
        "admission_sha256": digest(admission),
        "journal_initial_only": True,
        "native_execution_enabled": False,
    }


def preview(selected=None):
    """Read-only admission digest for separate administrator inspection."""
    require(os.geteuid() == 0, "root-required", "root-only admission preview")
    selected = (operator_selection_from_protected_file()
                if selected is None else check_selection(selected))
    observation = LiveNativeMigrationEvidence().inspect(selected)
    _, admission = evaluate(selected, observation)
    return {
        "status": "REVIEW_ONLY_NOT_AUTHORIZED",
        "migration_id": selected["migration_id"],
        "admission_sha256": digest(admission),
        "native_execution_enabled": False,
    }


def issue():
    """Production admission path; does not execute migration stages.

    The approved digest is a deliberate root-local operator confirmation,
    not a cryptographic signature. This command must run only in an
    independently authorized administrative session.
    """
    require(os.geteuid() == 0, "root-required",
            "root-only local admission issuer")
    selected = operator_selection_from_protected_file()
    require(selected["approved_admission_sha256"] is not None,
            "migration-approval", "operator has not approved preview digest")
    # Re-observe both before and while holding the durable owner lock. Actual
    # journal publication below happens before any identity/service mutation.
    evidence = LiveNativeMigrationEvidence()
    observation = evidence.inspect(selected)
    bundle, admission = evaluate(selected, observation)
    require(digest(admission) == selected["approved_admission_sha256"],
            "migration-approval", "operator approval does not match live selection")
    parentfd = _open_approved_journal_parent(observation["root_device"])
    try:
        # Establish exclusive journal ownership BEFORE reading original witness.
        with lock(parentfd, ".admission.lock"):
            observation = evidence.inspect(selected)
            bundle, admission = evaluate(selected, observation)
            require(digest(admission) ==
                    selected["approved_admission_sha256"],
                    "migration-approval", "live evidence changed under owner lock")
            identity_fd = open_original_legacy_identity_fd(
                selected["identity_inode"],
                expected_root_device=observation["root_device"])
            try:
                witness = original_witness_from_fd(
                    admission["plan"], identity_fd)
            finally:
                os.close(identity_fd)
            require(witness["identity_inode"] ==
                    observation["identity_inodes"]["directory"],
                    "migration-issuer", "original path replaced")
            # Same process serializes via flock; publication routine also
            # holds that permanent inode, allowing only exact-byte retries.
            result = _publish_records(
                parentfd, selected["migration_id"],
                bundle=bundle, admission=admission, witness=witness)
            return result
    finally:
        os.close(parentfd)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Root-local registry STATE migration admission (no execution)")
    chosen = parser.add_mutually_exclusive_group(required=True)
    chosen.add_argument("--preview", action="store_true",
                        help="read-only selected Host/preflight digest")
    chosen.add_argument("--admit", action="store_true",
                        help="create initial protected plan/witness/journal only")
    args = parser.parse_args(argv)
    result = preview() if args.preview else issue()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
