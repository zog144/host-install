"""Root-owned retained-identity completion: read-only postconditions and no new key.

The publication contract matches host-identify PR #1 exactly. This source does
not provide a production entrypoint, authorization to run account operations,
or a systemd descriptor launcher. Root-owned original witness must be created
before the first mutation and kept separately from the moved identity.
"""
import hashlib
import os
import stat

from .state_contract import StateError, canonical, decode, digest, require
from .state_account_migration_consumer import (
    COMPLETION_SCHEMA, IDENTITY_DIRECTORY, CONSUMER_SELECTION,
)
from .state_account_migration import JOURNAL_SCHEMA, SCHEMA, STAGES, _uuid
from .state_io import publish

WITNESS_SCHEMA = "zog-registry-legacy-identity-original-witness-v1"
COMPLETION_FILE = "retained-legacy-completion.json"
WITNESS_FIELDS = frozenset((
    "schema", "migration_id", "plan_sha256", "host_uuid", "fingerprint",
    "registry_origin", "identity_inode", "key_inode", "binding_inode",
    "lock_inode", "ca_inode", "ca_sha256",
))
INODE_FIELDS = ("identity_inode", "key_inode", "binding_inode", "lock_inode")
ENTRIES = {
    "identity.pem": "key_inode",
    "binding.json": "binding_inode",
    "key.lock": "lock_inode",
}


def _inode(s):
    return [s.st_dev, s.st_ino]


def _read_protected(fd, *, size=8192):
    s = os.fstat(fd)
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0
            and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1
            and 0 < s.st_size <= size
            and os.lseek(fd, 0, os.SEEK_SET) == 0,
            "migration-completion", "protected root document required")
    raw = os.read(fd, size + 1)
    require(len(raw) <= size and len(raw) == s.st_size,
            "migration-completion", "short or oversized protected document")
    return raw


def _pair(pair):
    return (type(pair) is list and len(pair) == 2
            and all(type(v) is int and v > 0 for v in pair))



def original_witness_from_fd(plan, identity_fd, *,
                             expected_uid=991, expected_gid=991):
    """Record ORIGINAL legacy entry identity before any migration mutation.

    Only public binding and optional CA bytes are inspected. The private key
    is never opened/read/serialized. The later retained-key consumer proves
    that the existing key corresponds to the original public fingerprint.
    This source helper does NOT authenticate the FD origin: native Work must
    open it from the independently verified legacy location, under the
    selected root transaction lock before stopping host-discover.
    """
    require(os.geteuid()==0, "root-required",
            "original identity witness requires root")
    require(type(plan) is dict and plan.get("schema")==SCHEMA
            and plan.get("status")=="SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
            and _uuid(plan.get("migration_id"))
            and plan.get("consumer_selection_sha256")==digest(CONSUMER_SELECTION)
            and type(expected_uid) is int and type(expected_gid) is int,
            "migration-witness", "selected migration plan required")
    directory=os.fstat(identity_fd)
    require(stat.S_ISDIR(directory.st_mode)
            and (directory.st_uid,directory.st_gid,
                 stat.S_IMODE(directory.st_mode))==
                (expected_uid,expected_gid,0o700),
            "migration-witness","original identity owner/mode unrecognized")
    entries=set(os.listdir(identity_fd))
    require(entries in (set(ENTRIES),set(ENTRIES)|{"registry-ca.pem"}),
            "migration-witness","unexpected original identity entry")
    pairs={"identity_inode":_inode(directory)}
    contents={}
    for name,field in list(ENTRIES.items()) + (
            [("registry-ca.pem","ca_inode")] if "registry-ca.pem" in entries
            else []):
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                   dir_fd=identity_fd)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode)
                    and info.st_nlink==1
                    and info.st_dev==directory.st_dev
                    and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==
                        (expected_uid,expected_gid,0o600)
                    and 0 <= info.st_size <= 32768,
                    "migration-witness","unrecognized identity file metadata")
            pairs[field]=_inode(info)
            if name in ("binding.json","registry-ca.pem"):
                # These are public metadata/certificate bytes, never a
                # secret key. The key is verified by host-identify on use.
                value=os.read(fd,32769)
                require(len(value)==info.st_size,
                        "migration-witness","public evidence size changed")
                contents[name]=value
        finally:os.close(fd)
    binding=decode(contents["binding.json"])
    require(type(binding) is dict
            and set(binding)=={"host_id","fingerprint"}
            and binding["host_id"]==plan["host_uuid"]
            and binding["fingerprint"]==plan["public_fingerprint"],
            "migration-witness","original public identity binding differs")
    # No legacy key fingerprint is inferred merely from binding: the exact
    # Ed25519 private key is authenticated by the retained loader later.
    witness={
        "schema":WITNESS_SCHEMA,
        "migration_id":plan["migration_id"],
        "plan_sha256":digest(plan),
        "host_uuid":plan["host_uuid"],
        "fingerprint":plan["public_fingerprint"],
        "registry_origin":plan["registry_origin"],
        **pairs,
        "ca_inode":pairs.get("ca_inode"),
        "ca_sha256":(
            hashlib.sha256(contents["registry-ca.pem"]).hexdigest()
            if "registry-ca.pem" in entries else None),
    }
    require(set(witness)==WITNESS_FIELDS,
            "migration-witness","incomplete original identity witness")
    return witness


def publish_original_witness(root_fd, witness, *,
                             checkpoint=lambda _:None):
    """First durable mutation: publish root-owned original inode evidence.

    Caller must authenticate the exact journal parent and hold the permanent
    owner lock. Repeat same bytes is allowed; replacement is prohibited.
    """
    require(os.geteuid()==0 and type(witness) is dict
            and set(witness)==WITNESS_FIELDS
            and witness["schema"]==WITNESS_SCHEMA,
            "migration-witness","exact pre-migration witness required")
    root=os.fstat(root_fd)
    require(stat.S_ISDIR(root.st_mode)
            and (root.st_uid,root.st_gid,stat.S_IMODE(root.st_mode))==
                (0,0,0o700),
            "migration-witness","protected root-owned parent required")
    publish(root_fd,"original.json",canonical(witness),0o600,
            checkpoint=checkpoint)
    return {"status":"original-witness-published",
            "witness_sha256":digest(witness),"mutation_authorized":False}


def completion_from_observed_fds(
    *, plan, original_witness_fd, journal_fd, identity_fd,
    identity_directory=IDENTITY_DIRECTORY, expected_uid=970, expected_gid=970,
):
    """Consume independent original root witness and completed durable journal.

    This is an evidence builder, not a migration authorizer. Caller MUST hold
    the native transaction lock and independently check /state mount+config,
    journal directory, and FD origin before use.
    """
    require(os.geteuid() == 0, "root-required", "root completion issuer only")
    require(type(plan) is dict and plan.get("schema") == SCHEMA
            and plan.get("status") == "SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
            and _uuid(plan.get("migration_id"))
            and identity_directory == IDENTITY_DIRECTORY
            and type(expected_uid) is int and type(expected_gid) is int,
            "migration-completion", "unrecognized migration selection")
    root_witness = decode(_read_protected(original_witness_fd))
    raw_journal = _read_protected(journal_fd, size=65536)
    journal = decode(raw_journal)
    require(type(root_witness) is dict and set(root_witness) == WITNESS_FIELDS
            and root_witness["schema"] == WITNESS_SCHEMA
            and root_witness["migration_id"] == plan["migration_id"]
            and root_witness["plan_sha256"] == digest(plan)
            and root_witness["host_uuid"] == plan["host_uuid"]
            and root_witness["fingerprint"] == plan["public_fingerprint"]
            and root_witness["registry_origin"] == plan["registry_origin"]
            and all(_pair(root_witness[key]) for key in INODE_FIELDS)
            and ((root_witness["ca_inode"] is None
                  and root_witness["ca_sha256"] is None)
                 or (_pair(root_witness["ca_inode"])
                     and type(root_witness["ca_sha256"]) is str
                     and len(root_witness["ca_sha256"]) == 64
                     and all(c in "0123456789abcdef"
                             for c in root_witness["ca_sha256"]))),
            "migration-completion", "original identity witness incorrect")
    require(type(journal) is dict
            and set(journal) == {"schema", "migration_id", "plan_sha256",
                                 "status", "completed", "active"}
            and journal["schema"] == JOURNAL_SCHEMA
            and journal["migration_id"] == plan["migration_id"]
            and journal["plan_sha256"] == digest(plan)
            and journal["status"] == "complete"
            and journal["active"] is None
            and journal["completed"] == list(STAGES),
            "migration-completion", "durable migration not completed")
    directory = os.fstat(identity_fd)
    require(stat.S_ISDIR(directory.st_mode)
            and (directory.st_uid, directory.st_gid,
                 stat.S_IMODE(directory.st_mode)) ==
                (expected_uid, expected_gid, 0o700)
            and _inode(directory) == root_witness["identity_inode"],
            "migration-completion", "original directory inode not preserved")
    entries = set(os.listdir(identity_fd))
    require(entries in (
        set(ENTRIES), set(ENTRIES) | {"registry-ca.pem"}),
        "migration-completion", "identity inventory changed")
    for name, inode_field in (
            list(ENTRIES.items()) + (
                [("registry-ca.pem", "ca_inode")] if "registry-ca.pem" in entries
                else [])):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=identity_fd)
        try:
            s = os.fstat(fd)
            require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
                    and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) ==
                        (expected_uid, expected_gid, 0o600)
                    and _inode(s) == root_witness[inode_field],
                    "migration-completion", "original key/binding/lock/CA changed")
            if name == "registry-ca.pem":
                require(s.st_size <= 32768
                        and hashlib.sha256(os.read(fd, 32769)).hexdigest() ==
                            root_witness["ca_sha256"],
                        "migration-completion", "retained registry CA changed")
        finally:
            os.close(fd)
    require(("registry-ca.pem" in entries) ==
            (root_witness["ca_inode"] is not None),
            "migration-completion", "retained CA inventory changed")
    record = {
        "schema": COMPLETION_SCHEMA, "status": "complete",
        "migration_id": plan["migration_id"],
        "identity_directory": identity_directory,
        "host_uuid": plan["host_uuid"], "fingerprint": plan["public_fingerprint"],
        "registry_origin": plan["registry_origin"],
        "uid": expected_uid, "gid": expected_gid,
        "identity_inode": root_witness["identity_inode"],
        "key_inode": root_witness["key_inode"],
        "binding_inode": root_witness["binding_inode"],
        "lock_inode": root_witness["lock_inode"],
        "ca_inode": root_witness["ca_inode"],
        "ca_sha256": root_witness["ca_sha256"],
        "plan_sha256": digest(plan),
        "journal_sha256": hashlib.sha256(raw_journal).hexdigest(),
    }
    return record


def publish_completion(directory_fd, receipt, *, checkpoint=lambda _: None):
    """No replacement of a conflicting completion; root mode 0600."""
    require(os.geteuid() == 0 and type(receipt) is dict
            and receipt.get("schema") == COMPLETION_SCHEMA
            and receipt.get("status") == "complete",
            "migration-completion", "root-owned verified completion required")
    stat_dir = os.fstat(directory_fd)
    require(stat.S_ISDIR(stat_dir.st_mode) and stat_dir.st_uid == 0
            and stat_dir.st_gid == 0
            and stat.S_IMODE(stat_dir.st_mode) == 0o700,
            "migration-completion", "protected completion parent required")
    publish(directory_fd, COMPLETION_FILE, canonical(receipt), 0o600,
            checkpoint=checkpoint)
    return {"status": "completion-published", "receipt_sha256": digest(receipt),
            "native_service_enabled": False}
