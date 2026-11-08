"""Protected local retained-identity restart bridge (source-only, disabled).

A privileged host-install supervisor opens its OWN root-only transaction and
completion documents and verified canonical STATE directory, then passes only
two already-open descriptors to the unprivileged *existing* beacon. The
supervisor must not load or log a private key. No production entrypoint enabled.
"""
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from .state_account_migration import JOURNAL_SCHEMA, SCHEMA, STAGES
from .state_account_migration_completion import (
    _read_protected, COMPLETION_FILE,
)
from .state_account_migration_consumer import (
    COMPLETION_SCHEMA, CONSUMER_SELECTION, IDENTITY_DIRECTORY,
)
from .state_contract import StateError, decode, digest, require
from .state_inspect import inspect_live, directory

RUNTIME_ENABLED = False
TRANSACTION_DIRECTORY = "/var/lib/zog-host-install/migrations"
CONSUMER_EXECUTABLE = "/opt/host-discover/venv/bin/host-discover"
CONSUMER_CONFIGURATION = "/etc/host-discover/configuration.json"
CONSUMER_UID = 970
CONSUMER_GID = 970
CONSUMER_GROUPS = (972,973)


def _protected_fd(fd, limit=65536):
    return decode(_read_protected(fd,size=limit))


def validate_relaunch_fds(context, plan_fd, journal_fd, completion_fd,
                          identity_fd, *, expected_uid=CONSUMER_UID,
                          expected_gid=CONSUMER_GID):
    """Recheck exact source/STATE/receipt without loading any key bytes.

    Only native launcher opens these FDs from protected fixed paths. Passing
    arbitrary external FDs to this pure validator alone is not an authority.
    """
    require(os.geteuid()==0,"root-required","root owner FD bridge only")
    context.recheck()
    b=context.bundle["bootstrap"]
    plan=_protected_fd(plan_fd)
    journal_bytes=_read_protected(journal_fd)
    journal=decode(journal_bytes)
    receipt=_protected_fd(completion_fd,size=8192)
    require(type(plan) is dict and plan.get("schema")==SCHEMA
            and plan.get("status")=="SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
            and plan.get("consumer_selection_sha256")==digest(CONSUMER_SELECTION)
            and plan.get("bundle_sha256")==digest(context.bundle)
            and plan.get("installation_id")==b["installation_id"]
            and plan.get("state_volume_id")==b["state"]["state_volume_id"]
            and plan.get("root_fs_uuid")==b["state"]["filesystem_uuid"]
            and plan.get("root_partuuid")==b["state"]["partition_partuuid"]
            and plan.get("host_uuid")==b["initialization"]["expected_host_uuid"]
            and plan.get("public_fingerprint")==b["initialization"]["expected_fingerprint"]
            and context.mount.get("backend")=="root-directory",
            "migration-launcher","canonical installation/STATE source mismatch")
    controls=[row for row in b["registries"] if row["role"]=="control"]
    require(len(controls)==1 and plan["registry_origin"]==controls[0]["origin"],
            "migration-launcher","registry origin altered")
    require(type(journal) is dict and set(journal)=={
                "schema","migration_id","plan_sha256","status","completed","active"}
            and journal["schema"]==JOURNAL_SCHEMA
            and journal["migration_id"]==plan["migration_id"]
            and journal["plan_sha256"]==digest(plan)
            and journal["status"]=="complete" and journal["active"] is None
            and journal["completed"]==list(STAGES),
            "migration-launcher","migration not durably completed")
    require(type(receipt) is dict and
            receipt.get("schema")==COMPLETION_SCHEMA
            and receipt.get("status")=="complete"
            and receipt.get("migration_id")==plan["migration_id"]
            and receipt.get("identity_directory")==IDENTITY_DIRECTORY
            and receipt.get("host_uuid")==plan["host_uuid"]
            and receipt.get("fingerprint")==plan["public_fingerprint"]
            and receipt.get("registry_origin")==plan["registry_origin"]
            and receipt.get("plan_sha256")==digest(plan)
            and receipt.get("journal_sha256")==
                hashlib.sha256(journal_bytes).hexdigest()
            and receipt.get("uid")==expected_uid and
                receipt.get("gid")==expected_gid,
            "migration-launcher","foreign or incomplete root receipt")
    actual=os.fstat(identity_fd)
    require(stat.S_ISDIR(actual.st_mode)
            and (actual.st_uid,actual.st_gid,stat.S_IMODE(actual.st_mode))==
                (expected_uid,expected_gid,0o700)
            and [actual.st_dev,actual.st_ino]==receipt["identity_inode"],
            "migration-launcher","identity directory descriptor substituted")
    home=os.open("host-discover",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                 dir_fd=context.fd)
    try:
        held=os.open("identity",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                     dir_fd=home)
        try:
            s=os.fstat(held)
            require([s.st_dev,s.st_ino]==receipt["identity_inode"],
                    "migration-launcher","verified STATE identity path changed")
        finally:os.close(held)
    finally:os.close(home)
    context.recheck()
    return {"status":"reviewed-retained-identity-relaunch",
            "host_uuid":plan["host_uuid"],
            "public_fingerprint":plan["public_fingerprint"],
            "migration_id":plan["migration_id"],
            "service_uid":expected_uid,
            "service_gid":expected_gid,
            "remote_control_authorized":False}


def selected_beacon_argv(identity_fd, completion_fd, public_fingerprint):
    require(type(identity_fd) is int and type(completion_fd) is int
            and 3 <= identity_fd != completion_fd >= 3
            and type(public_fingerprint) is str
            and len(public_fingerprint)==64
            and all(c in "0123456789abcdef" for c in public_fingerprint),
            "migration-launcher","invalid pre-opened descriptor selection")
    return [
        CONSUMER_EXECUTABLE,
        "--configuration",CONSUMER_CONFIGURATION,
        "--existing-legacy-migration",
        "--retained-identity-fd",str(identity_fd),
        "--migration-completion-fd",str(completion_fd),
        "--retained-fingerprint",public_fingerprint,
    ]


def source_only_main():
    """The reviewed root launcher is not a production-activated entrypoint."""
    require(RUNTIME_ENABLED,"migration-native-hold",
            "protected retained migration launcher is not yet activated")
    raise StateError("migration-native-hold",
                     "native installed-byte and systemd acceptance missing")


def main():
    source_only_main()


if __name__ == "__main__":
    main()
