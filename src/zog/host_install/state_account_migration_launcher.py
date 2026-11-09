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


def _protected_fd(fd, size=65536):
    return decode(_read_protected(fd,size=size))


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


def selected_beacon_argv(identity_fd, completion_fd, public_fingerprint, *, runtime=None):
    require(type(identity_fd) is int and type(completion_fd) is int
            and 3 <= identity_fd != completion_fd >= 3
            and type(public_fingerprint) is str
            and len(public_fingerprint)==64
            and all(c in "0123456789abcdef" for c in public_fingerprint),
            "migration-launcher","invalid pre-opened descriptor selection")
    if runtime is not None:
        from .state_account_migration_admission import (
            CANDIDATE_EXECUTABLE, CANDIDATE_PYTHON, RUNTIME_SCHEMA,
        )
        require(type(runtime) is dict and
                runtime.get("schema") == RUNTIME_SCHEMA and
                runtime.get("executable") == CANDIDATE_EXECUTABLE and
                runtime.get("interpreter") == CANDIDATE_PYTHON and
                runtime.get("consumer_selection_sha256") ==
                    digest(CONSUMER_SELECTION),
                "migration-launcher", "unreviewed candidate runtime")
    return [
        CONSUMER_EXECUTABLE if runtime is None else runtime["executable"],
        "--configuration",CONSUMER_CONFIGURATION,
        "--existing-legacy-migration",
        "--retained-identity-fd",str(identity_fd),
        "--migration-completion-fd",str(completion_fd),
        "--retained-fingerprint",public_fingerprint,
    ]


def reviewed_launcher_dropin_template():
    """Not installable as-is: Work must select a verified Python 3.12 binary.

    Runtime selection is a root-owned launcher that drops to service UID 970;
    the old legacy service cannot inherit a root-only completion FD by itself.
    """
    return (
        "[Service]\n"
        "User=root\n"
        "Group=root\n"
        "ExecStart=\n"
        "ExecStart=@PINNED_HOST_INSTALL_PYTHON312@ -m "
        "zog.host_install.state_account_migration_launcher\n"
        "ReadWritePaths=\n"
        "ReadWritePaths=/state/host-discover/identity "
        "/var/lib/host-discover/credentials\n"
    ).encode("ascii")


def render_launcher_dropin(python_executable):
    """Produce a reviewed selection; do not touch installed units."""
    from .state_contract import require
    require(type(python_executable) is str
            and python_executable.startswith("/")
            and all(c.isalnum() or c in "/._-" for c in python_executable)
            and ".." not in python_executable.split("/")
            and python_executable.endswith("python3.12"),
            "migration-launcher","pinned Python 3.12 path required")
    return reviewed_launcher_dropin_template().replace(
        b"@PINNED_HOST_INSTALL_PYTHON312@",
        python_executable.encode("ascii"))


def render_selected_launcher_dropin(selection):
    """Pin the reviewed candidate Python path in a source-only drop-in.

    This produces bytes for review, not permission to install or activate them.
    """
    from .state_account_migration_admission import (
        ADMISSION_SCHEMA, CANDIDATE_EXECUTABLE, CANDIDATE_PYTHON,
        RUNTIME_SCHEMA,
    )
    require(type(selection) is dict and
            selection.get("schema") == ADMISSION_SCHEMA
            and type(selection.get("runtime")) is dict,
            "migration-launcher", "reviewed admission required")
    runtime=selection["runtime"]
    require(runtime.get("schema") == RUNTIME_SCHEMA and
            runtime.get("executable") == CANDIDATE_EXECUTABLE and
            runtime.get("interpreter") == CANDIDATE_PYTHON and
            runtime.get("consumer_selection_sha256") ==
                digest(CONSUMER_SELECTION),
            "migration-launcher", "consumer runtime not pinned")
    return render_launcher_dropin(runtime["interpreter"])


def run_selected_once():
    """Open trusted local sources anew on EACH restart; never inspect a key.

    Unreachable until a separately approved source change enables runtime.
    This is the actual subprocess/FD lifetime code, not a production claim.
    """
    require(RUNTIME_ENABLED and os.geteuid()==0,"migration-native-hold",
            "reviewed native service activation has not been approved")
    from .state_inspect import metadata
    with inspect_live() as context:
        root=directory(TRANSACTION_DIRECTORY)
        try:
            metadata(root,0,0,0o700)
            entries=os.listdir(root)
            require(len(entries)==1 and
                    __import__("zog.host_install.state_account_migration",
                               fromlist=["_uuid"])._uuid(entries[0]),
                    "migration-launcher","exactly one approved transaction required")
            migration_id=entries[0]
            folder=os.open(migration_id,
                           os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                           dir_fd=root)
            try:
                metadata(folder,0,0,0o700)
                def open_root_record(name):
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
                               dir_fd=folder)
                    try:
                        _read_protected(fd)
                        return fd
                    except BaseException:
                        os.close(fd)
                        raise
                plan_fd=open_root_record("plan.json")
                try:
                    journal_fd=open_root_record("transaction.json")
                    try:
                        completion_fd=open_root_record(COMPLETION_FILE)
                        try:
                            home=os.open("host-discover",
                                os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                                dir_fd=context.fd)
                            try:
                                identity_fd=os.open("identity",
                                    os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                                    dir_fd=home)
                                try:
                                    result=validate_relaunch_fds(
                                        context,plan_fd,journal_fd,
                                        completion_fd,identity_fd)
                                    require(result["migration_id"]==migration_id,
                                            "migration-launcher","wrong transaction directory")
                                    from .state_account_migration_admission import (
                                        ADMISSION_SCHEMA, select_runtime,
                                    )
                                    admission_fd=open_root_record("admission.json")
                                    try:
                                        admission=_protected_fd(admission_fd)
                                    finally:
                                        os.close(admission_fd)
                                    plan=_protected_fd(plan_fd)
                                    require(type(admission) is dict
                                            and admission.get("schema")==ADMISSION_SCHEMA
                                            and admission.get("plan")==plan
                                            and admission.get("bundle_sha256")==
                                                digest(context.bundle)
                                            and type(admission.get("runtime")) is dict
                                            and admission.get("authorization_reference"),
                                            "migration-launcher",
                                            "protected admission selection absent")
                                    runtime=admission["runtime"]
                                    selected=select_runtime(
                                        runtime["executable"],
                                        runtime["interpreter"],
                                        runtime["executable_sha256"],
                                        runtime["interpreter_sha256"])
                                    require(selected==runtime,
                                            "migration-launcher",
                                            "candidate installed-byte selection changed")
                                    args=selected_beacon_argv(
                                        identity_fd,completion_fd,
                                        result["public_fingerprint"],
                                        runtime=selected)
                                    context.recheck()
                                    # Only these two already-open descriptors
                                    # cross root -> UID 970. No secret content
                                    # appears in argv/environment/logs.
                                    child=subprocess.Popen(
                                        args,close_fds=True,
                                        pass_fds=(identity_fd,completion_fd),
                                        user=CONSUMER_UID,group=CONSUMER_GID,
                                        extra_groups=list(CONSUMER_GROUPS),
                                        stdin=subprocess.DEVNULL,
                                        env={"PATH":"/usr/bin:/bin",
                                             "LANG":"C.UTF-8"},
                                        cwd="/opt/host-discover")
                                    return child.wait()
                                finally:os.close(identity_fd)
                            finally:os.close(home)
                        finally:os.close(completion_fd)
                    finally:os.close(journal_fd)
                finally:os.close(plan_fd)
            finally:os.close(folder)
        finally:os.close(root)


def main():
    return run_selected_once()


if __name__ == "__main__":
    raise SystemExit(main())
