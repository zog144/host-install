"""Selected root-local registry STATE migration executor entrypoint.

Installed source path, not a remote bootstrap API: the operator chooses one
already admitted transaction, not a new installation/key/issuer. The legacy
beacon must remain operable until the retained-identity launcher is installed
and independently attested. Actual mutation remains gated by the two native
source activation constants pending installed recovery acceptance.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat

from .state_account_migration import (
    SCHEMA, STAGES, MigrationJournal, SOURCE, DESTINATION, CONFIGURATION,
    changed_configuration, _uuid,
)
from .state_account_migration_admission import select_runtime
from .state_account_migration_completion import (
    WITNESS_SCHEMA, WITNESS_FIELDS, _read_protected,
)
from .state_account_migration_issuer import (
    verify_operator_binding, _protected_dir,
)
from .state_account_migration_launcher import (
    TRANSACTION_DIRECTORY, RUNTIME_ENABLED,
)
from .state_account_migration_native import (
    NATIVE_ACTIVATION_ENABLED, NativeStageBackend, RootCommandRunner,
)
from .state_account_migration_observer import NativeNSSSystemdObserver
from .state_contract import canonical, decode, digest, require, validate
from .state_inspect import _mount
from .state_io import lock

TRANSACTION_FILES = frozenset({
    "bundle.json", "plan.json", "admission.json",
    "operator-selection.json", "source-inventory.json", "original.json",
    "transaction.json",
    ".transaction.lock", "retained-legacy-completion.json",
    ".pending.retained-legacy-completion.json", ".transaction.pending",
})


def _read_selected(folder_fd, name):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,
               dir_fd=folder_fd)
    try:
        return decode(_read_protected(fd, size=65536))
    finally:
        os.close(fd)


def review_protected_transaction(parent_fd, migration_id):
    """Read-only closed evidence; no fabricated pre-migration approval."""
    require(os.geteuid()==0 and _uuid(migration_id),
            "migration-native-selection", "root and exact migration UUID required")
    _protected_dir(parent_fd)
    names=set(os.listdir(parent_fd))
    require(".admission.lock" in names
            and names- {".admission.lock"} == {migration_id},
            "migration-native-selection", "one admitted transaction required")
    root=os.open(migration_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,
                 dir_fd=parent_fd)
    try:
        _protected_dir(root,expected_device=os.fstat(parent_fd).st_dev)
        entries=set(os.listdir(root))
        required={"bundle.json","plan.json","admission.json",
                  "operator-selection.json","source-inventory.json",
                  "original.json","transaction.json"}
        require(required <= entries and entries <= TRANSACTION_FILES,
                "migration-native-selection", "foreign transaction entries")
        b=_read_selected(root,"bundle.json")
        plan=_read_selected(root,"plan.json")
        admission=_read_selected(root,"admission.json")
        operator=_read_selected(root,"operator-selection.json")
        file_inventory=_read_selected(root,"source-inventory.json")
        witness=_read_selected(root,"original.json")
        journal=_read_selected(root,"transaction.json")
        validate(b)
        require(type(plan) is dict and plan.get("schema")==SCHEMA
                and plan.get("migration_id")==migration_id
                and plan.get("status")=="SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
                and type(admission) is dict
                and admission.get("plan")==plan
                and admission.get("bundle_sha256")==digest(b)
                and plan.get("bundle_sha256")==digest(b)
                and plan.get("consumer_selection_sha256") ==
                    admission["runtime"].get("consumer_selection_sha256")
                and type(witness) is dict
                and set(witness)==WITNESS_FIELDS
                and witness.get("schema")==WITNESS_SCHEMA
                and witness.get("migration_id")==migration_id
                and witness.get("plan_sha256")==digest(plan)
                and witness.get("host_uuid")==plan.get("host_uuid")
                and witness.get("fingerprint")==plan.get("public_fingerprint")
                and witness.get("registry_origin")==plan.get("registry_origin")
                and digest(file_inventory)==plan.get(
                    "file_inventory_metadata_sha256")
                and digest(file_inventory)==operator.get(
                    "file_inventory_sha256")
                and journal.get("migration_id")==migration_id
                and journal.get("plan_sha256")==digest(plan),
                "migration-native-selection", "foreign admission or original evidence")
        verify_operator_binding(operator,admission)
        runtime=admission["runtime"]
        candidate=select_runtime(
            runtime["executable"],runtime["interpreter"],
            runtime["executable_sha256"],runtime["interpreter_sha256"])
        require(candidate==runtime,
                "migration-native-selection", "candidate installed bytes changed")
        return {
            "bundle":b, "plan":plan, "admission":admission,
            "operator":operator, "witness":witness,
            "journal":journal, "file_inventory":file_inventory,
            "folder":migration_id,
        }
    finally:
        os.close(root)


def _original_configuration(plan):
    """Reconstruct only a byte-for-byte reversible original config."""
    candidate=Path(CONFIGURATION)
    data=candidate.read_bytes()
    require(len(data)<=65536,
            "migration-native-selection", "bounded configuration required")
    expected=plan["configuration_before_sha256"]
    if hashlib.sha256(data).hexdigest()==expected:
        return data
    previous=changed_configuration(data,old=DESTINATION,new=SOURCE)
    require(hashlib.sha256(previous).hexdigest()==expected
            and changed_configuration(previous)==data,
            "migration-native-selection",
            "current configuration is neither selected before nor after")
    return previous


def inspect_installed_transaction(migration_id):
    """Native read-only gate to link installed issuer/consumer/executor."""
    require(os.geteuid()==0 and _uuid(migration_id),
            "migration-native-selection", "root operator selection required")
    parent=Path(TRANSACTION_DIRECTORY)
    require(parent.is_dir() and not parent.is_symlink(),
            "migration-native-selection", "issuer's protected storage absent")
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        observed=review_protected_transaction(fd,migration_id)
    finally:
        os.close(fd)
    from .state_account_migration_consumer import CONSUMER_SELECTION
    require(observed["admission"]["runtime"]["consumer_selection_sha256"] ==
            digest(CONSUMER_SELECTION),
            "migration-native-selection", "unreviewed retained consumer selection")
    # This is observed backing identity; no /state marker is required before
    # the journal stage that creates /state.
    mount=_mount(observed["bundle"])
    require(mount.get("backend")=="root-directory"
            and mount["device"] ==
                str(os.major(os.stat("/").st_dev))+":"+
                str(os.minor(os.stat("/").st_dev)),
            "migration-native-selection", "foreign host root backing")
    original=_original_configuration(observed["plan"])
    observed["original_configuration"]=original
    observed["native_activation_enabled"]=(
        NATIVE_ACTIVATION_ENABLED and RUNTIME_ENABLED)
    return observed


def execute(migration_id, *, rollback=False, expected_admission_sha256):
    """Explicit root-local action, never triggered by systemd or admission."""
    require(type(expected_admission_sha256) is str
            and len(expected_admission_sha256)==64
            and all(ch in "0123456789abcdef"
                    for ch in expected_admission_sha256),
            "migration-native-selection",
            "operator-approved exact admission digest required")
    require(NATIVE_ACTIVATION_ENABLED and RUNTIME_ENABLED,
            "migration-native-hold",
            "native executor and retained launcher are not installed/accepted")
    parent=os.open(TRANSACTION_DIRECTORY,
                   os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        # The same permanent parent lock is used by the admission issuer;
        # no second mutable transaction can appear while executing.
        with lock(parent,".admission.lock"):
            selected=review_protected_transaction(parent,migration_id)
            require(digest(selected["admission"]) ==
                    expected_admission_sha256,
                    "migration-native-selection",
                    "operator's exact admission selection changed")
            observed=inspect_installed_transaction(migration_id)
            plan=observed["plan"]
            inventory=observed["admission"]["identity_inodes"]
            credentials=observed["admission"]["credential_inodes"]
            root=Path(TRANSACTION_DIRECTORY)/migration_id
            probe=NativeNSSSystemdObserver(
                journal_stage_reader=lambda: _read_completed(root))
            backend=NativeStageBackend(
                plan,probe=probe,command_runner=RootCommandRunner(),
                initial_config=observed["original_configuration"],
                original_identity_inodes=inventory,
                original_credential_inodes=credentials,
                selected_file_inventory=_selected_file_inventory(plan,observed),
                selected_admission=observed["admission"],
                selected_bundle=observed["bundle"],journal_root=root)
            engine=MigrationJournal(root,plan,backend,require_root=True)
            return engine.execute(rollback=rollback)
    finally:
        os.close(parent)


def _selected_file_inventory(plan, observed):
    inventory=observed["file_inventory"]
    require(type(inventory) is dict
            and digest(inventory)==plan["file_inventory_metadata_sha256"]
            and digest(inventory)==observed["operator"][
                "file_inventory_sha256"],
            "migration-native-selection",
            "original inventory does not match protected admission")
    return inventory


def _read_completed(root):
    from .state_account_migration import STAGES
    data=decode((root/"transaction.json").read_bytes())
    return data["completed"] if (data.get("completed") is not None
                                  and type(data["completed"]) is list
                                  and all(x in STAGES for x in
                                          data["completed"])) else []


def main(argv=None):
    parser=argparse.ArgumentParser(
        description="Root-local retained identity migration executor (held)")
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--inspect",action="store_true")
    action.add_argument("--apply",action="store_true")
    action.add_argument("--rollback",action="store_true")
    parser.add_argument("--migration-id",required=True)
    parser.add_argument("--admission-sha256")
    args=parser.parse_args(argv)
    if args.inspect:
        result=inspect_installed_transaction(args.migration_id)
        result={
            "status":"NATIVE_SOURCE_REVIEW_ONLY",
            "migration_id":args.migration_id,
            "admission_sha256":digest(result["admission"]),
            "native_activation_enabled":result["native_activation_enabled"],
            "source_hold":"safe canonical STATE rollback and native acceptance pending",
        }
    else:
        result=execute(args.migration_id,
                       rollback=args.rollback,
                       expected_admission_sha256=args.admission_sha256)
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
