"""Migration-only canonical STATE configuration and layout publication.

The ordinary fresh install path stays unchanged. These entrypoints take a
root-owned *open journal FD* checked for the exact active migration stage, and
publish only fixed canonical host-install records. No identity key is created.
"""
import os
import stat
from pathlib import Path

from .state_account_migration import JOURNAL_SCHEMA, STAGES, SCHEMA
from .state_account_migration_completion import _read_protected
from .state_contract import StateError, canonical, decode, digest, require, validate
from .state_io import ensure_directory, publish
from .state_inspect import directory, metadata
from .state_provision import prepare_tree


def verify_active_stage(plan, journal_fd, stage):
    require(os.geteuid()==0,"root-required","privileged installer only")
    require(type(plan) is dict and plan.get("schema")==SCHEMA
            and stage in ("canonical-configuration-published",
                          "state-layout-prepared"),
            "migration-stage","only selected migration storage stages")
    row=decode(_read_protected(journal_fd,size=65536))
    position=STAGES.index(stage)
    require(type(row) is dict and set(row)=={
        "schema","migration_id","plan_sha256","status","completed","active"}
        and row["schema"]==JOURNAL_SCHEMA
        and row["migration_id"]==plan["migration_id"]
        and row["plan_sha256"]==digest(plan)
        and row["status"]=="applying" and row["active"]==stage
        and row["completed"]==list(STAGES[:position]),
        "migration-stage","no committed matching stage intent")
    return row


def _parent(fd,name,uid=0,gid=0,mode=0o755):
    return ensure_directory(fd,name,uid,gid,mode)


def publish_migration_configuration(bundle, plan, journal_fd,
                                    *, disposable_root=None,
                                    checkpoint=lambda _:None):
    """Publish closed new record set; bootstrap is the last commit marker.

    disposable_root is allowed for source tests only. Real root publication
    requires the independently verified native adapter and still has no
    user-facing command in this PR.
    """
    verify_active_stage(plan,journal_fd,"canonical-configuration-published")
    validate(bundle)
    require(bundle["installation"]["operation"]=="migration"
            and bundle["bootstrap"]["mode"]=="migration"
            and digest(bundle)==plan["bundle_sha256"]
            and bundle["bootstrap"]["state"]["filesystem_uuid"]==
                plan["root_fs_uuid"],
            "migration-records","selected original migration bundle required")
    root=Path("/") if disposable_root is None else Path(disposable_root).absolute()
    if root!=Path("/"):
        require(root.is_dir() and not root.is_symlink()
                and root.stat().st_uid==0,
                "migration-records","root-owned test tree required")
    root_fd=directory(str(root))
    opened=[]
    current=root_fd
    try:
        for part in ("etc","zog","host-install"):
            current=_parent(current,part)
            opened.append(current)
        # Do not adopt any unknown canonical configuration.
        require(set(os.listdir(current)) <= {
            ".host-install.lock",
            "accounts.json","installation.json","bootstrap.json",
            ".pending.accounts.json",".pending.installation.json",
            ".pending.bootstrap.json"},
            "migration-records","preexisting configuration not selected")
        for name in ("accounts","installation","bootstrap"):
            publish(current,name+".json",canonical(bundle[name]),0o444,
                    checkpoint=checkpoint)
        os.fsync(current)
        return {"status":"migration-configuration-published",
                "bundle_sha256":digest(bundle),"native_accepted":False}
    finally:
        for fd in reversed(opened):os.close(fd)
        os.close(root_fd)


def prepare_migration_layout(context, selected_state_id, plan, journal_fd,
                             *, checkpoint=lambda _:None,
                             service_ids=(970,970,971,971)):
    """Only checked open STATE descriptor + root-owned journal allow migration.

    No Host identity initialization/consumption receipt is fabricated.
    """
    verify_active_stage(plan,journal_fd,"state-layout-prepared")
    bundle=context.bundle
    validate(bundle)
    require(os.geteuid()==0 and
            bundle["installation"]["operation"]=="migration"
            and bundle["bootstrap"]["mode"]=="migration"
            and bundle["marker"]["kind"]=="zog-state-directory"
            and digest(bundle)==plan["bundle_sha256"]
            and bundle["bootstrap"]["state"]["state_volume_id"]==
                plan["state_volume_id"]==selected_state_id
            and bundle["bootstrap"]["state"]["filesystem_uuid"]==
                plan["root_fs_uuid"]
            and context.mount.get("backend")=="root-directory",
            "migration-state","verified root-directory STATE and plan required")
    context.recheck()
    result=prepare_tree(context,selected_state_id,checkpoint,
                        service_ids=service_ids,
                        _verified_migration_stage=True)
    context.recheck()
    require(result["identity_created"] is False and
            result["control_authorized"] is False,
            "migration-state","layout must not initialize an identity")
    return {**result,"migration_id":plan["migration_id"],
            "native_accepted":False}
