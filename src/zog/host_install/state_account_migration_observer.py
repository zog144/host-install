"""Read-only native Linux NSS and systemd observation for explicit account migration.

Native source admission must not accept a gateway's arbitrary after=true flag.
NSS is re-read at every decision. Service state is checked separately; stopped
and restored are historical journal milestones, not simultaneously true
ActiveState conditions.
"""
import grp
import os
import pwd
import subprocess

from .state_contract import StateError, require

GROUPS = {
    "archive-consumers-gid-updated": ("archive-consumers",990,972),
    "host-discover-group-gid-updated": ("host-discover",991,970),
}
USER_VALUES = {
    "host-discover-primary-gid-updated": ("host-discover","pw_gid",991,970),
    "host-discover-uid-updated": ("host-discover","pw_uid",991,970),
    "host-discover-home-updated": (
        "host-discover","pw_dir","/home/host-discover","/state/host-discover"),
    "host-discover-shell-updated": (
        "host-discover","pw_shell","/sbin/nologin","/usr/sbin/nologin"),
}
CREATED_GROUPS = {
    "host-control-group-created": ("host-control",973),
    "box-control-group-created": ("box-control",971),
}


def _state(value,before,after):
    if value==before:return "before"
    if value==after:return "after"
    return "conflict"


def _group(name):
    try:return grp.getgrnam(name)
    except KeyError:return None


def _user(name):
    try:return pwd.getpwnam(name)
    except KeyError:return None


def _members(name):
    return frozenset(g.gr_name for g in grp.getgrall() if name in g.gr_mem)


class NativeNSSSystemdObserver:
    """Root-only read-only view, never itself authorizing an account change."""

    def __init__(self, *, journal_stage_reader=None):
        require(os.geteuid()==0,"root-required","native NSS observer requires root")
        self._journal_stage_reader=journal_stage_reader

    def _systemctl(self,field):
        require(field in ("ActiveState","UnitFileState","NeedDaemonReload"),
                "migration-service","unsupported systemd field")
        p=subprocess.run(
            ["systemctl","show","host-discover.service",
             "--property="+field,"--value"],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=15,check=False)
        require(p.returncode==0 and len(p.stdout)<=256,
                "migration-service","actual systemd view unavailable")
        return p.stdout.decode("ascii","strict").strip()

    def stage_state(self,stage,plan):
        if stage in GROUPS:
            name,old,new=GROUPS[stage]
            item=_group(name)
            return "conflict" if item is None else _state(item.gr_gid,old,new)
        if stage in USER_VALUES:
            name,field,old,new=USER_VALUES[stage]
            item=_user(name)
            return "conflict" if item is None else _state(
                getattr(item,field),old,new)
        if stage in CREATED_GROUPS:
            name,gid=CREATED_GROUPS[stage]
            item=_group(name)
            return "before" if item is None else (
                "after" if item.gr_gid==gid else "conflict")
        if stage=="box-control-user-created":
            account=_user("box-control")
            return "before" if account is None else (
                "after" if (
                    account.pw_uid,account.pw_gid,account.pw_dir,
                    account.pw_shell)==
                    (971,971,"/state/box-control","/usr/sbin/nologin")
                else "conflict")
        if stage=="host-discover-supplementary-groups-updated":
            members=_members("host-discover")
            # The original NSS membership is empty. systemd independently
            # grants archive-consumers to the legacy running service; do not
            # confuse its SupplementaryGroups with usermod/secondary NSS.
            return _state(members,
                          frozenset(),
                          frozenset({"archive-consumers","host-control"}))
        if stage=="box-control-supplementary-groups-updated":
            return _state(_members("box-control"),
                          frozenset(),frozenset({"archive-consumers"}))
        if stage in ("service-stopped","service-restored"):
            status=self._systemctl("ActiveState")
            require(status in ("active","inactive"),
                    "migration-service","service failure/transition needs review")
            if stage=="service-restored":
                return _state(status,"inactive","active")
            # Once the service has been restored, the earlier stop is a
            # protected historical milestone. Read-only journal reader must
            # also confirm that later restoration completed.
            if status=="active" and self._journal_stage_reader is not None:
                completed=self._journal_stage_reader()
                if "service-restored" in completed:return "after"
            return _state(status,"active","inactive")
        if stage=="systemd-daemon-reloaded":
            value=self._systemctl("NeedDaemonReload")
            require(value in ("yes","no"),"migration-service",
                    "unknown systemd reload requirement")
            if self._journal_stage_reader is not None:
                completed=self._journal_stage_reader()
                if stage not in completed and "systemd-path-switched" not in completed:
                    return "before"
            return _state(value,"yes","no")
        raise StateError("migration-stage",
                         "only account and service source probes supported")

    def transition(self,stage,*,rollback=False):
        require(stage in ("service-stopped","service-restored",
                          "systemd-daemon-reloaded"),
                "migration-service","unreviewed service operation")
        if stage=="systemd-daemon-reloaded":
            action=["systemctl","daemon-reload"]
        else:
            target_active=(stage=="service-restored") != rollback
            action=["systemctl","start" if target_active else "stop",
                    "host-discover.service"]
        result=subprocess.run(
            action, stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=45,check=False)
        require(result.returncode==0,
                "migration-service","systemd command failed; reconcile transaction")
