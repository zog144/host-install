"""Root-only explicit native migration actuator, never invoked by a normal boot.

This adapter is real Linux argv + filesystem machinery, but the production
entrypoint is HARD DISABLED pending native independent preflight, installed
consumer/source attestation, and authorized Work acceptance. Tests use a
disposable root with a synthetic account/service operator.
"""
import ctypes
import errno
import os
from pathlib import Path
import stat
import subprocess

from .state_account_migration import (
    STAGES, SOURCE, DESTINATION, CREDENTIALS, CONFIGURATION, SELECTED_UNIT,
    REQUIRED_IDENTITY_FILES, OPTIONAL_IDENTITY_FILES,
    changed_configuration, changed_unit_dropin,
)
from .state_contract import StateError, canonical, digest, require

NATIVE_ACTIVATION_ENABLED = False

ACCOUNT_COMMANDS = {
    "archive-consumers-gid-updated": (
        ["groupmod","-g","972","archive-consumers"],
        ["groupmod","-g","990","archive-consumers"]),
    "host-discover-group-gid-updated": (
        ["groupmod","-g","970","host-discover"],
        ["groupmod","-g","991","host-discover"]),
    "host-discover-primary-gid-updated": (
        ["usermod","-g","970","host-discover"],
        ["usermod","-g","991","host-discover"]),
    "host-discover-uid-updated": (
        ["usermod","-u","970","host-discover"],
        ["usermod","-u","991","host-discover"]),
    "host-discover-home-updated": (
        ["usermod","-d","/state/host-discover","host-discover"],
        ["usermod","-d","/home/host-discover","host-discover"]),
    "host-discover-shell-updated": (
        ["usermod","-s","/usr/sbin/nologin","host-discover"],
        ["usermod","-s","/sbin/nologin","host-discover"]),
    "host-control-group-created": (
        ["groupadd","-g","973","host-control"],
        ["groupdel","host-control"]),
    "box-control-group-created": (
        ["groupadd","-g","971","box-control"],
        ["groupdel","box-control"]),
    "box-control-user-created": (
        ["useradd","-u","971","-g","971","-d","/state/box-control",
         "-s","/usr/sbin/nologin","-M","box-control"],
        ["userdel","box-control"]),
    "host-discover-supplementary-groups-updated": (
        ["usermod","-G","archive-consumers,host-control","host-discover"],
        ["usermod","-G","archive-consumers","host-discover"]),
    "box-control-supplementary-groups-updated": (
        ["usermod","-G","archive-consumers","box-control"],
        ["usermod","-G","","box-control"]),
}
FILE_OWNERS = {
    "legacy-identity-owner-updated": (SOURCE, (991,991), (970,970)),
    "legacy-credentials-owner-and-group-updated":
        (CREDENTIALS,(991,990),(970,972)),
    "legacy-destinations-owner-updated":
        ("/var/lib/host-discover/beacon-destinations.json",
         (991,991),(970,970)),
}
FILE_STAGES = frozenset(FILE_OWNERS) | {
    "identity-moved", "configuration-path-switched",
    "systemd-path-switched", "canonical-configuration-published",
    "state-layout-prepared",
}


def exact_command(stage, rollback=False):
    require(stage in ACCOUNT_COMMANDS, "migration-stage",
            "unreviewed native account mutation")
    return tuple(ACCOUNT_COMMANDS[stage][bool(rollback)])


class RootCommandRunner:
    """No shell, no arbitrary argv, bounded command result and stderr."""
    def run(self, stage, *, rollback=False):
        args=exact_command(stage,rollback)
        require(os.geteuid()==0,"root-required","root-owned migration required")
        # Never resolve a root-capable account tool through inherited PATH.
        selected=("/usr/sbin/"+args[0],*args[1:])
        require(Path(selected[0]).is_file()
                and not Path(selected[0]).is_symlink(),
                "migration-native-command","account command binary missing")
        p=subprocess.run(selected, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         timeout=30,check=False,env={"PATH":"/usr/sbin:/usr/bin:/bin","LANG":"C"})
        require(p.returncode==0, "migration-native-command",
                "account command rejected; reconcile protected stage before retry")
        return p.returncode


def _noreplace(srcdir, src, dstdir, dst):
    """Atomic same-fs directory move; never replace an existing target."""
    libc=ctypes.CDLL(None,use_errno=True)
    fn=libc.renameat2
    fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,
                 ctypes.c_uint]
    fn.restype=ctypes.c_int
    if fn(srcdir,os.fsencode(src),dstdir,os.fsencode(dst),1)!=0:
        code=ctypes.get_errno()
        raise OSError(code,os.strerror(code),dst)


class NativeStageBackend:
    """Actual per-operation native state transitions through a protected plan.

    No arbitrary 'verified' flag is accepted: the source-selected owner must
    supply an independently authenticating probe. Live operation is disabled
    in this candidate; tests inject a disposable root, runner and probe.
    """
    DROPIN="/etc/systemd/system/host-discover.service.d/zog-state-migration.conf"

    def __init__(self, plan, *, filesystem_root="/", probe=None,
                 command_runner=None, initial_config=None,
                 original_identity_inodes=None,
                 original_credential_inodes=None, selected_file_inventory=None,
                 allow_disposable=False):
        require(os.geteuid()==0,"root-required","native adapter needs root")
        root=Path(filesystem_root).absolute()
        if root==Path("/"):
            require(NATIVE_ACTIVATION_ENABLED,"migration-native-hold",
                    "production native account/file mutation disabled")
            from .state_account_migration_observer import NativeNSSSystemdObserver
            require(type(probe) is NativeNSSSystemdObserver and
                    type(command_runner) is RootCommandRunner,
                    "migration-native-observer",
                    "production must use fresh protected NSS/systemd probes")
        else:
            require(allow_disposable and root.is_dir()
                    and not root.is_symlink() and
                    root.stat().st_uid == 0,
                    "migration-native-hold","disposable source test only")
        require(type(plan) is dict
                and plan.get("schema") ==
                    "zog-host-registry-directory-state-account-migration-v1"
                and plan.get("consumer_selection_sha256") is not None,
                "migration-consumer","reviewed retained consumer required")
        require(probe is not None and command_runner is not None,
                "migration-native-observer",
                "fresh installed account and service observer required")
        require(type(original_identity_inodes) is dict
                and REQUIRED_IDENTITY_FILES <=
                    set(original_identity_inodes) - {"directory"}
                and set(original_identity_inodes) <=
                    REQUIRED_IDENTITY_FILES | OPTIONAL_IDENTITY_FILES |
                    {"directory"}
                and all(type(pair) is list and len(pair)==2
                        and all(type(x) is int and x>0 for x in pair)
                        for pair in original_identity_inodes.values()),
                "migration-native-witness","closed original file inodes required")
        require(type(selected_file_inventory) is dict
                and digest(selected_file_inventory) ==
                    plan.get("file_inventory_metadata_sha256")
                and type(selected_file_inventory.get("credential_files")) is dict
                and 0 < len(selected_file_inventory["credential_files"]) <= 128,
                "migration-native-inventory",
                "full source-selected identity/credential inventory required")
        names=set(selected_file_inventory["credential_files"])
        require(type(original_credential_inodes) is dict
                and set(original_credential_inodes)==names
                and all(type(name) is str and name not in (".","..")
                        and __import__("re").fullmatch(r"[A-Za-z0-9_.-]{1,128}",name)
                        for name in names)
                and all(type(pair) is list and len(pair)==2
                        and all(type(x) is int and x>0 for x in pair)
                        for pair in original_credential_inodes.values()),
                "migration-native-inventory",
                "exact original credential inode witnesses required")
        if root==Path("/"):
            require(all(
                selected_file_inventory[name]["dev"] == pair[0]
                and selected_file_inventory[name]["inode"] == pair[1]
                for name,pair in original_identity_inodes.items()
                if name!="directory"),
                "migration-native-witness",
                "root original identity metadata differs from selected plan")
        require(type(initial_config) is bytes
                and changed_configuration(initial_config)
                and __import__("hashlib").sha256(initial_config).hexdigest()
                    == plan["configuration_before_sha256"],
                "migration-config","original configuration bytes required")
        self.plan=plan
        self.root=root
        self.probe=probe
        self.runner=command_runner
        self.original_identity_inodes=original_identity_inodes
        self.original_credential_inodes=original_credential_inodes
        self.credential_files=frozenset(names)
        self.original_config=initial_config
        self.target_config=changed_configuration(initial_config)

    def path(self, absolute):
        require(type(absolute) is str and absolute.startswith("/")
                and all(part not in (".","..") for part in absolute.split("/")),
                "unsafe-path","canonical absolute path required")
        path=self.root/absolute.lstrip("/")
        # No symlink traversal through an attacker-replaceable component.
        item=self.root
        for part in absolute.strip("/").split("/"):
            if not part:continue
            item=item/part
            if item.is_symlink():
                raise StateError("unsafe-path","symlink path component")
        return path

    def _status_files(self, stage):
        original,before,after=FILE_OWNERS[stage]
        root=self.path(original)
        if stage=="legacy-identity-owner-updated":
            moved=self.path(DESTINATION)
            require(root.exists() != moved.exists(),
                    "migration-native-file","identity missing or in both locations")
            if not root.exists():
                root=moved
        require(root.exists() and not root.is_symlink(),
                "migration-native-file","original file tree missing")
        paths=sorted(root.iterdir()) if root.is_dir() else []
        selected=[root,*paths]
        if stage=="legacy-identity-owner-updated":
            require({p.name for p in paths} ==
                    set(self.original_identity_inodes) - {"directory"},
                    "migration-native-inventory",
                    "original identity/role inventory changed")
        if stage=="legacy-credentials-owner-and-group-updated":
            require({p.name for p in paths} == self.credential_files,
                    "migration-native-inventory",
                    "credential files do not match selected protected inventory")
        changes=[]
        for p in selected:
            s=p.lstat()
            require(not p.is_symlink() and
                    (stat.S_ISREG(s.st_mode) and s.st_nlink==1
                     or stat.S_ISDIR(s.st_mode)),
                    "migration-native-file","unsafe file type/link")
            if stage=="legacy-identity-owner-updated":
                require(s.st_dev==root.lstat().st_dev and
                        (stat.S_ISDIR(s.st_mode) and
                         stat.S_IMODE(s.st_mode)==0o700 if p==root
                         else stat.S_ISREG(s.st_mode) and
                         stat.S_IMODE(s.st_mode)==0o600),
                        "migration-native-inventory",
                        "retained identity/role entry ownership layout changed")
                key="directory" if p==root else p.name
                if key in self.original_identity_inodes:
                    require([s.st_dev,s.st_ino]==self.original_identity_inodes[key],
                            "migration-native-witness",
                            "identity inode changed")
            if stage=="legacy-credentials-owner-and-group-updated":
                require(s.st_dev==root.lstat().st_dev
                        and (stat.S_ISDIR(s.st_mode) and
                             stat.S_IMODE(s.st_mode)==0o750 if p==root
                             else stat.S_ISREG(s.st_mode) and
                             stat.S_IMODE(s.st_mode)==0o640 and
                             [s.st_dev,s.st_ino]==
                                 self.original_credential_inodes[p.name]),
                        "migration-native-inventory",
                        "original credential inode or mode changed")
            pair=(s.st_uid,s.st_gid)
            require(pair in (before,after),"migration-native-owner",
                    "unrecognized ownership during migration")
            changes.append(pair)
        return ("after" if all(x==after for x in changes) else "before")

    def state(self,stage):
        require(stage in STAGES,"migration-stage","unreviewed stage")
        if stage in ACCOUNT_COMMANDS or stage in (
                "service-stopped","systemd-daemon-reloaded","service-restored"):
            return self.probe.stage_state(stage,self.plan)
        if stage in FILE_OWNERS:
            return self._status_files(stage)
        if stage=="identity-moved":
            before=self.path(SOURCE)
            after=self.path(DESTINATION)
            present=(before.exists(),after.exists())
            if present not in ((True,False),(False,True)):
                return "conflict"
            candidate=before if present[0] else after
            info=candidate.lstat()
            require(stat.S_ISDIR(info.st_mode)
                    and [info.st_dev,info.st_ino]==
                        self.original_identity_inodes["directory"],
                    "migration-native-witness","identity directory replaced")
            return "before" if present[0] else "after"
        if stage=="configuration-path-switched":
            current=self.path(CONFIGURATION).read_bytes()
            return ("before" if current==self.original_config
                    else "after" if current==self.target_config
                    else "conflict")
        if stage=="systemd-path-switched":
            dropin=self.path(self.DROPIN)
            return ("before" if not dropin.exists() else
                    "after" if dropin.is_file()
                    and dropin.read_bytes()==changed_unit_dropin()
                    else "conflict")
        # Canonical STATE/config are separately guarded by their dedicated
        # privileged filesystem publishers; no arbitrary empty mkdir.
        return self.probe.stage_state(stage,self.plan)

    def _chown_stage(self,stage,to_after):
        original,before,after=FILE_OWNERS[stage]
        target=after if to_after else before
        root=self.path(original)
        for p in [root,*sorted(root.iterdir())] if root.is_dir() else [root]:
            s=p.lstat()
            require((s.st_uid,s.st_gid) in (before,after)
                    and not p.is_symlink(),"migration-native-owner",
                    "foreign file owner/path")
            if stage=="legacy-identity-owner-updated":
                key="directory" if p==root else p.name
                require(key in self.original_identity_inodes and
                        s.st_dev==root.lstat().st_dev
                        and (stat.S_IMODE(s.st_mode)==0o700 if p==root
                             else stat.S_ISREG(s.st_mode)
                             and s.st_nlink==1
                             and stat.S_IMODE(s.st_mode)==0o600)
                        and [s.st_dev,s.st_ino]==
                            self.original_identity_inodes[key],
                        "migration-native-witness",
                        "unreviewed identity/role inode or mode")
            if stage=="legacy-credentials-owner-and-group-updated":
                require(
                    (p==root and stat.S_ISDIR(s.st_mode) and
                     stat.S_IMODE(s.st_mode)==0o750) or
                    (p!=root and p.name in self.credential_files and
                     stat.S_ISREG(s.st_mode) and s.st_nlink==1
                     and stat.S_IMODE(s.st_mode)==0o640
                     and [s.st_dev,s.st_ino]==
                         self.original_credential_inodes[p.name]),
                    "migration-native-inventory",
                    "unrecognized original credential entry")
            if (s.st_uid,s.st_gid)!=target:
                os.chown(p,*target,follow_symlinks=False)
                require((p.lstat().st_uid,p.lstat().st_gid)==target,
                        "migration-native-owner","owner update failed")
        dfd=os.open(root if root.is_dir() else root.parent,
                    os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(dfd)
        finally:os.close(dfd)

    def _move(self,rollback):
        source=self.path(DESTINATION if rollback else SOURCE)
        target=self.path(SOURCE if rollback else DESTINATION)
        require(source.is_dir() and not target.exists(),
                "migration-native-move","identity source/target conflict")
        src=source.parent;dst=target.parent
        require(src.is_dir() and dst.is_dir()
                and src.stat().st_dev==dst.stat().st_dev
                and source.stat().st_dev==src.stat().st_dev,
                "migration-native-move","cross filesystem or missing parent")
        a=os.open(src,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        b=os.open(dst,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            _noreplace(a,source.name,b,target.name)
            os.fsync(a);os.fsync(b)
        finally:os.close(b);os.close(a)
        require([target.stat().st_dev,target.stat().st_ino] ==
                self.original_identity_inodes["directory"],
                "migration-native-witness","move changed original inode")

    def _write_bytes(self,path,value,*,remove=False):
        target=self.path(path)
        if remove:
            require(target.is_file() and target.read_bytes()==value,
                    "migration-native-file","changed file cannot be removed")
            target.unlink()
            d=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(d)
            finally:os.close(d)
            return
        require(not target.exists(),"migration-native-file",
                "must not overwrite existing file")
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchmod(fd,0o600)
            view=memoryview(value)
            while view:
                n=os.write(fd,view)
                require(n>0,"migration-native-file","short write")
                view=view[n:]
            os.fsync(fd)
        finally:os.close(fd)
        d=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(d)
        finally:os.close(d)

    def _switch_config(self,rollback):
        # Atomic old/new byte-for-byte publication, unlike truncating write.
        path=self.path(CONFIGURATION)
        old=self.target_config if rollback else self.original_config
        new=self.original_config if rollback else self.target_config
        require(path.read_bytes()==old,
                "migration-native-config","current config not selected")
        staged=path.with_name(".pending.zog-host-discover-migration")
        if staged.exists():
            require(staged.is_file() and not staged.is_symlink()
                    and staged.read_bytes()==new,
                    "migration-native-config","pending config changed")
        else:
            self._write_bytes("/"+str(staged.relative_to(self.root)),new)
        os.replace(staged,path)
        d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(d)
        finally:os.close(d)
        require(path.read_bytes()==new,
                "migration-native-config","config switch not durable")

    def apply(self,stage):
        self._act(stage,False)

    def undo(self,stage):
        self._act(stage,True)

    def _act(self,stage,rollback):
        require(self.state(stage)==("after" if rollback else "before"),
                "migration-native-stage","step state not selected")
        if stage in ACCOUNT_COMMANDS:
            self.runner.run(stage,rollback=rollback)
        elif stage in ("service-stopped","systemd-daemon-reloaded",
                       "service-restored"):
            self.probe.transition(stage,rollback=rollback)
        elif stage in FILE_OWNERS:
            self._chown_stage(stage,not rollback)
        elif stage=="identity-moved":
            self._move(rollback)
        elif stage=="configuration-path-switched":
            self._switch_config(rollback)
        elif stage=="systemd-path-switched":
            dropin=self.path(self.DROPIN)
            if rollback:
                self._write_bytes(self.DROPIN,changed_unit_dropin(),remove=True)
            else:
                require(dropin.parent.is_dir(),
                        "migration-native-file","unreviewed systemd dropin path")
                self._write_bytes(self.DROPIN,changed_unit_dropin())
        else:
            # Canonical /state and /etc publication must use their separate
            # reviewed privileged publishers, not arbitrary mkdir or writes.
            self.probe.transition(stage,rollback=rollback)
        require(self.state(stage)==("before" if rollback else "after"),
                "migration-native-stage","native stage postcondition failed")
