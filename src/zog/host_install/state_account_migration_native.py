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

NATIVE_ACTIVATION_ENABLED = True  # Explicit root-local transaction only; never automatic

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
        # Restore actual original NSS membership: none. The old service's
        # archive-consumers access came from systemd, not /etc/group.
        ["usermod","-G","","host-discover"]),
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


def quarantine_selected_directory(source, destination_parent, destination):
    """No-replace preservation of selected root-owned rollback evidence.

    This fixed-shape primitive is also exercised on disposable test roots.
    Never recursively delete or overwrite a STATE tree that may have carried
    service data since the first successful retained-identity launch.
    """
    require(os.geteuid()==0 and source.name in ("state","host-install")
            and destination in ("rolled-back-state",
                                "rolled-back-configuration")
            and ((source.name=="state" and
                  destination=="rolled-back-state") or
                 (source.name=="host-install" and
                  destination=="rolled-back-configuration")),
            "migration-native-rollback", "unselected directory quarantine")
    require(source.is_dir() and not source.is_symlink()
            and destination_parent.is_dir()
            and not destination_parent.is_symlink()
            and (source.stat().st_uid,source.stat().st_gid,
                 stat.S_IMODE(source.stat().st_mode))==(0,0,0o755)
            and (destination_parent.stat().st_uid,
                 destination_parent.stat().st_gid,
                 stat.S_IMODE(destination_parent.stat().st_mode))==(0,0,0o700)
            and source.stat().st_dev==
                destination_parent.stat().st_dev
            and not (destination_parent/destination).exists()
            and not (destination_parent/destination).is_symlink(),
            "migration-native-rollback",
            "unprotected or conflicting original rollback directory")
    original=(source.stat().st_dev,source.stat().st_ino)
    srcfd=os.open(source.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    dstfd=os.open(destination_parent,
                  os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        _noreplace(srcfd,source.name,dstfd,destination)
        os.fsync(srcfd)
        os.fsync(dstfd)
    finally:
        os.close(dstfd)
        os.close(srcfd)
    archived=destination_parent/destination
    require(not source.exists() and archived.is_dir()
            and not archived.is_symlink()
            and (archived.stat().st_dev,archived.stat().st_ino)==original,
            "migration-native-rollback",
            "rollback evidence inode not preserved")
    return archived


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
                 selected_admission=None, selected_bundle=None,
                 journal_root=None, allow_disposable=False):
        require(os.geteuid()==0,"root-required","native adapter needs root")
        root=Path(filesystem_root).absolute()
        if root==Path("/"):
            require(NATIVE_ACTIVATION_ENABLED,"migration-native-hold",
                    "production native account/file mutation disabled")
            require(type(selected_admission) is dict
                    and selected_admission.get("plan") == plan,
                    "migration-native-consumer",
                    "root execution requires matching protected admission")
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
        self.selected_bundle=selected_bundle
        if root == Path("/"):
            from .state_contract import validate
            require(type(selected_bundle) is dict
                    and type(selected_admission) is dict
                    and digest(selected_bundle) == plan["bundle_sha256"]
                    and selected_admission.get("bundle_sha256") ==
                        digest(selected_bundle),
                    "migration-native-bundle",
                    "source-authenticated canonical bundle required")
            validate(selected_bundle)
        self.journal_root = (
            Path(journal_root) if journal_root is not None else None)
        if root == Path("/"):
            from .state_account_migration_launcher import TRANSACTION_DIRECTORY
            require(self.journal_root == Path(TRANSACTION_DIRECTORY) /
                    plan["migration_id"],
                    "migration-native-journal",
                    "root backend must select exact protected journal")
        self.original_config=initial_config
        self.target_config=changed_configuration(initial_config)
        if selected_admission is None:
            self.target_dropin=changed_unit_dropin()
        else:
            from .state_account_migration_launcher import (
                render_selected_launcher_dropin,
            )
            require(selected_admission.get("plan") == plan,
                    "migration-native-consumer",
                    "selected admission and plan differ")
            self.target_dropin=render_selected_launcher_dropin(
                selected_admission)
        require(__import__("hashlib").sha256(self.target_dropin).hexdigest() ==
                    plan.get("unit_dropin_sha256"),
                "migration-native-consumer",
                "systemd drop-in bytes differ from protected plan")

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

    def ensure_rollback_autostart_fence(self):
        """Persist reboot hold before undoing any account or identity stage.

        Called only after MigrationJournal has durably marked rolling-back,
        under both root transaction locks. If a reboot interrupts this
        command, the root FD launcher denies non-applying journals.
        """
        require(self.root==Path("/") and NATIVE_ACTIVATION_ENABLED,
                "migration-native-hold",
                "source-selected native rollback fence required")
        from .state_account_migration_live import _systemctl
        enabled=_systemctl("show","host-discover.service",
                           "--property=UnitFileState","--value")
        require(enabled in ("enabled","disabled"),
                "migration-native-service","unknown unit enablement")
        if enabled=="enabled":
            result=subprocess.run(
                ("/usr/bin/systemctl","disable","host-discover.service"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=45,check=False,
                env={"PATH":"/usr/bin:/bin","LANG":"C"})
            require(result.returncode==0,
                    "migration-native-service",
                    "cannot durably disable service during rollback")
        require(_systemctl("show","host-discover.service",
                           "--property=UnitFileState","--value")=="disabled",
                "migration-native-service",
                "reboot hold not persistent")

    def _effective_service_state(self):
        """Compare actual systemd manager argv/identity, not just unit bytes.

        The new service must execute the protected Python FD supervisor;
        selecting the previous legacy daemon after /state migration could
        generate a new Host key. A mismatched reload is always a hard HOLD.
        """
        import re
        import shlex
        from .state_account_migration_live import (
            _systemctl, _legacy_argv, OLD_EXE,
        )
        fields=("ExecStart","User","Group","SupplementaryGroups",
                "NeedDaemonReload","ReadWritePaths")
        values={key:_systemctl(
            "show","host-discover.service","--property="+key,"--value")
                for key in fields}
        starts=re.findall(r"argv\[\]=(.*?)(?=\s+;\s+|\s*})",
                          values["ExecStart"],flags=re.S)
        require(len(starts)==1,
                "migration-native-service","ambiguous actual ExecStart")
        try:
            argv=shlex.split(starts[0].strip(),posix=True)
        except ValueError as exc:
            raise StateError("migration-native-service",
                             "invalid effective argv syntax") from exc
        from .state_account_migration_admission import CANDIDATE_PYTHON
        expected=[CANDIDATE_PYTHON,"-m",
                  "zog.host_install.state_account_migration_launcher"]
        if (argv==expected
                and values["User"]==values["Group"]=="root"
                and values["SupplementaryGroups"]==""
                and set(values["ReadWritePaths"].split()) == {
                    "/state/host-discover/identity",
                    "/var/lib/host-discover/credentials"}):
            return "after"
        try:
            legacy=_legacy_argv(" ".join(argv))
        except (StateError,ValueError):
            legacy=None
        if (legacy is not None
                and values["User"]==values["Group"]=="host-discover"
                and values["SupplementaryGroups"]=="archive-consumers"):
            return "before"
        raise StateError("migration-native-service",
                         "effective service is neither original nor selected FD launcher")

    def _read_record(self, path, expected):
        """Refuse unexpected canonical migration file content and metadata."""
        file=self.path(path)
        if not file.exists():
            return False
        info=file.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
                and stat.S_IMODE(info.st_mode)==0o444
                and info.st_nlink==1 and file.read_bytes()==expected,
                "migration-native-record", "canonical record substituted")
        return True

    def _storage_state(self,stage):
        """Observe real canonical storage, independently of synthetic probes."""
        require(self.root==Path("/") and self.selected_bundle is not None,
                "migration-native-storage", "real selected bundle required")
        from .state_provision import layout_record
        b=self.selected_bundle
        if stage=="canonical-configuration-published":
            directory=self.path("/etc/zog/host-install")
            if not directory.exists():
                return "before"
            require(directory.is_dir() and not directory.is_symlink()
                    and (directory.stat().st_uid,directory.stat().st_gid,
                         stat.S_IMODE(directory.stat().st_mode))==(0,0,0o755)
                    and directory.stat().st_dev==self.path("/").stat().st_dev,
                    "migration-native-storage",
                    "foreign owner, mount or canonical directory")
            # A partial durable publication remains BEFORE and the guarded
            # publisher must resume only exact original record bytes.
            for name in ("accounts", "installation", "bootstrap"):
                p=directory/(name+".json")
                if p.exists():
                    self._read_record(
                        "/etc/zog/host-install/"+name+".json",
                        canonical(b[name]))
            expected={name+".json" for name in (
                "accounts", "installation", "bootstrap")}
            present=set(os.listdir(directory))
            require(present <= expected |
                    {".host-install.lock"} |
                    {".pending."+name for name in expected},
                    "migration-native-storage", "foreign configuration entry")
            return ("after" if expected <= present else "before")
        state=self.path("/state")
        if not state.exists():
            return "before"
        require(state.is_dir() and not state.is_symlink()
                and (state.stat().st_uid,state.stat().st_gid,
                     stat.S_IMODE(state.stat().st_mode)) == (0,0,0o755)
                and state.stat().st_dev==self.path("/").stat().st_dev,
                "migration-native-storage", "foreign directory-backed STATE")
        marker=state/".zog-state.json"
        if marker.exists():
            self._read_record("/state/.zog-state.json",
                              canonical(b["marker"]))
        prepared=state/".zog-prepared.json"
        if not prepared.exists():
            # A journaled, interrupted layout is still BEFORE. prepare_tree
            # will independently reject unrelated directories, marker data
            # and unsafe paths when retried.
            return "before"
        self._read_record("/state/.zog-prepared.json",
                          layout_record(b,"zog-state-prepared"))
        from .state_inspect import inspect_live
        with inspect_live() as context:
            require(context.bundle==b,
                    "migration-native-storage",
                    "STATE installation differs from approved bundle")
        return "after"

    def _active_journal_fd(self):
        """Open only root-owned committed transaction journal at fixed path."""
        require(self.root==Path("/") and self.journal_root is not None,
                "migration-native-journal",
                "only selected native transaction may publish storage")
        expected=self.path(
            "/var/lib/zog-host-install/migrations/"+self.plan["migration_id"])
        require(self.journal_root==expected
                and expected.is_dir() and not expected.is_symlink()
                and (expected.stat().st_uid,expected.stat().st_gid,
                     stat.S_IMODE(expected.stat().st_mode))==(0,0,0o700),
                "migration-native-journal", "wrong protected transaction path")
        from .state_account_migration_completion import _read_protected
        fd=os.open(expected/"transaction.json",
                   os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            _read_protected(fd,size=65536)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _apply_storage_stage(self,stage):
        require(self.root==Path("/") and NATIVE_ACTIVATION_ENABLED
                and stage in ("canonical-configuration-published",
                              "state-layout-prepared"),
                "migration-native-hold",
                "native storage publishers require protected activation")
        journal_fd=self._active_journal_fd()
        try:
            if stage=="canonical-configuration-published":
                from .state_account_migration_storage import (
                    publish_migration_configuration,
                )
                publish_migration_configuration(
                    self.selected_bundle,self.plan,journal_fd)
            else:
                from .state_account_migration_storage import (
                    prepare_migration_layout,
                )
                from .state_provision import (
                    ensure_directory_mountpoint,open_volume,
                )
                from .state_inspect import _mount,load_configuration,directory
                bundle=load_configuration()
                require(bundle==self.selected_bundle
                        and _mount(bundle).get("backend")=="root-directory",
                        "migration-native-storage",
                        "foreign root-backed STATE selection")
                root_fd=directory("/")
                try:
                    ensure_directory_mountpoint(root_fd)
                finally: os.close(root_fd)
                with open_volume() as context:
                    prepare_migration_layout(
                        context,self.plan["state_volume_id"],
                        self.plan,journal_fd)
        finally:
            os.close(journal_fd)

    def state(self,stage):
        require(stage in STAGES,"migration-stage","unreviewed stage")
        if stage in ("service-disabled","service-stopped") and self.root==Path("/"):
            # After crash near the very end of rollback, the old 0.3.3 unit
            # may already be active/enabled while the rolling-back journal
            # still carries historical forward-stage completion. Never
            # re-disable it just because that history has not been cleared.
            record=self.probe._record()
            if (record is not None
                    and record.get("status")=="rolling-back"
                    and self._effective_service_state()=="before"):
                from .state_account_migration_live import _systemctl
                if (_systemctl("show","host-discover.service",
                               "--property=ActiveState","--value")=="active"
                    and _systemctl("show","host-discover.service",
                                   "--property=UnitFileState","--value")=="enabled"):
                    return "before"
        if stage=="systemd-daemon-reloaded" and self.root==Path("/"):
            return self._effective_service_state()
        if stage=="service-restored" and self.root==Path("/"):
            # A resumed legacy 0.3.3 daemon on rollback is NOT the migrated
            # FD-backed service, regardless of the still-retained journal
            # completion history. Keep restart reconciliation unambiguous.
            if self._effective_service_state()=="before":
                return "before"
        if stage in ACCOUNT_COMMANDS or stage in (
                "service-disabled","service-stopped",
                "systemd-daemon-reloaded","service-restored"):
            return self.probe.stage_state(stage,self.plan)
        if stage in ("canonical-configuration-published",
                     "state-layout-prepared") and self.root==Path("/"):
            return self._storage_state(stage)
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
                    and dropin.read_bytes()==self.target_dropin
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
            # Pin the selected inode with an FD across the ownership syscall.
            # lstat(path) followed by chown(path) can otherwise mutate a
            # substituted entry after a concurrent pathname replacement.
            fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|
                       (os.O_DIRECTORY if stat.S_ISDIR(s.st_mode) else 0))
            try:
                held=os.fstat(fd)
                require([held.st_dev,held.st_ino]==[s.st_dev,s.st_ino]
                        and (held.st_uid,held.st_gid) in (before,after)
                        and stat.S_IFMT(held.st_mode)==stat.S_IFMT(s.st_mode)
                        and stat.S_IMODE(held.st_mode)==stat.S_IMODE(s.st_mode),
                        "migration-native-owner",
                        "selected inode changed before ownership update")
                if (held.st_uid,held.st_gid)!=target:
                    os.fchown(fd,*target)
                after_fd=os.fstat(fd)
                require((after_fd.st_uid,after_fd.st_gid)==target
                        and [after_fd.st_dev,after_fd.st_ino]==[s.st_dev,s.st_ino],
                        "migration-native-owner",
                        "opened inode ownership update failed")
                after_path=p.lstat()
                require((after_path.st_uid,after_path.st_gid)==target
                        and [after_path.st_dev,after_path.st_ino]==
                            [s.st_dev,s.st_ino],
                        "migration-native-owner",
                        "original name changed after ownership update")
            finally:
                os.close(fd)
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

    def _rollback_storage_stage(self, stage):
        """Quarantine precisely selected root-backed storage, never delete data.

        After identity is restored to its original path, preserve all new
        STATE data in the protected transaction as rollback evidence.
        Original canonical config is likewise moved aside, not overwritten
        or recursively removed. Unrecognized ownership/marker/entries deny.
        """
        require(self.root==Path("/") and NATIVE_ACTIVATION_ENABLED
                and stage in ("state-layout-prepared",
                              "canonical-configuration-published")
                and self.journal_root is not None,
                "migration-native-rollback-hold",
                "root-only selected rollback storage required")
        require(self._storage_state(stage)=="after",
                "migration-native-rollback",
                "selected storage not in complete after state")
        if stage=="state-layout-prepared":
            source=self.path("/state")
            require(not (source/"host-discover/identity").exists()
                    and source.is_dir() and not source.is_symlink(),
                    "migration-native-rollback",
                    "retained identity must be restored before STATE quarantine")
            destination="rolled-back-state"
            parent=self.path("/")
            original_name="state"
        else:
            source=self.path("/etc/zog/host-install")
            destination="rolled-back-configuration"
            parent=self.path("/etc/zog")
            original_name="host-install"
            expected={"accounts.json","installation.json",
                      "bootstrap.json",".host-install.lock"}
            require(set(os.listdir(source)) <= expected and
                    expected- {".host-install.lock"} <= set(os.listdir(source)),
                    "migration-native-rollback",
                    "unrecognized canonical configuration cannot be quarantined")
        quarantine_selected_directory(
            source,self.journal_root,destination)

    def prepare_service_start(self, row):
        """Publish original-key completion from the durably committed intent.

        This runs only while MigrationJournal owns the transaction lock. The
        receipt is already present when systemd starts the FD bridge, avoiding
        a circular dependency on a completed service-restored stage.
        """
        from .state_account_migration import service_start_intent
        from .state_account_migration_completion import (
            completion_from_observed_fds, publish_completion,
        )
        require(self.root == Path("/") and NATIVE_ACTIVATION_ENABLED
                and self.journal_root is not None
                and row == service_start_intent(self.plan),
                "migration-native-hold",
                "protected prestart journal intent required")
        path=self.journal_root
        require(path.is_dir() and not path.is_symlink()
                and os.stat(path).st_uid==0
                and stat.S_IMODE(os.stat(path).st_mode)==0o700,
                "migration-native-journal",
                "protected transaction directory not selected")
        identity=self.path(DESTINATION)
        require(identity.is_dir() and not identity.is_symlink()
                and [identity.stat().st_dev,identity.stat().st_ino] ==
                    self.original_identity_inodes["directory"],
                "migration-native-witness",
                "original identity not present under STATE")
        folder=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        opened=[]
        try:
            for name in ("original.json","transaction.json"):
                opened.append(os.open(name,os.O_RDONLY|os.O_NOFOLLOW|
                                      os.O_NONBLOCK,dir_fd=folder))
            opened.append(os.open(identity,
                                  os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
            receipt=completion_from_observed_fds(
                plan=self.plan,
                original_witness_fd=opened[0],
                journal_fd=opened[1],identity_fd=opened[2],
                prestart=True)
            result=publish_completion(folder,receipt)
            require(result["status"]=="completion-published",
                    "migration-native-witness",
                    "missing durable prestart completion")
        finally:
            for fd in reversed(opened):os.close(fd)
            os.close(folder)

    def apply(self,stage):
        self._act(stage,False)

    def undo(self,stage):
        self._act(stage,True)

    def _act(self,stage,rollback):
        require(self.state(stage)==("after" if rollback else "before"),
                "migration-native-stage","step state not selected")
        if stage in ACCOUNT_COMMANDS:
            self.runner.run(stage,rollback=rollback)
        elif stage in ("service-disabled","service-stopped",
                       "systemd-daemon-reloaded","service-restored"):
            if self.root==Path("/") and stage=="service-restored" and not rollback:
                require(self._effective_service_state()=="after",
                        "migration-native-service",
                        "service start requires effective retained FD launcher")
            if self.root==Path("/") and stage=="systemd-daemon-reloaded" and rollback:
                # Reverse the override and reload as one journaled intent;
                # service-start may not select a cached FD supervisor.
                override=self.path(self.DROPIN)
                if override.exists():
                    self._write_bytes(self.DROPIN,self.target_dropin,remove=True)
            self.probe.transition(stage,rollback=rollback)
        elif stage in FILE_OWNERS:
            self._chown_stage(stage,not rollback)
        elif stage in ("canonical-configuration-published",
                         "state-layout-prepared") and self.root==Path("/"):
            if rollback:
                self._rollback_storage_stage(stage)
            else:
                self._apply_storage_stage(stage)
        elif stage=="identity-moved":
            self._move(rollback)
        elif stage=="configuration-path-switched":
            self._switch_config(rollback)
        elif stage=="systemd-path-switched":
            dropin=self.path(self.DROPIN)
            if rollback:
                self._write_bytes(self.DROPIN,self.target_dropin,remove=True)
            else:
                require(dropin.parent.is_dir(),
                        "migration-native-file","unreviewed systemd dropin path")
                self._write_bytes(self.DROPIN,self.target_dropin)
        else:
            # Canonical /state and /etc publication must use their separate
            # reviewed privileged publishers, not arbitrary mkdir or writes.
            self.probe.transition(stage,rollback=rollback)
        require(self.state(stage)==("before" if rollback else "after"),
                "migration-native-stage","native stage postcondition failed")
