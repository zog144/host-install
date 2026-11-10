"""Root-capable disposable native filesystem + synthetic NSS/systemd actuation.

No live account database, root /state, host service or private Host key is
modified; only temporary files have real ownership and rename syscalls.
"""
import os
from pathlib import Path
import uuid

import pytest

from zog.host_install import state_account_migration as migration
from zog.host_install import state_account_migration_native as native
from zog.host_install.state_account_migration_consumer import CONSUMER_SELECTION
from zog.host_install.state_contract import StateError
from test_state_account_migration import fixture as source_fixture


class SyntheticNSS:
    def __init__(self):
        self.status={name:"before" for name in migration.STAGES
                     if name not in native.FILE_OWNERS and
                     name not in ("identity-moved","configuration-path-switched",
                                  "systemd-path-switched")}
        self.commands=[]
    def stage_state(self,stage,plan):return self.status[stage]
    def transition(self,stage,*,rollback=False):
        assert self.status[stage]==("after" if rollback else "before")
        self.status[stage]="before" if rollback else "after"
    def run(self,stage,*,rollback=False):
        command=native.exact_command(stage,rollback)
        assert command[0] in ("groupmod","usermod","useradd","userdel",
                              "groupadd","groupdel")
        assert not any(";" in x or "$" in x for x in command)
        self.commands.append((stage,rollback,command))
        self.transition(stage,rollback=rollback)


@pytest.fixture
def root_case(tmp_path):
    if os.geteuid()!=0:
        pytest.skip("root-required temporary filesystem chown/rename")
    selected=source_fixture()
    selected["consumer_contract"]=dict(CONSUMER_SELECTION)
    # The second name is synthetic; only a native protected inventory may
    # identify the real Host's second credential file.
    selected["file_inventory"]["credential_files"]["second-retained.json"]={
        "kind":"file","uid":991,"gid":990,"mode":0o640,"links":1}
    plan=migration.review_source_migration(**selected)
    root=tmp_path/"sandbox"
    identity=root/migration.SOURCE.lstrip("/")
    credentials=root/migration.CREDENTIALS.lstrip("/")
    dest=root/migration.DESTINATIONS.lstrip("/")
    cfg=root/migration.CONFIGURATION.lstrip("/")
    dropin=root/native.NativeStageBackend.DROPIN.lstrip("/")
    for p in (identity,credentials,dropin.parent,cfg.parent,
              root/"state/host-discover"):
        p.mkdir(parents=True,exist_ok=True)
    (identity/"identity.pem").write_bytes(b"synthetic-key-only")
    (identity/"binding.json").write_bytes(b'{"synthetic":"binding"}')
    (identity/"key.lock").write_bytes(b"")
    for p in identity.iterdir():
        p.chmod(0o600);os.chown(p,991,991)
    identity.chmod(0o700);os.chown(identity,991,991)
    (credentials/"archive.json").write_bytes(b"synthetic-not-a-credential")
    (credentials/"second-retained.json").write_bytes(b"synthetic-second-file")
    for p in credentials.iterdir():p.chmod(0o640)
    credentials.chmod(0o750)
    for p in [credentials,*credentials.iterdir()]:os.chown(p,991,990)
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(b"synthetic-destinations")
    dest.chmod(0o600);os.chown(dest,991,991)
    cfg.write_bytes(selected["configuration_bytes"])
    cfg.chmod(0o600)
    inodes={"directory":list(stat(identity)),
            **{p.name:list(stat(p)) for p in identity.iterdir()}}
    fake=SyntheticNSS()
    backend=native.NativeStageBackend(
        plan,filesystem_root=root,allow_disposable=True,
        probe=fake,command_runner=fake,
        original_identity_inodes=inodes,
        original_credential_inodes={
            p.name:list(stat(p)) for p in credentials.iterdir()},
        selected_file_inventory=selected["file_inventory"],
        initial_config=selected["configuration_bytes"])
    return backend,fake,root,identity,credentials,cfg,dropin,inodes


def stat(path):
    s=path.lstat();return (s.st_dev,s.st_ino)


def journal(tmp_path,backend):
    directory=tmp_path/"journal"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return migration.MigrationJournal(
        directory,backend.plan,backend,require_root=False)


def test_all_native_account_opcodes_are_explicit_and_reversible():
    assert native.exact_command(
        "host-discover-supplementary-groups-updated") == (
            "usermod", "-G", "archive-consumers,host-control", "host-discover")
    assert native.exact_command(
        "host-discover-supplementary-groups-updated", rollback=True) == (
            "usermod", "-G", "", "host-discover")
    assert set(native.ACCOUNT_COMMANDS)<set(migration.STAGES)
    for stage in native.ACCOUNT_COMMANDS:
        forward=native.exact_command(stage)
        reverse=native.exact_command(stage,rollback=True)
        assert forward and reverse and tuple(forward)!=tuple(reverse)
        assert all(isinstance(part,str) for part in forward+reverse)
    with pytest.raises(StateError):
        native.exact_command("rm -rf /")


def test_production_host_native_adapter_is_hard_disabled():
    if os.geteuid()!=0:
        pytest.skip("root-only production gate")
    with pytest.raises(StateError,match="migration-native-hold"):
        native.NativeStageBackend(
            {"schema":migration.SCHEMA},
            filesystem_root="/",probe=SyntheticNSS(),
            command_runner=SyntheticNSS(),initial_config=b"",
            original_identity_inodes={})
    assert native.NATIVE_ACTIVATION_ENABLED is False


def test_disposable_root_migrates_identity_inode_and_restores_it(root_case,tmp_path):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    engine=journal(tmp_path,backend)
    assert engine.execute()["status"]=="complete"
    moved=root/migration.DESTINATION.lstrip("/")
    assert moved.is_dir() and not identity.exists()
    assert list(stat(moved))==inodes["directory"]
    assert list(stat(moved/"identity.pem"))==inodes["identity.pem"]
    assert (moved/"identity.pem").read_bytes()==b"synthetic-key-only"
    assert (moved/"identity.pem").stat().st_uid==970
    assert (creds/"archive.json").stat().st_gid==972
    assert (creds/"second-retained.json").stat().st_gid==972
    assert cfg.read_bytes()==migration.changed_configuration(backend.original_config)
    assert dropin.read_bytes()==migration.changed_unit_dropin()
    assert engine.execute()["status"]=="complete"
    assert engine.execute(rollback=True)["status"]=="rolled-back"
    assert identity.is_dir() and not moved.exists()
    assert list(stat(identity))==inodes["directory"]
    assert list(stat(identity/"identity.pem"))==inodes["identity.pem"]
    assert (identity/"identity.pem").stat().st_uid==991
    assert (creds/"archive.json").stat().st_gid==990
    assert (creds/"second-retained.json").stat().st_gid==990
    assert cfg.read_bytes()==backend.original_config
    assert not dropin.exists()
    assert len(fake.commands)==2*len(native.ACCOUNT_COMMANDS)


@pytest.mark.parametrize("point",(
    "apply-before:legacy-identity-owner-updated",
    "apply-after:legacy-identity-owner-updated",
    "apply-before:identity-moved",
    "apply-after:identity-moved",
    "apply-after:configuration-path-switched",
    "rollback-after:identity-moved",
))
def test_native_step_retry_after_disposable_interrupt(root_case,tmp_path,point):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    engine=journal(tmp_path,backend)
    def interrupt(value):
        if value==point:raise RuntimeError("injected stage crash")
    if point.startswith("rollback"):
        assert engine.execute()["status"]=="complete"
        with pytest.raises(RuntimeError):
            engine.execute(rollback=True,checkpoint=interrupt)
        assert engine.execute(rollback=True)["status"]=="rolled-back"
        assert identity.is_dir()
    else:
        with pytest.raises(RuntimeError):
            engine.execute(checkpoint=interrupt)
        assert engine.execute()["status"]=="complete"
        assert not identity.exists()
    candidate=root/migration.DESTINATION.lstrip("/")
    selected=identity if identity.exists() else candidate
    assert list(stat(selected/"identity.pem"))==inodes["identity.pem"]


def test_chown_partial_stage_resumes_only_selected_original_inode(root_case,tmp_path,monkeypatch):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    engine=journal(tmp_path,backend)
    original=os.fchown
    calls=[0]
    def interrupt(fd,uid,gid):
        selected=os.readlink("/proc/self/fd/"+str(fd))
        if selected.startswith(str(identity)) and uid==970:
            calls[0]+=1
            if calls[0]==2:raise OSError("crash during opened inode ownership update")
        return original(fd,uid,gid)
    with monkeypatch.context() as ctx:
        ctx.setattr(native.os,"fchown",interrupt)
        with pytest.raises(OSError):
            engine.execute()
    assert backend.state("legacy-identity-owner-updated")=="before"
    assert engine.execute()["status"]=="complete"
    assert list(stat(root/migration.DESTINATION.lstrip("/")/"identity.pem"))==inodes["identity.pem"]


def test_unexpected_inode_and_symlink_hold_before_chown(root_case,tmp_path):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    src=identity/"identity.pem"
    src.unlink()
    src.symlink_to("/etc/passwd")
    with pytest.raises((StateError,OSError)):
        backend.state("legacy-identity-owner-updated")
    assert cfg.read_bytes()==backend.original_config


@pytest.mark.parametrize("attack",(
    "valid", "wrong-sidecar-inode", "unknown-extra",
    "symlink-origin", "wrong-role-mode",
))
def test_disposable_native_role_origin_files_preserved_through_rollback(
        root_case,tmp_path,attack):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    originals={
        "mirror-role.json":b'{"status":{"state":"stopped"}}',
        "mirror-role.lock":b"",
        "primary-origin.json":b'{"origin":"https://registry.example.invalid"}',
    }
    for name,content in originals.items():
        path=identity/name
        path.write_bytes(content)
        path.chmod(0o600)
        os.chown(path,991,991)
        backend.original_identity_inodes[name]=list(stat(path))
    if attack=="wrong-sidecar-inode":
        backend.original_identity_inodes["mirror-role.json"]=[1,9999]
    elif attack=="unknown-extra":
        (identity/"other-role.json").write_bytes(b"{}")
    elif attack=="symlink-origin":
        (identity/"primary-origin.json").unlink()
        (identity/"primary-origin.json").symlink_to("/etc/passwd")
    elif attack=="wrong-role-mode":
        (identity/"mirror-role.lock").chmod(0o644)
    if attack!="valid":
        with pytest.raises((StateError,OSError)):
            backend.state("legacy-identity-owner-updated")
        assert fake.status["service-stopped"]=="before"
        return
    engine=journal(tmp_path,backend)
    assert engine.execute()["status"]=="complete"
    moved=root/migration.DESTINATION.lstrip("/")
    for name,content in originals.items():
        path=moved/name
        assert path.read_bytes()==content
        assert list(stat(path))==backend.original_identity_inodes[name]
        assert (path.stat().st_uid,path.stat().st_gid)==(970,970)
    assert engine.execute(rollback=True)["status"]=="rolled-back"
    for name,content in originals.items():
        path=identity/name
        assert path.read_bytes()==content
        assert list(stat(path))==backend.original_identity_inodes[name]
        assert (path.stat().st_uid,path.stat().st_gid)==(991,991)


@pytest.mark.parametrize("attack",(
    "extra-file","missing-file","substituted-inode",
    "symlink","hardlink","wrong-mode","mismatched-source-plan",
))
def test_credential_ownership_requires_exact_closed_native_witness(
        root_case,attack,tmp_path):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    file=creds/"second-retained.json"
    if attack=="extra-file":
        (creds/"foreign").write_text("no")
    elif attack=="missing-file":file.unlink()
    elif attack=="substituted-inode":
        file.rename(creds/"kept-old-inode")
        file.write_bytes(b"unselected")
        file.chmod(0o640);os.chown(file,991,990)
        (creds/"kept-old-inode").unlink()
    elif attack=="symlink":
        file.unlink()
        file.symlink_to("/etc/passwd")
    elif attack=="hardlink":
        os.link(file,tmp_path/"foreign-link")
    elif attack=="wrong-mode":
        file.chmod(0o600)
    elif attack=="mismatched-source-plan":
        backend.credential_files=frozenset({"archive.json"})
    with pytest.raises((StateError,OSError)):
        backend.state("legacy-credentials-owner-and-group-updated")
    assert (creds/"archive.json").stat().st_gid==990


def test_original_credential_inventory_digest_denies_unreviewed_files(
        root_case):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    assert backend.credential_files=={
        "archive.json","second-retained.json"}
    assert set(backend.original_credential_inodes)==backend.credential_files
    assert backend.plan["file_inventory_metadata_sha256"]==__import__(
        "zog.host_install.state_contract",fromlist=["digest"]).digest(
            {**__import__("test_state_account_migration",fromlist=["fixture"])
             .fixture()["file_inventory"],
             "credential_files":{
                "archive.json":{"kind":"file","uid":991,"gid":990,
                                "mode":0o640,"links":1},
                "second-retained.json":{"kind":"file","uid":991,"gid":990,
                                        "mode":0o640,"links":1},
             }})


def test_native_fd_owner_update_rejects_inflight_path_replacement(
        root_case,tmp_path,monkeypatch):
    backend,fake,root,identity,creds,cfg,dropin,inodes=root_case
    old_key=identity/"identity.pem"
    retained=identity/"identity-original-held.pem"
    original_chown=os.fchown
    injected=[False]
    def replace_after_fd_open(fd,uid,gid):
        path=os.readlink("/proc/self/fd/"+str(fd))
        if path==str(old_key) and uid==970 and not injected[0]:
            injected[0]=True
            old_key.rename(retained)
            old_key.write_bytes(b"replaced-after-original-fd-open")
            old_key.chmod(0o600)
            os.chown(old_key,991,991)
        return original_chown(fd,uid,gid)
    with monkeypatch.context() as patch:
        patch.setattr(native.os,"fchown",replace_after_fd_open)
        engine=journal(tmp_path,backend)
        with pytest.raises(StateError,match="migration-native-owner"):
            engine.execute()
    assert injected==[True]
    assert old_key.read_bytes()==b"replaced-after-original-fd-open"
    assert old_key.stat().st_uid==991
    assert list(stat(retained))==inodes["identity.pem"]
    # No success or silent restart is allowed after a concurrent pathname
    # replacement. The original FD can change its own inode, not the
    # substituted path; the stage fails and requires protected recovery.
    assert fake.status["service-restored"]=="before"


def test_root_disposable_rollback_quarantines_state_without_deleting_data(
        tmp_path):
    if os.geteuid()!=0:
        pytest.skip("root-only no-replace quarantine requires disposable root")
    root=tmp_path/"sandbox"
    root.mkdir(mode=0o755)
    state=root/"state"
    state.mkdir(mode=0o755)
    identity_free=state/"host-discover"
    identity_free.mkdir(mode=0o700)
    (identity_free/"health.json").write_text("synthetic-retained-data")
    ledger=root/"journal"
    ledger.mkdir(mode=0o700)
    inode=stat(state)
    archived=native.quarantine_selected_directory(
        state,ledger,"rolled-back-state")
    assert not state.exists()
    assert stat(archived)==inode
    assert (archived/"host-discover/health.json").read_text() == (
        "synthetic-retained-data")
    other=root/"state"
    other.mkdir(mode=0o755)
    with pytest.raises(StateError):
        native.quarantine_selected_directory(
            other,ledger,"rolled-back-state")
    assert other.exists()
    assert (archived/"host-discover/health.json").is_file()


@pytest.mark.parametrize("attack", ("symlink","writable-source",
                                     "writable-ledger","wrong-name"))
def test_rollback_quarantine_denies_unsafe_disposable_paths(tmp_path,attack):
    if os.geteuid()!=0:
        pytest.skip("root-only disposable filesystem test")
    root=tmp_path/"sandbox"
    root.mkdir(mode=0o755)
    state=root/"state"
    state.mkdir(mode=0o755)
    ledger=root/"journal"
    ledger.mkdir(mode=0o700)
    if attack=="symlink":
        actual=root/"actual"
        state.rename(actual)
        state.symlink_to(actual,target_is_directory=True)
    elif attack=="writable-source":
        state.chmod(0o777)
    elif attack=="writable-ledger":
        ledger.chmod(0o777)
    elif attack=="wrong-name":
        state.rename(root/"wrong")
        state=root/"wrong"
    with pytest.raises(StateError):
        native.quarantine_selected_directory(
            state,ledger,"rolled-back-state")
    assert not (ledger/"rolled-back-state").exists()


def test_actual_systemd_effective_identity_fences_retained_fd_launcher(
        root_case, monkeypatch):
    backend,*_=root_case
    from zog.host_install import state_account_migration_live as live
    from zog.host_install.state_account_migration_admission import CANDIDATE_PYTHON
    historical={
        "ExecStart":("{ path="+live.OLD_EXE+" ; argv[]="+
                     " ".join(live.LEGACY_ARGV)+" ; ignore_errors=no ; }"),
        "User":"host-discover","Group":"host-discover",
        "SupplementaryGroups":"archive-consumers",
        "NeedDaemonReload":"no",
        "ReadWritePaths":"/var/lib/host-discover/identity /var/lib/host-discover/credentials",
    }
    selected={
        "ExecStart":("{ path="+CANDIDATE_PYTHON+" ; argv[]="+
                     CANDIDATE_PYTHON+
                     " -m zog.host_install.state_account_migration_launcher"+
                     " ; ignore_errors=no ; }"),
        "User":"root","Group":"root","SupplementaryGroups":"",
        "NeedDaemonReload":"no",
        "ReadWritePaths":"/state/host-discover/identity /var/lib/host-discover/credentials",
    }
    shown=dict(historical)
    def systemctl(*args):
        assert args[:2]==("show","host-discover.service")
        return shown[args[2].removeprefix("--property=").split("=")[0]]
    monkeypatch.setattr(live,"_systemctl",systemctl)
    assert backend._effective_service_state()=="before"
    shown.update(selected)
    assert backend._effective_service_state()=="after"
    shown["ExecStart"]=historical["ExecStart"]
    with pytest.raises(StateError):
        backend._effective_service_state()
    shown.update(selected)
    shown["SupplementaryGroups"]="archive-consumers"
    with pytest.raises(StateError):
        backend._effective_service_state()
    shown.update(selected)
    shown["ExecStart"]=shown["ExecStart"].replace(
        "zog.host_install.state_account_migration_launcher",
        "zog.host_discover.daemon")
    with pytest.raises(StateError):
        backend._effective_service_state()
