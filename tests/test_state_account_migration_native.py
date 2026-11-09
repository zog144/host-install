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
    (credentials/"archive.json").chmod(0o640)
    credentials.chmod(0o750)
    for p in (credentials,credentials/"archive.json"):os.chown(p,991,990)
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
    assert cfg.read_bytes()==migration.changed_configuration(backend.original_config)
    assert dropin.read_bytes()==migration.changed_unit_dropin()
    assert engine.execute()["status"]=="complete"
    assert engine.execute(rollback=True)["status"]=="rolled-back"
    assert identity.is_dir() and not moved.exists()
    assert list(stat(identity))==inodes["directory"]
    assert list(stat(identity/"identity.pem"))==inodes["identity.pem"]
    assert (identity/"identity.pem").stat().st_uid==991
    assert (creds/"archive.json").stat().st_gid==990
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
    original=os.chown
    calls=[0]
    def interrupt(path,uid,gid,*,follow_symlinks=True):
        if str(path).startswith(str(identity)) and uid==970:
            calls[0]+=1
            if calls[0]==2:raise OSError("crash during file ownership update")
        return original(path,uid,gid,follow_symlinks=follow_symlinks)
    with monkeypatch.context() as ctx:
        ctx.setattr(native.os,"chown",interrupt)
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
