"""Source-only legacy host-registry migration, crash and rollback regressions.

All account/service updates use a disposable injected backend. The real
host-discover service and Host UUID/private identity are never touched.
"""
import copy
import json
import os
import uuid
from pathlib import Path

import pytest

from zog.host_install import state_account_migration as m
from zog.host_install.state_contract import StateError, digest, validate
from test_state_directory_runtime import directory_bundle, ROOT_PARTUUID, ROOT_UUID


HOST_UUID="d934cd5e-54d3-4980-8305-3dd77b023e0d"
FINGERPRINT="fc9eb1c215a3e5f8a610263ef30072022f76c1e30225aa1a5435aec7389a8ed3"
MIGRATION_ID="6bbd56c4-79af-436f-aa05-cdc1e79f90cd"


def fixture():
    b=directory_bundle()
    b["bootstrap"]["mode"]="migration"
    b["installation"]["operation"]="migration"
    b["bootstrap"]["registries"][0]["origin"]=(
        "https://host-registry.hosts.zog-network-demo.uk")
    b["bootstrap"]["initialization"]["expected_host_uuid"]=HOST_UUID
    b["bootstrap"]["initialization"]["expected_fingerprint"]=FINGERPRINT
    b["bootstrap"]["installation_record"]["sha256"]=digest(b["installation"])
    validate(b)
    rows=[{"target":"/","root":"/","type":"xfs","device":"259:1",
           "options":["rw"],"super_options":["rw"]}]
    devices=[{"maj:min":"259:1","type":"part",
              "partuuid":ROOT_PARTUUID,"uuid":ROOT_UUID,"fstype":"xfs"}]
    file_=lambda ino:{"kind":"file","uid":991,"gid":991,"mode":0o600,
                       "links":1,"dev":259,"inode":ino}
    config=json.dumps({
        "server":"https://host-registry.hosts.zog-network-demo.uk",
        "provider":"aws","host_id":HOST_UUID,
        "identity_directory":m.SOURCE,
        "credential_directory":m.CREDENTIALS,
        "archive_issuer":"preserve-this-value",
        "archive_audience":"preserve-this-audience",
    },indent=2).encode()
    unit=(
        b"[Unit]\nDescription=Existing host-discover\n[Service]\n"
        b"User=host-discover\nGroup=host-discover\n"
        b"SupplementaryGroups=archive-consumers\n"
        b"ReadWritePaths=/var/lib/host-discover/identity /var/lib/host-discover/credentials\n"
        b"[Install]\nWantedBy=multi-user.target\n")
    return {
        "bundle":b,"migration_id":MIGRATION_ID,
        "root_observation":{"mounts":rows,"devices":devices,
                            "root_device":"259:1","state_exists":False},
        "account_snapshot":{
            "users":{"host-discover":{
                "uid":991,"gid":991,"home":"/home/host-discover",
                "shell":"/sbin/nologin","groups":["archive-consumers"]}},
            "groups":{"host-discover":991,"archive-consumers":990},
            "uid_index":{"991":"host-discover","1000":"ec2-user"},
            "gid_index":{"991":"host-discover","990":"archive-consumers",
                         "1000":"ec2-user"},
        },
        "file_inventory":{
            "identity.pem":file_(121),
            "binding.json":file_(122),
            "key.lock":file_(123),
            "registry-ca.pem":None,
            "credential_files":{
                "archive.json":{"kind":"file","uid":991,"gid":990,
                                "mode":0o640,"links":1}},
            "destinations":{"kind":"file","uid":991,"gid":991,
                            "mode":0o600,"links":1},
        },
        "configuration_bytes":config,
        "binding":{"host_id":HOST_UUID,"fingerprint":FINGERPRINT},
        "public_identity_witness":FINGERPRINT,
        "unit_bytes":unit,
        "service_snapshot":{"active":True,"enabled":True},
        "consumer_contract":None,
    }


def review(row):
    return m.review_source_migration(**row)


def test_source_migration_explicit_identity_account_and_registry():
    row=fixture()
    got=review(row)
    assert got["status"]=="SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
    assert got["migration_id"]==MIGRATION_ID
    assert got["host_uuid"]==HOST_UUID
    assert got["public_fingerprint"]==FINGERPRINT
    assert got["root_fs_type"]=="xfs"
    assert got["service_was_active"] and got["service_was_enabled"]
    target=m.changed_configuration(row["configuration_bytes"])
    raw=json.loads(row["configuration_bytes"])
    cooked=json.loads(target)
    assert {k:v for k,v in raw.items() if k!="identity_directory"}=={
        k:v for k,v in cooked.items() if k!="identity_directory"}
    assert cooked["identity_directory"]==m.DESTINATION
    assert cooked["credential_directory"]==m.CREDENTIALS
    assert got["configuration_before_sha256"]!=got["configuration_after_sha256"]
    assert b"ReadWritePaths=\n" in m.changed_unit_dropin()
    assert m.CREDENTIALS.encode() in m.changed_unit_dropin()


@pytest.mark.parametrize("attack",(
    "wrong_host_uuid","wrong_fingerprint","private_key_claim",
    "wrong_binding","unexpected_file","identity_symlink",
    "identity_hardlink","identity_uid","credential_group",
    "destinations_world_readable","wrong_legacy_uid","wrong_archive_gid",
    "target_uid_used","target_gid_used","old_box_present","absent_root",
    "state_exists","nested_state_mount","wrong_root_uuid","root_readonly",
    "foreign_service","wrong_group","changed_endpoint","wrong_config_path",
    "unexpected_consumer_contract","wrong_install_mode",
    "unrelated_canonical_registry","unapproved_ca_replacement",
    "cross_filesystem_identity",
))
def test_preflight_rejects_foreign_identity_or_unreviewed_migration(attack):
    row=fixture()
    if attack=="wrong_host_uuid":
        row["bundle"]["bootstrap"]["initialization"]["expected_host_uuid"]=str(uuid.uuid4())
    elif attack=="wrong_fingerprint":
        row["public_identity_witness"]="e"*64
    elif attack=="private_key_claim":
        row["file_inventory"]["private_key_bytes"]="secrets"
    elif attack=="wrong_binding":
        row["binding"]["host_id"]=str(uuid.uuid4())
    elif attack=="unexpected_file":
        row["file_inventory"]["new-marker.json"]={"kind":"file"}
    elif attack=="identity_symlink":
        row["file_inventory"]["identity.pem"]["kind"]="symlink"
    elif attack=="identity_hardlink":
        row["file_inventory"]["identity.pem"]["links"]=2
    elif attack=="identity_uid":
        row["file_inventory"]["identity.pem"]["uid"]=970
    elif attack=="credential_group":
        row["file_inventory"]["credential_files"]["archive.json"]["gid"]=973
    elif attack=="destinations_world_readable":
        row["file_inventory"]["destinations"]["mode"]=0o644
    elif attack=="wrong_legacy_uid":
        row["account_snapshot"]["users"]["host-discover"]["uid"]=970
    elif attack=="wrong_archive_gid":
        row["account_snapshot"]["groups"]["archive-consumers"]=972
    elif attack=="target_uid_used":
        row["account_snapshot"]["uid_index"]["970"]="another-service"
    elif attack=="target_gid_used":
        row["account_snapshot"]["gid_index"]["973"]="another-service"
    elif attack=="old_box_present":
        row["account_snapshot"]["users"]["box-control"]={"uid":971}
    elif attack=="absent_root":
        row["root_observation"]["mounts"]=[]
    elif attack=="state_exists":
        row["root_observation"]["state_exists"]=True
    elif attack=="nested_state_mount":
        row["root_observation"]["mounts"].append(
            {**row["root_observation"]["mounts"][0],"target":"/state/overlay"})
    elif attack=="wrong_root_uuid":
        row["root_observation"]["devices"][0]["uuid"]=str(uuid.uuid4())
    elif attack=="root_readonly":
        row["root_observation"]["mounts"][0]["options"]=["ro"]
    elif attack=="foreign_service":
        row["unit_bytes"]=row["unit_bytes"].replace(b"User=host-discover",b"User=root")
    elif attack=="wrong_group":
        row["unit_bytes"]=row["unit_bytes"].replace(
            b"SupplementaryGroups=archive-consumers",b"SupplementaryGroups=other")
    elif attack=="changed_endpoint":
        row["configuration_bytes"]=row["configuration_bytes"].replace(
            b"https://host-registry.hosts.zog-network-demo.uk",b"http://unknown")
    elif attack=="wrong_config_path":
        row["configuration_bytes"]=row["configuration_bytes"].replace(
            b"/var/lib/host-discover/identity",b"/tmp/identity")
    elif attack=="unexpected_consumer_contract":
        row["consumer_contract"]={"approved":True}
    elif attack=="wrong_install_mode":
        row["bundle"]["bootstrap"]["mode"]="fresh"
    elif attack=="unrelated_canonical_registry":
        row["bundle"]["bootstrap"]["registries"][0]["origin"]="https://other.example.invalid"
    elif attack=="unapproved_ca_replacement":
        row["configuration_bytes"]=row["configuration_bytes"].replace(
            b'"archive_issuer"',b'"ca_file":"/etc/my-old-ca.pem", "archive_issuer"')
    elif attack=="cross_filesystem_identity":
        row["file_inventory"]["key.lock"]["dev"]=1
    with pytest.raises(StateError):
        review(row)


@pytest.mark.parametrize("modification",(
    "duplicate_key","credential_path","host_id","registry_origin","ambiguous_assignment",
))
def test_configuration_rewrite_is_one_path_only(modification):
    row=fixture()
    raw=row["configuration_bytes"]
    if modification=="duplicate_key":
        raw=raw.replace(b'"identity_directory":',
                        b'"identity_directory": "/else",\n"identity_directory":')
    elif modification=="credential_path":
        raw=raw.replace(m.CREDENTIALS.encode(),b"/state/credentials")
    elif modification=="host_id":
        raw=raw.replace(HOST_UUID.encode(),str(uuid.uuid4()).encode())
    elif modification=="registry_origin":
        raw=raw.replace(b"https://",b"http://",1)
    elif modification=="ambiguous_assignment":
        raw=raw.replace(b'"identity_directory"',b'"identity_directory" ')
    row["configuration_bytes"]=raw
    if modification=="ambiguous_assignment":
        # Whitespace is permitted; all other bytes must remain unchanged.
        assert review(row)["status"]=="SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
    else:
        with pytest.raises(StateError):
            review(row)


class DisposableBackend:
    def __init__(self):
        self.states={stage:"before" for stage in m.STAGES}
        self.actions=[]
        self.key_inode=123456
        self.public_fingerprint=FINGERPRINT
        self.registry_endpoint="https://host-registry.hosts.zog-network-demo.uk"
        self.credential_path=m.CREDENTIALS
    def state(self,stage):return self.states[stage]
    def apply(self,stage):
        assert self.states[stage]=="before"
        self.states[stage]="after"
        self.actions.append(("apply",stage))
    def undo(self,stage):
        assert self.states[stage]=="after"
        self.states[stage]="before"
        self.actions.append(("undo",stage))


@pytest.fixture
def plan():
    return review(fixture())


def journal(tmp_path,plan,backend):
    path=tmp_path/"private-journal"
    path.mkdir(mode=0o700,exist_ok=True)
    path.chmod(0o700)
    return m.MigrationJournal(path,plan,backend,require_root=False)


@pytest.mark.parametrize("crash_at",[
    "apply-before:"+s for s in m.STAGES
]+[
    "apply-after:"+s for s in m.STAGES
])
def test_same_operation_retry_resumes_after_each_stage_boundary(
        tmp_path,plan,crash_at):
    backend=DisposableBackend()
    engine=journal(tmp_path,plan,backend)
    def crash(where):
        if where==crash_at:raise RuntimeError("injected interruption")
    with pytest.raises(RuntimeError):
        engine.execute(checkpoint=crash)
    original_actions=list(backend.actions)
    assert engine.execute()["status"]=="complete"
    assert all(backend.state(s)=="after" for s in m.STAGES)
    assert engine.execute()["status"]=="complete"
    assert len(backend.actions)==len(m.STAGES)
    assert backend.actions[:len(original_actions)]==original_actions
    assert backend.key_inode==123456
    assert backend.public_fingerprint==FINGERPRINT
    assert backend.credential_path==m.CREDENTIALS


@pytest.mark.parametrize("crash_at",[
    "rollback-before:"+s for s in m.STAGES
]+[
    "rollback-after:"+s for s in m.STAGES
])
def test_rollback_retry_restores_all_account_and_path_stages(
        tmp_path,plan,crash_at):
    backend=DisposableBackend()
    engine=journal(tmp_path,plan,backend)
    assert engine.execute()["status"]=="complete"
    def crash(where):
        if where==crash_at:raise RuntimeError("injected rollback interruption")
    with pytest.raises(RuntimeError):
        engine.execute(rollback=True,checkpoint=crash)
    assert engine.execute(rollback=True)["status"]=="rolled-back"
    assert all(backend.state(s)=="before" for s in m.STAGES)
    with pytest.raises(StateError):
        engine.execute()
    assert backend.public_fingerprint==FINGERPRINT


def test_foreign_journal_and_ambiguous_completed_states_hold(tmp_path,plan):
    backend=DisposableBackend()
    engine=journal(tmp_path,plan,backend)
    assert engine.execute()["status"]=="complete"
    backend.states[m.STAGES[-1]]="before"
    with pytest.raises(StateError):
        engine.execute()
    backend.states[m.STAGES[-1]]="after"
    other=dict(plan,migration_id=str(uuid.uuid4()))
    with pytest.raises(StateError):
        journal(tmp_path,other,backend).execute()
    assert backend.public_fingerprint==FINGERPRINT


def test_pending_journal_recovery_and_conflicting_bytes_hold(tmp_path,plan):
    backend=DisposableBackend()
    engine=journal(tmp_path,plan,backend)
    def crash(where):
        if where=="apply-before:"+m.STAGES[2]:
            raise RuntimeError("simulated crash")
    with pytest.raises(RuntimeError):
        engine.execute(checkpoint=crash)
    root=tmp_path/"private-journal"
    pending=root/".transaction.pending"
    contents=(root/"transaction.json").read_bytes()
    pending.write_bytes(contents)
    os.chmod(pending,0o600)
    assert engine.execute()["status"]=="complete"
    assert not pending.exists()
    pending.write_bytes(b'{"foreign":"journal"}')
    os.chmod(pending,0o600)
    with pytest.raises(StateError):
        engine.execute()


def test_journal_rejects_wrong_directory_permissions(tmp_path,plan):
    root=tmp_path/"unsafe"
    root.mkdir(mode=0o777)
    root.chmod(0o777)
    with pytest.raises(StateError):
        m.MigrationJournal(root,plan,DisposableBackend(),require_root=False).execute()

class DisposableFilesystemBackend(DisposableBackend):
    """Real rename/content/ownership simulation on a temporary root.

    No production account database, native /state or service is accessed.
    """
    def __init__(self,root):
        super().__init__()
        self.root=root
        self.old=root/"var/lib/host-discover/identity"
        self.new=root/"state/host-discover/identity"
        self.config=root/"etc/host-discover/configuration.json"
        self.dropin=root/"etc/systemd/system/host-discover.service.d/zog-state-migration.conf"
        self.old.mkdir(parents=True)
        self.config.parent.mkdir(parents=True)
        for name,payload in (("identity.pem",b"synthetic-existing-key-never-regenerate"),
                             ("binding.json",b'{"public":"synthetic"}'),
                             ("key.lock",b"")):
            (self.old/name).write_bytes(payload)
        self.original_inode=self.old.stat().st_ino
        self.old_key_inode=(self.old/"identity.pem").stat().st_ino
        self.key_content=b"synthetic-existing-key-never-regenerate"
        self.before=fixture()["configuration_bytes"]
        self.after=m.changed_configuration(self.before)
        self.config.write_bytes(self.before)
        self.snapshot={"identity_owner":(991,991),
                       "credentials_owner":(991,990),
                       "destinations_owner":(991,991)}
    def state(self,stage):
        if stage=="identity-moved":
            old=self.old.exists()
            new=self.new.exists()
            return "before" if old and not new else "after" if new and not old else "conflict"
        if stage=="configuration-path-switched":
            value=self.config.read_bytes()
            return "before" if value==self.before else "after" if value==self.after else "conflict"
        if stage=="systemd-path-switched":
            return "after" if self.dropin.is_file() and self.dropin.read_bytes()==m.changed_unit_dropin() else (
                "before" if not self.dropin.exists() else "conflict")
        return super().state(stage)
    def apply(self,stage):
        if stage=="identity-moved":
            assert self.new.parent.is_dir()
            os.rename(self.old,self.new)
            self.actions.append(("apply",stage))
        elif stage=="configuration-path-switched":
            self.config.write_bytes(self.after)
            self.actions.append(("apply",stage))
        elif stage=="systemd-path-switched":
            self.dropin.parent.mkdir(parents=True,exist_ok=True)
            self.dropin.write_bytes(m.changed_unit_dropin())
            self.actions.append(("apply",stage))
        else:
            super().apply(stage)
            if stage=="state-layout-prepared":
                self.new.parent.mkdir(parents=True,exist_ok=True)
            if stage=="legacy-credentials-owner-and-group-updated":
                self.snapshot={
                    "identity_owner":(970,970),
                    "credentials_owner":(970,972),
                    "destinations_owner":(970,970),
                }
    def undo(self,stage):
        if stage=="identity-moved":
            os.rename(self.new,self.old)
            self.actions.append(("undo",stage))
        elif stage=="configuration-path-switched":
            self.config.write_bytes(self.before)
            self.actions.append(("undo",stage))
        elif stage=="systemd-path-switched":
            self.dropin.unlink()
            self.actions.append(("undo",stage))
        else:
            super().undo(stage)
            if stage=="legacy-credentials-owner-and-group-updated":
                self.snapshot={
                    "identity_owner":(991,991),
                    "credentials_owner":(991,990),
                    "destinations_owner":(991,991),
                }
            if stage=="state-layout-prepared":
                self.new.parent.rmdir()


@pytest.mark.parametrize("crash_at",[
    "apply-after:identity-moved",
    "apply-after:configuration-path-switched",
    "apply-after:systemd-path-switched",
    "rollback-after:identity-moved",
    "rollback-after:configuration-path-switched",
    "rollback-after:systemd-path-switched",
])
def test_disposable_same_filesystem_inode_preserved_and_rollback(
        tmp_path,plan,crash_at):
    backend=DisposableFilesystemBackend(tmp_path/"sandbox")
    engine=journal(tmp_path,plan,backend)
    def crash(location):
        if location==crash_at:raise RuntimeError("simulated filesystem interruption")
    if crash_at.startswith("rollback"):
        assert engine.execute()["status"]=="complete"
        with pytest.raises(RuntimeError):
            engine.execute(rollback=True,checkpoint=crash)
        assert engine.execute(rollback=True)["status"]=="rolled-back"
        assert backend.old.stat().st_ino==backend.original_inode
        assert (backend.old/"identity.pem").stat().st_ino==backend.old_key_inode
        assert (backend.old/"identity.pem").read_bytes()==backend.key_content
        assert backend.config.read_bytes()==backend.before
        assert not backend.dropin.exists()
        assert backend.snapshot["credentials_owner"]==(991,990)
    else:
        with pytest.raises(RuntimeError):
            engine.execute(checkpoint=crash)
        assert engine.execute()["status"]=="complete"
        assert backend.new.stat().st_ino==backend.original_inode
        assert (backend.new/"identity.pem").stat().st_ino==backend.old_key_inode
        assert (backend.new/"identity.pem").read_bytes()==backend.key_content
        assert backend.config.read_bytes()==backend.after
        assert backend.dropin.read_bytes()==m.changed_unit_dropin()
        assert backend.snapshot["credentials_owner"]==(970,972)
    assert backend.public_fingerprint==FINGERPRINT
    assert backend.credential_path==m.CREDENTIALS


def test_unexpected_partial_filesystem_placement_blocks_resume(tmp_path,plan):
    backend=DisposableFilesystemBackend(tmp_path/"sandbox")
    engine=journal(tmp_path,plan,backend)
    def crash(location):
        if location=="apply-before:state-layout-prepared":
            raise RuntimeError("crash")
    with pytest.raises(RuntimeError):
        engine.execute(checkpoint=crash)
    backend.new.parent.mkdir(parents=True)
    backend.new.mkdir()
    with pytest.raises(StateError,match="migration-recovery"):
        engine.execute()
    assert backend.old.exists() and backend.new.exists()

def test_no_production_root_executor_before_consumer_adoption(tmp_path,plan):
    backend=DisposableBackend()
    root=tmp_path/"production-hold"
    root.mkdir(mode=0o700)
    with pytest.raises(StateError,match="migration-consumer-hold"):
        m.MigrationJournal(root,plan,backend)
    assert all(backend.state(stage)=="before" for stage in m.STAGES)

def test_large_realistic_inode_numbers_are_not_rejected_as_uid_values():
    row=fixture()
    for key in ("key.lock","identity.pem","binding.json"):
        row["file_inventory"][key]["inode"]+=2**42
        row["file_inventory"][key]["dev"]+=2**26
    assert review(row)["status"]=="SOURCE_REVIEW_NATIVE_CONSUMER_HOLD"
