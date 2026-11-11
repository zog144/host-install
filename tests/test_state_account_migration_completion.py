"""Root-capable disposable completion and real retained-consumer FD integration.

Never touches the selected registry Host. Only temporary synthetic Ed25519
identity, root-owned transaction evidence and no-network descriptors are used.
"""
import hashlib
import json
import os
from pathlib import Path
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_install import state_account_migration_completion as c
from zog.host_install import state_account_migration as m
from zog.host_install.state_account_migration_consumer import (
    CONSUMER_SELECTION, verify_consumer_selection,
)
from zog.host_install.state_contract import StateError, canonical, digest
from test_state_account_migration import fixture as migration_fixture


def ino(p):
    s=p.stat()
    return [s.st_dev,s.st_ino]


@pytest.fixture
def retained(tmp_path,monkeypatch):
    if os.geteuid()!=0:
        pytest.skip("root-owned completion and synthetic retained-key FD test")
    row=migration_fixture()
    row["consumer_contract"]=dict(CONSUMER_SELECTION)
    plan=m.review_source_migration(**row)
    path=tmp_path/"legacy-identity"
    path.mkdir(mode=0o700)
    key=Ed25519PrivateKey.generate()
    pem=key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    (path/"identity.pem").write_bytes(pem)
    (path/"binding.json").write_text(json.dumps({
        "host_id":plan["host_uuid"],"fingerprint":plan["public_fingerprint"]}))
    (path/"key.lock").write_bytes(b"")
    for p in path.iterdir():p.chmod(0o600)
    original={name:ino(path/name) for name in ("identity.pem","binding.json","key.lock")}
    original_dir=ino(path)
    moved=tmp_path/"state/host-discover/identity"
    moved.parent.mkdir(parents=True,exist_ok=True)
    path.rename(moved)
    moved.chmod(0o700)
    # This is a fabricated test fingerprint, not an actual Host's identity.
    from zog.host_identify.signatures import fingerprint
    real_fingerprint=fingerprint(key.public_key())
    plan["public_fingerprint"]=real_fingerprint
    witness={
        "schema":c.WITNESS_SCHEMA,
        "migration_id":plan["migration_id"],
        "plan_sha256":digest(plan),
        "host_uuid":plan["host_uuid"],
        "fingerprint":real_fingerprint,
        "registry_origin":plan["registry_origin"],
        "identity_inode":original_dir,
        "key_inode":original["identity.pem"],
        "binding_inode":original["binding.json"],
        "lock_inode":original["key.lock"],
        "ca_inode":None,"ca_sha256":None,"retained_files":{},
    }
    (moved/"binding.json").write_text(json.dumps({
        "host_id":plan["host_uuid"],"fingerprint":real_fingerprint}))
    # Rewriting binding preserves the original file inode.
    journal={"schema":m.JOURNAL_SCHEMA,"migration_id":plan["migration_id"],
             "plan_sha256":digest(plan),"status":"complete",
             "completed":list(m.STAGES),"active":None}
    evidence=tmp_path/"evidence"
    evidence.mkdir(mode=0o700)
    for name,body in (("original.json",witness),("transaction.json",journal)):
        p=evidence/name;p.write_bytes(canonical(body));p.chmod(0o600)
    monkeypatch.setattr(c,"IDENTITY_DIRECTORY",str(moved))
    from zog.host_identify import retained_legacy
    monkeypatch.setattr(retained_legacy,"DIRECTORY",str(moved))
    return plan,moved,evidence,witness,journal,key,real_fingerprint


def run_issue(row):
    plan,moved,evidence,*_=row
    handles=[]
    try:
        for path in (evidence/"original.json",evidence/"transaction.json",moved):
            handles.append(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|
                                   (os.O_DIRECTORY if path==moved else 0)))
        return c.completion_from_observed_fds(
            plan=plan,original_witness_fd=handles[0],journal_fd=handles[1],
            identity_fd=handles[2],identity_directory=str(moved),
            expected_uid=os.geteuid(),expected_gid=os.getegid())
    finally:
        for fd in handles:os.close(fd)


def test_exact_consumer_selection_requires_all_pins():
    assert verify_consumer_selection(dict(CONSUMER_SELECTION))==CONSUMER_SELECTION
    for value in (None,True,{"approved":True},
                  dict(CONSUMER_SELECTION,host_identify_revision="0"*40)):
        with pytest.raises(StateError):
            verify_consumer_selection(value)


def test_root_completed_receipt_matches_actual_host_identify_loader(retained):
    plan,moved,evidence,witness,journal,key,fp=retained
    receipt=run_issue(retained)
    assert receipt["schema"]==c.COMPLETION_SCHEMA
    assert receipt["journal_sha256"]==hashlib.sha256(
        (evidence/"transaction.json").read_bytes()).hexdigest()
    root=os.open(evidence,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        outcome=c.publish_completion(root,receipt)
        assert outcome["native_service_enabled"] is False
        assert c.publish_completion(root,receipt)==outcome
    finally:os.close(root)
    receipt_path=evidence/c.COMPLETION_FILE
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    from zog.host_identify.retained_legacy import load_retained_legacy_fd
    folder=os.open(moved,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fd=os.open(receipt_path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        loaded,binding=load_retained_legacy_fd(
            folder,fd,expected_host_uuid=plan["host_uuid"],
            expected_fingerprint=fp,
            expected_registry_origin=plan["registry_origin"],
            identity_directory=str(moved))
        from zog.host_identify.signatures import fingerprint
        assert fingerprint(loaded.public_key())==fp
        assert binding=={"host_id":plan["host_uuid"],"fingerprint":fp}
    finally:os.close(fd);os.close(folder)
    assert (moved/"identity.pem").read_bytes()==key.private_bytes(
        serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())


@pytest.mark.parametrize("attack",(
    "active","missing-stage","foreign-plan","foreign-migration",
    "witness-wrong-inode","witness-foreign-host","file-hardlink",
    "directory-replaced","unexpected-marker","journal-rollback",
    "witness-mode","changed-key-owner","foreign-registry",
))
def test_completion_cannot_be_published_for_unknown_or_changed_migration(retained,attack,tmp_path):
    plan,moved,evidence,witness,journal,*_=retained
    if attack=="active":journal["active"]=m.STAGES[-1]
    elif attack=="missing-stage":journal["completed"].pop()
    elif attack=="foreign-plan":journal["plan_sha256"]="e"*64
    elif attack=="foreign-migration":journal["migration_id"]=str(uuid.uuid4())
    elif attack=="witness-wrong-inode":witness["key_inode"]=[1,42]
    elif attack=="witness-foreign-host":witness["host_uuid"]=str(uuid.uuid4())
    elif attack=="file-hardlink":os.link(moved/"identity.pem",tmp_path/"linked")
    elif attack=="directory-replaced":
        moved.rename(tmp_path/"old")
        moved.mkdir(mode=0o700)
    elif attack=="unexpected-marker":(moved/"receipt.json").write_text("not allowed")
    elif attack=="journal-rollback":journal["status"]="rolling-back"
    elif attack=="witness-mode":(evidence/"original.json").chmod(0o644)
    elif attack=="changed-key-owner":os.chown(moved/"identity.pem",12345,-1)
    elif attack=="foreign-registry":witness["registry_origin"]="https://foreign.invalid"
    (evidence/"original.json").write_bytes(canonical(witness))
    (evidence/"transaction.json").write_bytes(canonical(journal))
    with pytest.raises((StateError,OSError,PermissionError)):
        run_issue(retained)


def test_root_receipt_conflicting_publication_refused(retained):
    plan,moved,evidence,*_=retained
    record=run_issue(retained)
    fd=os.open(evidence,os.O_RDONLY|os.O_DIRECTORY)
    try:
        c.publish_completion(fd,record)
        conflict=dict(record,host_uuid=str(uuid.uuid4()))
        with pytest.raises(StateError):
            c.publish_completion(fd,conflict)
    finally:os.close(fd)


@pytest.mark.parametrize("attack",(
    "valid","foreign-binding","substituted-key-inode","key-symlink",
    "key-hardlink","extra-entry","wrong-owner","wrong-mode",
))
def test_original_witness_is_captured_before_move_and_public_only(
        retained,attack,tmp_path):
    plan,moved,evidence,witness,journal,key,fp=retained
    legacy=tmp_path/"var/lib/host-discover/identity"
    legacy.parent.mkdir(parents=True)
    moved.rename(legacy)
    os.chown(legacy,991,991)
    for file in legacy.iterdir():os.chown(file,991,991)
    if attack=="foreign-binding":
        (legacy/"binding.json").write_text(json.dumps({
            "host_id":str(uuid.uuid4()),"fingerprint":fp}))
    elif attack=="substituted-key-inode":
        # Keep the original inode allocated: unlink+create may legitimately
        # reuse exactly the same inode number on ext4/XFS.
        (legacy/"identity.pem").rename(tmp_path/"original-key-backup")
        (legacy/"identity.pem").write_bytes(b"substituted")
        (legacy/"identity.pem").chmod(0o600)
        os.chown(legacy/"identity.pem",991,991)
        # Merely re-capturing a substituted inode must not count as prior
        # authorized evidence; a separate original inventory must be checked.
        pass
    elif attack=="key-symlink":
        (legacy/"identity.pem").unlink()
        (legacy/"identity.pem").symlink_to("/etc/passwd")
    elif attack=="key-hardlink":
        os.link(legacy/"identity.pem",tmp_path/"other-link")
    elif attack=="extra-entry":
        (legacy/"unknown").write_text("unexpected")
    elif attack=="wrong-owner":
        os.chown(legacy/"identity.pem",970,991)
    elif attack=="wrong-mode":
        (legacy/"binding.json").chmod(0o644)
    fd=os.open(legacy,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        if attack in ("foreign-binding","key-symlink","key-hardlink",
                      "extra-entry","wrong-owner","wrong-mode"):
            with pytest.raises((StateError,OSError,ValueError)):
                c.original_witness_from_fd(plan,fd)
        else:
            original=c.original_witness_from_fd(plan,fd)
            assert original["key_inode"]==ino(legacy/"identity.pem")
            assert original["identity_inode"]==ino(legacy)
            assert "private_key" not in original
            assert "identity.pem" not in c.canonical(original).decode()
            published=tmp_path/"new-original-witness"
            published.mkdir(mode=0o700)
            published.chmod(0o700)
            owner=os.open(published,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                outcome=c.publish_original_witness(owner,original)
                assert outcome["mutation_authorized"] is False
                assert c.publish_original_witness(owner,original)==outcome
                with pytest.raises(StateError):
                    c.publish_original_witness(
                        owner,dict(original,host_uuid=str(uuid.uuid4())))
            finally:os.close(owner)
            if attack=="valid":
                # Exact original key inode must be retained at destination.
                os.chown(legacy,0,0)
                for path in legacy.iterdir():os.chown(path,0,0)
                legacy.rename(moved)
                assert ino(moved/"identity.pem")==original["key_inode"]
                # The completed journal and signed identity consumer remain
                # independent: no stale witness is itself an activation grant.
                (evidence/"original.json").write_bytes(canonical(original))
                assert run_issue(retained)["key_inode"]==original["key_inode"]
            else:
                # Replacing the key before witness capture would be detected
                # by matching against the independently retained original
                # filesystem inode from the native preflight inventory.
                assert original["key_inode"]!=witness["key_inode"]

    finally:
        os.close(fd)

def test_original_witness_denies_missing_consumer_selection(retained,tmp_path):
    plan,moved,evidence,witness,*_=retained
    legacy=tmp_path/"original-host-discover-identity"
    moved.rename(legacy)
    os.chown(legacy,991,991)
    for item in legacy.iterdir():os.chown(item,991,991)
    plan["consumer_selection_sha256"]=None
    fd=os.open(legacy,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        with pytest.raises(StateError,match="migration-witness"):
            c.original_witness_from_fd(plan,fd)
    finally:os.close(fd)


@pytest.mark.parametrize("attack", (
    "valid", "changed-role", "deleted-origin", "role-symlink",
    "role-hardlink", "wrong-origin-mode", "foreign-role-owner",
    "unlisted-entry", "changed-role-inode",
))
def test_retained_role_and_origin_are_bound_across_identity_migration(
        retained,attack,tmp_path):
    plan,moved,evidence,witness,journal,key,fingerprint=retained
    legacy=tmp_path/"old/host-discover/identity"
    legacy.parent.mkdir(parents=True)
    moved.rename(legacy)
    sidecars={
        "mirror-role.json":b'{"status":{"state":"stopped"}}',
        "mirror-role.lock":b"",
        "primary-origin.json":b'{"origin":"https://registry.example.invalid"}',
    }
    for name,data in sidecars.items():
        target=legacy/name
        target.write_bytes(data)
        target.chmod(0o600)
    os.chown(legacy,991,991)
    for child in legacy.iterdir():os.chown(child,991,991)
    source_fd=os.open(legacy,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:original=c.original_witness_from_fd(plan,source_fd)
    finally:os.close(source_fd)
    assert set(original["retained_files"])==set(sidecars)
    assert all(original["retained_files"][n]["inode"]==ino(legacy/n)
               for n in sidecars)
    assert not any(data.decode(errors="ignore") in canonical(original).decode()
                   for data in sidecars.values() if data)
    (evidence/"original.json").write_bytes(canonical(original))
    # Simulate exactly the source-approved owner conversion and one inode-
    # preserving filesystem move before any daemon is launched.
    os.chown(legacy,0,0)
    for child in legacy.iterdir():os.chown(child,0,0)
    legacy.rename(moved)
    if attack=="changed-role":
        (moved/"mirror-role.json").write_bytes(b'{"status":"tampered"}')
    elif attack=="deleted-origin":
        (moved/"primary-origin.json").unlink()
    elif attack=="role-symlink":
        (moved/"mirror-role.json").unlink()
        (moved/"mirror-role.json").symlink_to("/etc/passwd")
    elif attack=="role-hardlink":
        os.link(moved/"mirror-role.lock",tmp_path/"foreign-hardlink")
    elif attack=="wrong-origin-mode":
        (moved/"primary-origin.json").chmod(0o644)
    elif attack=="foreign-role-owner":
        os.chown(moved/"mirror-role.json",10001,-1)
    elif attack=="unlisted-entry":
        (moved/"other-role.json").write_bytes(b"{}")
    elif attack=="changed-role-inode":
        replacement=moved/"replacement-tmp"
        replacement.write_bytes(sidecars["mirror-role.json"])
        replacement.chmod(0o600)
        os.replace(replacement,moved/"mirror-role.json")
    if attack != "valid":
        with pytest.raises((StateError,OSError,ValueError)):
            run_issue(retained)
        return
    receipt=run_issue(retained)
    assert set(receipt)=={
        "schema","status","migration_id","identity_directory","host_uuid",
        "fingerprint","registry_origin","uid","gid","identity_inode",
        "key_inode","binding_inode","lock_inode","ca_inode","ca_sha256",
        "plan_sha256","journal_sha256",
    }
    # The consumer's completion remains an identity document: mutable role
    # files are secured at migration time, not permanently inode-pinned.
    directory_fd=os.open(evidence,os.O_RDONLY|os.O_DIRECTORY)
    try:c.publish_completion(directory_fd,receipt)
    finally:os.close(directory_fd)
    from zog.host_identify.retained_legacy import load_retained_legacy_fd
    selected=os.open(moved,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    completed=os.open(evidence/c.COMPLETION_FILE,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        identity,binding=load_retained_legacy_fd(
            selected,completed,expected_host_uuid=plan["host_uuid"],
            expected_fingerprint=fingerprint,
            expected_registry_origin=plan["registry_origin"],
            identity_directory=str(moved))
        assert binding["fingerprint"]==fingerprint
        # Existing roles.Controller.save atomically publishes role changes.
        replacement=moved/".new-role"
        replacement.write_bytes(b'{"status":{"state":"ready"}}')
        replacement.chmod(0o600)
        os.replace(replacement,moved/"mirror-role.json")
        again,_=load_retained_legacy_fd(
            selected,completed,expected_host_uuid=plan["host_uuid"],
            expected_fingerprint=fingerprint,
            expected_registry_origin=plan["registry_origin"],
            identity_directory=str(moved))
        from zog.host_identify.signatures import fingerprint as compute_fp
        assert compute_fp(again.public_key())==fingerprint
    finally:os.close(completed);os.close(selected)


@pytest.mark.parametrize("attack", (
    "valid", "parent-symlink", "foreign-parent", "writable-parent",
    "wrong-root-device", "wrong-inode", "changed-identity-path",
    "final-symlink",
))
def test_original_path_descriptor_is_independently_opened(
        retained, tmp_path, attack, monkeypatch):
    # No production /var or Host identity is opened. A disposable stand-in
    # exercises the exact root-relative, component-by-component traversal.
    plan, moved, evidence, witness, journal, key, fingerprint = retained
    root = tmp_path / "original-root"
    legacy = root / "var/lib/host-discover/identity"
    legacy.parent.mkdir(parents=True, mode=0o755)
    moved.rename(legacy)
    os.chown(legacy, 991, 991)
    for entry in legacy.iterdir():
        os.chown(entry, 991, 991)
    expected = ino(legacy)
    root_device = root.stat().st_dev
    if attack == "parent-symlink":
        legacy.parent.rename(legacy.parent.with_name("host-discover-original"))
        legacy.parent.symlink_to("host-discover-original")
    elif attack == "foreign-parent":
        os.chown(legacy.parent, 991, 991)
    elif attack == "writable-parent":
        legacy.parent.chmod(0o777)
    elif attack == "wrong-root-device":
        root_device += 1
    elif attack == "wrong-inode":
        expected[1] += 1
    elif attack == "changed-identity-path":
        legacy.rename(legacy.with_name("identity-original"))
        legacy.mkdir(mode=0o700)
        os.chown(legacy, 991, 991)
    elif attack == "final-symlink":
        legacy.rename(legacy.with_name("identity-original"))
        legacy.symlink_to("identity-original", target_is_directory=True)
    options = dict(expected_root_device=root_device,
                   filesystem_root=str(root), allow_disposable=True)
    if attack != "valid":
        with pytest.raises((StateError, OSError)):
            c.open_original_legacy_identity_fd(expected, **options)
        return
    fd = c.open_original_legacy_identity_fd(expected, **options)
    try:
        assert [os.fstat(fd).st_dev, os.fstat(fd).st_ino] == expected
        original_open = os.open
        key_opens = []

        def audited_open(path, flags, *args, **kwargs):
            if path == "identity.pem":
                key_opens.append(flags)
                assert flags & os.O_PATH == os.O_PATH
                assert flags & os.O_NOFOLLOW
            return original_open(path, flags, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(c.os, "open", audited_open)
            result = c.original_witness_from_fd(plan, fd)
        assert key_opens and result["identity_inode"] == expected
        assert result["key_inode"] == ino(legacy / "identity.pem")
    finally:
        os.close(fd)


def test_original_key_completion_can_be_issued_at_durable_prestart_intent(
        retained):
    """Launcher must have key receipt before start, not after service start."""
    plan,moved,evidence,*_ = retained
    intent = m.service_start_intent(plan)
    (evidence/"transaction.json").write_bytes(canonical(intent))
    handles=[]
    try:
        for file in ("original.json","transaction.json"):
            handles.append(os.open(evidence/file,os.O_RDONLY|os.O_NOFOLLOW))
        handles.append(os.open(moved,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
        with pytest.raises(StateError):
            c.completion_from_observed_fds(
                plan=plan, original_witness_fd=handles[0],
                journal_fd=handles[1],identity_fd=handles[2],
                identity_directory=str(moved),
                expected_uid=0,expected_gid=0)
        receipt=c.completion_from_observed_fds(
            plan=plan, original_witness_fd=handles[0],
            journal_fd=handles[1],identity_fd=handles[2],
            identity_directory=str(moved),
            expected_uid=0,expected_gid=0, prestart=True)
        assert receipt["journal_sha256"] == hashlib.sha256(
            canonical(intent)).hexdigest()
    finally:
        for fd in handles: os.close(fd)
    invalid={**intent, "active":None}
    (evidence/"transaction.json").write_bytes(canonical(invalid))
    with pytest.raises(StateError):
        handles=[]
        try:
            for file in ("original.json","transaction.json"):
                handles.append(os.open(evidence/file,os.O_RDONLY|os.O_NOFOLLOW))
            handles.append(os.open(moved,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
            c.completion_from_observed_fds(
                plan=plan, original_witness_fd=handles[0],
                journal_fd=handles[1],identity_fd=handles[2],
                identity_directory=str(moved),
                expected_uid=0,expected_gid=0, prestart=True)
        finally:
            for fd in handles: os.close(fd)
