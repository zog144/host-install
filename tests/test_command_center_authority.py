import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_install import command_center_authority as authority
from zog.host_install.state_contract import StateError, canonical


NOW = 1793376000


def uid(number):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"zog-command-center-test-{number}"))


def fixture(*, identity_registry_id="primary", grant_registry_id="primary"):
    operator = Ed25519PrivateKey.generate()
    certificate = Ed25519PrivateKey.generate()
    credential = Ed25519PrivateKey.generate()
    consumer = Ed25519PrivateKey.generate()

    def raw(key):
        return key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    operator_pin = raw(operator)
    certificate_pin = raw(certificate)
    authority_pin = raw(credential)
    consumer_pin = raw(consumer)

    evidence = canonical({
        "schema": "synthetic-preauthenticated-aws-iid-evidence-v1",
        "instance_id": authority.COMMAND_CENTER_INSTANCE_ID,
        "document_sha256": "e" * 64,
        "verification": "native-owner-prerequisite",
    })
    observed = {
        "path": "/var/lib/station-access/database.sqlite3",
        "device": 11,
        "inode": 307826,
        "owner_uid": 999,
        "mode": 0o644,
        "parent_device": 11,
        "parent_inode": 307000,
    }
    identity_unsigned = {
        "schema": authority.IDENTITY_SCHEMA,
        "station_role": "command-center-host",
        "installation_mode": "externally-managed",
        "state_mode": "existing-station-application-database",
        "command_center_host_id": uid(1),
        "command_center_installation_id": uid(2),
        "external_host_instance_id": authority.COMMAND_CENTER_INSTANCE_ID,
        "external_host_evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        "station_registry_id": identity_registry_id,
        "station_source_commit": authority.STATION_ACCESS_COMMIT,
        "database_path": observed["path"],
        "database_device": observed["device"],
        "database_inode": observed["inode"],
        "database_owner_uid": observed["owner_uid"],
        "database_mode": observed["mode"],
        "database_parent_device": observed["parent_device"],
        "database_parent_inode": observed["parent_inode"],
        "enrolled_consumer_host_id": uid(3),
        "enrolled_consumer_installation_id": uid(4),
        "enrolled_consumer_state_volume_id": uid(5),
        "certificate_signer_pin_sha256": hashlib.sha256(certificate_pin).hexdigest(),
        "review_revision": 1,
        "issued_at": NOW - 60,
        "expires_at": NOW + 86400,
    }
    identity = {
        **identity_unsigned,
        "signature_ed25519": base64.b64encode(
            operator.sign(
                authority.IDENTITY_DOMAIN + canonical(identity_unsigned)
            )
        ).decode("ascii"),
    }

    projection_auth = {
        "schema": authority.PROJECTION_AUTH_SCHEMA,
        "state": "approved",
        "project": "/srv/station",
        "certificate_id": "station-web",
        "assignment_id": uid(6),
        "assignment_revision": 2,
        "credential_id": uid(7),
        "credential_revision": 3,
        "zone_id": "zone01",
        "zone_name": "example.org",
        "grant_id": "a" * 32,
        "storage_id": "b" * 32,
        "policy_sha256": "c" * 64,
        "receipt_sha256": "d" * 64,
        "expires_at": NOW + 7200,
    }
    projection = {
        "schema": authority.PROJECTION_SCHEMA,
        "authorization": projection_auth,
        "origin": "managed",
        "installation_id": uid(4),
        "host_id": uid(3),
        "account_id": "f" * 32,
        "owner_user_id": 10,
    }

    grant_packet = {
        "schema": authority.GRANT_SCHEMA,
        "state": "approved",
        "purpose": authority.PURPOSE,
        "consumer": authority.CONSUMER,
        "destination": authority.DESTINATION,
        "host_id": uid(3),
        "fingerprint": "1" * 64,
        "installation_id": uid(4),
        "state_volume_id": uid(5),
        "authority_id": uid(8),
        "registry_id": grant_registry_id,
        "assignment_id": uid(6),
        "assignment_revision": 2,
        "credential_revision": 3,
        "authorization_id": hashlib.sha256(canonical(projection_auth)).hexdigest(),
        "grant_id": "a" * 32,
        "storage_id": "b" * 32,
        "consumer_public_key": base64.b64encode(consumer_pin).decode("ascii"),
        "consumer_key_fingerprint": hashlib.sha256(consumer_pin).hexdigest(),
        "consumer_key_revision": 1,
        "independent_signer_pin_sha256": hashlib.sha256(certificate_pin).hexdigest(),
        "revision": 4,
        "expires_at": NOW + 3600,
    }
    grant_approval_unsigned = {
        "schema": authority.GRANT_APPROVAL_SCHEMA,
        "grant_sha256": hashlib.sha256(canonical(grant_packet)).hexdigest(),
    }
    grant_approval = {
        **grant_approval_unsigned,
        "signature_ed25519": base64.b64encode(
            operator.sign(
                authority.GRANT_APPROVAL_DOMAIN + canonical(grant_packet)
            )
        ).decode("ascii"),
    }
    grant = {
        **grant_packet,
        "operator_approval_sha256": hashlib.sha256(
            canonical(grant_approval)
        ).hexdigest(),
    }

    issuer = "https://host-registry.hosts.zog-network-demo.uk"
    authorization = {
        "schema": authority.AUTHORIZATION_SCHEMA,
        "issuer": issuer,
        "host_id": uid(3),
        "host_fingerprint": "1" * 64,
        "installation_id": uid(4),
        "state_volume_id": uid(5),
        "registry_id": grant_registry_id,
        "consumer": authority.CONSUMER,
        "purpose": authority.PURPOSE,
        "credential_id": "cloudflare-" + uid(7).replace("-", ""),
        "credential_revision": 3,
        "authorization_id": uid(9),
        "revision": 4,
        "status": "approved",
        "approved_at": NOW - 30,
        "revoked_at": None,
        "expires_at": NOW + 1800,
    }
    authorization_envelope = {
        "schema": authority.AUTHORIZATION_ENVELOPE_SCHEMA,
        "key_id": hashlib.sha256(authority_pin).hexdigest(),
        "authorization": authorization,
        "signature": base64.b64encode(
            credential.sign(
                authority.AUTHORIZATION_DOMAIN + canonical(authorization)
            )
        ).decode("ascii"),
    }
    role_unsigned = {
        "schema": authority.ROLE_APPROVAL_SCHEMA,
        "grant_sha256": hashlib.sha256(canonical(grant)).hexdigest(),
        "authorization_envelope_sha256": hashlib.sha256(
            canonical(authorization_envelope)
        ).hexdigest(),
        "authority_signer_sha256": hashlib.sha256(authority_pin).hexdigest(),
        "authorization_id": uid(9),
        "revision": 4,
        "expires_at": NOW + 2400,
    }
    role_approval = {
        **role_unsigned,
        "signature_ed25519": base64.b64encode(
            operator.sign(
                authority.ROLE_APPROVAL_DOMAIN + canonical(role_unsigned)
            )
        ).decode("ascii"),
    }
    private = credential.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return {
        "materials": {
            "operator_pin": operator_pin,
            "identity": canonical(identity),
            "aws_evidence": evidence,
            "certificate_pin": certificate_pin,
            "grant": canonical(grant),
            "grant_approval": canonical(grant_approval),
            "projection": canonical(projection),
            "authority_private_key": private,
            "authority_pin": authority_pin,
            "authorization": canonical(authorization_envelope),
            "authority_approval": canonical(role_approval),
        },
        "observed": observed,
        "operator_sha": hashlib.sha256(operator_pin).hexdigest(),
        "certificate_sha": hashlib.sha256(certificate_pin).hexdigest(),
        "issuer": issuer,
    }


def verify(value):
    return authority.verify_materials(
        value["materials"],
        expected_operator_pin_sha256=value["operator_sha"],
        expected_certificate_signer_sha256=value["certificate_sha"],
        expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
        expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
        expected_authorization_issuer=value["issuer"],
        observed_database=value["observed"],
        now=NOW,
    )


def test_exact_trust_graph_verifies_without_claiming_state_or_activation():
    value = fixture()
    report = verify(value)
    assert report["status"] == "protected-offline-authority-materials-verified"
    assert report["canonical_host_install_state_verified"] is False
    assert report["canonical_host_install_state_created"] is False
    assert report["offline_materials_only"] is True
    assert report["production_activation_authorized"] is False
    assert report["credential_delivery_authorized"] is False
    assert report["credential_transferred"] is False
    assert len({
        report["operator_pin_sha256"],
        report["certificate_signer_pin_sha256"],
        report["credential_authority_pin_sha256"],
    }) == 3
    assert (
        report["source_closure"]["host_install_companion"]
        == authority.COMPANION_HOST_INSTALL_COMMIT
    )


def test_consumer_identity_cannot_be_reused_as_command_center():
    value = fixture()
    identity = json.loads(value["materials"]["identity"])
    identity["command_center_host_id"] = identity["enrolled_consumer_host_id"]
    value["materials"]["identity"] = canonical(identity)
    with pytest.raises(StateError):
        verify(value)


@pytest.mark.parametrize("target_role,duplicate_role", [
    ("authority_pin", "operator_pin"),
    ("certificate_pin", "operator_pin"),
    ("authority_pin", "certificate_pin"),
])
def test_three_signing_roles_must_remain_distinct(target_role, duplicate_role):
    value = fixture()
    value["materials"][target_role] = value["materials"][duplicate_role]
    with pytest.raises(StateError, match="three distinct"):
        verify(value)


def test_matching_credential_authority_public_key_still_requires_original_private_key():
    value = fixture()
    other = fixture()
    value["materials"]["authority_private_key"] = other["materials"]["authority_private_key"]
    with pytest.raises(StateError, match="private/public signer mismatch"):
        verify(value)


def test_wrong_independently_expected_operator_pin_fails():
    value = fixture()
    with pytest.raises(StateError):
        authority.verify_materials(
            value["materials"],
            expected_operator_pin_sha256="0" * 64,
            expected_certificate_signer_sha256=value["certificate_sha"],
            expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
            expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
            expected_authorization_issuer=value["issuer"],
            observed_database=value["observed"],
            now=NOW,
        )


def test_changed_database_inode_fails():
    value = fixture()
    changed = dict(value["observed"])
    changed["inode"] += 1
    with pytest.raises(StateError):
        authority.verify_materials(
            value["materials"],
            expected_operator_pin_sha256=value["operator_sha"],
            expected_certificate_signer_sha256=value["certificate_sha"],
            expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
            expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
            expected_authorization_issuer=value["issuer"],
            observed_database=changed,
            now=NOW,
        )


def test_grant_or_authorization_substitution_fails():
    value = fixture()
    grant = json.loads(value["materials"]["grant"])
    grant["credential_revision"] += 1
    value["materials"]["grant"] = canonical(grant)
    with pytest.raises(StateError):
        verify(value)

    value = fixture()
    envelope = json.loads(value["materials"]["authorization"])
    envelope["authorization"]["expires_at"] -= 1
    value["materials"]["authorization"] = canonical(envelope)
    with pytest.raises(StateError):
        verify(value)


def test_no_replacement_publication_and_same_byte_resume():
    value = fixture()
    receipt = verify(value)
    with tempfile.TemporaryDirectory() as temp:
        root = os.open(temp, os.O_RDONLY | os.O_DIRECTORY)
        try:
            authority._publish_bundle(
                root, value["materials"], receipt, os.getgid()
            )
            authority._publish_bundle(
                root, value["materials"], receipt, os.getgid()
            )
            child = Path(temp) / authority.DIRECTORY_NAME
            assert {path.name for path in child.iterdir()} == set(authority.FILES)
            assert (
                child / authority.RECEIPT_NAME
            ).read_bytes() == canonical(receipt)

            changed = dict(value["materials"])
            changed["grant"] = changed["grant"] + b"\n"
            with pytest.raises(StateError):
                authority._publish_bundle(
                    root, changed, receipt, os.getgid()
                )
            assert (
                child / "root-grant.json"
            ).read_bytes() == value["materials"]["grant"]
        finally:
            os.close(root)


def test_unrecognized_file_blocks_publication_before_replacement():
    value = fixture()
    receipt = verify(value)
    with tempfile.TemporaryDirectory() as temp:
        root = os.open(temp, os.O_RDONLY | os.O_DIRECTORY)
        try:
            child = Path(temp) / authority.DIRECTORY_NAME
            child.mkdir(mode=0o700)
            (child / "foreign").write_text("do not touch")
            with pytest.raises(StateError):
                authority._publish_bundle(
                    root, value["materials"], receipt, os.getgid()
                )
            assert (child / "foreign").read_text() == "do not touch"
            assert not (child / "root-grant.json").exists()
        finally:
            os.close(root)


def test_source_contract_is_specific_to_externally_managed_command_center():
    assert authority.COMMAND_CENTER_INSTANCE_ID == "i-0c676721165320da0"
    assert (
        authority.STATION_ACCESS_COMMIT
        == "c2540cc5c9a3a0c1fff2748552819685ed2fdff4"
    )
    assert authority.RETAINED_CERTIFICATE_SIGNER_SHA256 == (
        "1ecf7d17bd8abc00ca50bde297f427b0fa28f2f6894b0a0cb71ae8d1237425cb"
    )


@pytest.mark.parametrize("identity_registry_id,grant_registry_id", [
    ("primary", "secondary"),
    ("secondary", "primary"),
])
def test_valid_independently_signed_cross_registry_inputs_are_rejected(
        identity_registry_id, grant_registry_id):
    # Identity, root grant, approval AND v1 authorization all have correct
    # signatures. They differ only in the signed registry selection.
    value = fixture(identity_registry_id=identity_registry_id,
                    grant_registry_id=grant_registry_id)
    with pytest.raises(StateError, match="root grant binding mismatch"):
        verify(value)


def test_matching_nondefault_signed_registry_is_allowed():
    value = fixture(identity_registry_id="secondary",
                    grant_registry_id="secondary")
    assert verify(value)["station_registry_id"] == "secondary"


class SimulatedPublicationInterruption(RuntimeError):
    """Represents termination after a real file fsync/link/unlink checkpoint."""


@pytest.mark.parametrize("file_name", tuple(authority.FILES))
@pytest.mark.parametrize("moment", ("staged", "linked", "published"))
def test_interrupted_bundle_publication_resumes_without_replacement(
        tmp_path, monkeypatch, file_name, moment):
    value = fixture()
    receipt = verify(value)
    original = authority.publish
    folder = tmp_path / authority.DIRECTORY_NAME

    def interrupted(fd, name, data, *, mode, uid, gid,
                    checkpoint=lambda _: None):
        def interrupted_checkpoint(step):
            checkpoint(step)
            if step == f"{moment}:{file_name}":
                raise SimulatedPublicationInterruption(step)
        return original(fd, name, data, mode=mode, uid=uid, gid=gid,
                        checkpoint=interrupted_checkpoint)

    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(authority, "publish", interrupted)
            with pytest.raises(SimulatedPublicationInterruption,
                               match=file_name):
                authority._publish_bundle(
                    root, value["materials"], receipt, os.getgid()
                )
        assert folder.is_dir()
        assert (folder / authority.RECEIPT_NAME).exists() == (
            file_name == authority.RECEIPT_NAME and moment != "staged"
        )
        old_inodes = {
            name: (folder / name).stat().st_ino for name in authority.FILES
            if (folder / name).exists()
        }
    finally:
        os.close(root)

    # Reopen a different descriptor, simulating process restart, and
    # reconcile actual on-disk data (not a mocked publishing routine).
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        authority._publish_bundle(root, value["materials"], receipt, os.getgid())
        assert set(os.listdir(folder)) == set(authority.FILES)
        assert (folder / authority.RECEIPT_NAME).read_bytes() == canonical(receipt)
        for name, inode in old_inodes.items():
            assert (folder / name).stat().st_ino == inode
        after = {name: (folder / name).stat().st_ino for name in authority.FILES}
        authority._publish_bundle(root, value["materials"], receipt, os.getgid())
        assert {name: (folder / name).stat().st_ino
                for name in authority.FILES} == after
    finally:
        os.close(root)


@pytest.mark.parametrize("premature_name", (
    authority.RECEIPT_NAME, ".pending." + authority.RECEIPT_NAME,
))
def test_premature_receipt_does_not_publish_missing_files(
        tmp_path, premature_name):
    value = fixture()
    receipt = verify(value)
    folder = tmp_path / authority.DIRECTORY_NAME
    folder.mkdir(mode=0o700)
    premature = folder / premature_name
    premature.write_bytes(canonical(receipt))
    premature.chmod(0o600)
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(StateError, match="receipt present before complete"):
            authority._publish_bundle(root, value["materials"], receipt, os.getgid())
        assert set(os.listdir(folder)) == {premature_name}
        assert premature.read_bytes() == canonical(receipt)
    finally:
        os.close(root)


@pytest.mark.parametrize("corrupted_name", (
    authority.RECEIPT_NAME, ".pending." + authority.RECEIPT_NAME,
))
def test_partial_receipt_bytes_fail_closed_with_no_replacement(
        tmp_path, corrupted_name):
    value = fixture()
    receipt = verify(value)
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        authority._publish_bundle(root, value["materials"], receipt, os.getgid())
        folder = tmp_path / authority.DIRECTORY_NAME
        (folder / authority.RECEIPT_NAME).unlink()
        corrupt = folder / corrupted_name
        corrupt.write_bytes(b'{"schema":"partial')
        corrupt.chmod(0o600)
        originals = {
            name: (folder / name).stat().st_ino for name in authority.FILES
            if name != authority.RECEIPT_NAME
        }
        with pytest.raises(StateError, match="record-conflict|publication-conflict"):
            authority._publish_bundle(root, value["materials"], receipt, os.getgid())
        assert corrupt.read_bytes() == b'{"schema":"partial'
        if corrupted_name != authority.RECEIPT_NAME:
            assert not (folder / authority.RECEIPT_NAME).exists()
        for name, inode in originals.items():
            assert (folder / name).stat().st_ino == inode
    finally:
        os.close(root)



# Command-Center writer-lock source regression. All paths below are synthetic.
# The protected production owner must independently bootstrap the original
# lock and its inode anchor before stage_offline can run.
def _writer_root(tmp_path):
    folder = tmp_path / "synthetic-offline-root"
    folder.mkdir(mode=0o700)
    folder.chmod(0o700)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return folder, fd, os.getuid(), os.getgid()


def test_writer_first_bootstrap_and_same_inode_resume(tmp_path):
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        lock_inode = (folder / authority.LOCK_NAME).stat().st_ino
        anchor_bytes = (folder / authority.LOCK_IDENTITY_NAME).read_bytes()
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        assert (folder / authority.LOCK_NAME).stat().st_ino == lock_inode
        assert (folder / authority.LOCK_IDENTITY_NAME).read_bytes() == anchor_bytes
        with authority._offline_writer_lock(fd, uid=uid, gid=gid) as guard:
            guard()
    finally:
        os.close(fd)


def test_interrupted_first_lock_provisioning_requires_explicit_reconciliation(tmp_path):
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        def crash(event):
            if event == "writer-created":
                raise RuntimeError("simulated crash before durable marker")
        with pytest.raises(RuntimeError, match="simulated crash"):
            authority.prepare_offline_writer_lock_source(
                fd, uid=uid, gid=gid, checkpoint=crash)
        assert (folder / authority.LOCK_NAME).exists()
        assert not (folder / authority.LOCK_IDENTITY_NAME).exists()
        with pytest.raises(StateError, match="partial first writer bootstrap"):
            authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        with pytest.raises(StateError, match="durable lock identity"):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid):
                pytest.fail("cannot adopt a partial writer bootstrap")
    finally:
        os.close(fd)


@pytest.mark.parametrize("change", ("deleted", "replaced", "symlink", "hardlink"))
def test_vanished_or_substituted_protected_lock_is_never_adopted(tmp_path, change):
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        anchor = (folder / authority.LOCK_IDENTITY_NAME).read_bytes()
        original = folder / authority.LOCK_NAME
        if change == "hardlink":
            os.link(original, folder / "foreign-lock-link")
        else:
            original.rename(folder / "retained-original-lock")
            if change == "replaced":
                original.write_bytes(b"")
                original.chmod(0o600)
            elif change == "symlink":
                original.symlink_to(folder / "retained-original-lock")
        with pytest.raises((StateError, OSError)):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid):
                pytest.fail("changed writer identity must never be accepted")
        assert (folder / authority.LOCK_IDENTITY_NAME).read_bytes() == anchor
        assert not (folder / authority.DIRECTORY_NAME).exists()
    finally:
        os.close(fd)


def test_competing_writers_cannot_split_on_deleted_or_replaced_lock(tmp_path):
    import threading
    folder, fd, uid, gid = _writer_root(tmp_path)
    second_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    blocked = threading.Event()
    started = threading.Event()
    done = threading.Event()
    errors = []
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        original_inode = (folder / authority.LOCK_NAME).stat().st_ino
        def second_writer():
            started.set()
            try:
                with authority._offline_writer_lock(second_fd, uid=uid, gid=gid):
                    errors.append("unexpected second writer")
            except StateError:
                blocked.set()
            finally:
                done.set()
        with pytest.raises(StateError, match="writer lock pathname was replaced"):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid) as guard:
                worker = threading.Thread(target=second_writer)
                worker.start()
                assert started.wait(3)
                assert not done.wait(.05)  # blocked on directory identity
                (folder / authority.LOCK_NAME).rename(folder / "old-lock")
                (folder / authority.LOCK_NAME).write_bytes(b"")
                (folder / authority.LOCK_NAME).chmod(0o600)
                guard()
        worker.join(3)
        assert not worker.is_alive() and done.is_set() and blocked.is_set()
        assert errors == []
        assert (folder / authority.LOCK_NAME).stat().st_ino != original_inode
        assert not (folder / authority.RECEIPT_NAME).exists()
    finally:
        os.close(second_fd)
        os.close(fd)


def test_path_substitution_mid_publication_refuses_final_receipt(tmp_path):
    value = fixture()
    receipt = verify(value)
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        touched = []
        with pytest.raises(StateError, match="writer lock pathname was replaced"):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid) as guard:
                def adversarial_guard(event=None):
                    if event == "staged:root-grant.json" and not touched:
                        touched.append(event)
                        (folder / authority.LOCK_NAME).rename(folder / "old-lock")
                        (folder / authority.LOCK_NAME).write_bytes(b"")
                        (folder / authority.LOCK_NAME).chmod(0o600)
                    guard()
                authority._publish_bundle(
                    fd, value["materials"], receipt, os.getgid(),
                    verify_writer=adversarial_guard)
        assert touched
        staged = folder / authority.DIRECTORY_NAME
        assert staged.is_dir()
        assert not (staged / authority.RECEIPT_NAME).exists()
        with pytest.raises(StateError):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid):
                pytest.fail("replacement lock cannot resume the receipt")
    finally:
        os.close(fd)


def test_intact_writer_allows_interrupted_same_byte_resume(tmp_path):
    value = fixture()
    receipt = verify(value)
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        attempt = []
        with pytest.raises(RuntimeError, match="synthetic fsync interruption"):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid) as guard:
                def interrupt(event=None):
                    guard()
                    if event == "linked:root-grant.json" and not attempt:
                        attempt.append(event)
                        raise RuntimeError("synthetic fsync interruption")
                authority._publish_bundle(fd,value["materials"],receipt,os.getgid(),
                                          verify_writer=interrupt)
        staged = folder / authority.DIRECTORY_NAME
        inode = (staged / "root-grant.json").stat().st_ino
        with authority._offline_writer_lock(fd, uid=uid, gid=gid) as guard:
            authority._publish_bundle(fd,value["materials"],receipt,os.getgid(),
                                      verify_writer=guard)
        assert (staged / "root-grant.json").stat().st_ino == inode
        assert (staged / authority.RECEIPT_NAME).read_bytes() == canonical(receipt)
        assert set(os.listdir(staged)) == set(authority.FILES)
    finally:
        os.close(fd)


@pytest.mark.skipif(os.geteuid()!=0,
                    reason="ephemeral original root-owned stage/inspect required")
def test_actual_stage_and_inspect_do_not_adopt_recreated_lock(tmp_path,monkeypatch):
    value = fixture()
    receipt = verify(value)
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        monkeypatch.setattr(authority,"_offline_root",
                            lambda _path:os.open(folder,os.O_RDONLY|os.O_DIRECTORY|
                                                  os.O_NOFOLLOW))
        monkeypatch.setattr(authority,"_read_inputs",
                            lambda paths,reader_gid:value["materials"])
        monkeypatch.setattr(authority,"_observe_database",
                            lambda path:value["observed"])
        monkeypatch.setattr(authority,"RETAINED_CERTIFICATE_SIGNER_SHA256",
                            value["certificate_sha"])
        args=dict(offline_directory=str(folder),
                  paths={},reader_gid=21001,
                  expected_operator_pin_sha256=value["operator_sha"],
                  expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
                  expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
                  expected_authorization_issuer=value["issuer"],now=NOW)
        result=authority.stage_offline(**args)
        assert result["status"] == receipt["status"]
        assert authority.inspect_offline(**{k:v for k,v in args.items()
                if k!="paths"})["status"]=="protected-offline-authority-materials-retained"
        (folder / authority.LOCK_NAME).rename(folder / "retained-lock")
        (folder / authority.LOCK_NAME).write_bytes(b"")
        (folder / authority.LOCK_NAME).chmod(0o600)
        with pytest.raises(StateError):
            authority.stage_offline(**args)
        with pytest.raises(StateError):
            authority.inspect_offline(**{k:v for k,v in args.items()
                if k!="paths"})
        assert (folder / authority.DIRECTORY_NAME /
                authority.RECEIPT_NAME).read_bytes() == canonical(receipt)
    finally:
        os.close(fd)


@pytest.mark.parametrize("change", ("renamed-away", "renamed-and-replaced"))
def test_renamed_protected_root_cannot_continue_on_stale_directory_lock(tmp_path, change):
    """Two root directories mean two distinct flock inodes. Reject old fd."""
    folder, fd, uid, gid = _writer_root(tmp_path)
    original = folder.with_name(folder.name + "-moved")
    replacement_fd = None
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        with pytest.raises(StateError, match="original offline"):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid,
                                                path=str(folder)) as guard:
                folder.rename(original)
                if change == "renamed-and-replaced":
                    folder.mkdir(mode=0o700)
                    replacement_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
                    # A different protected root can indeed acquire its own
                    # separate directory lock; an old writer must not publish
                    # into its disconnected inode after this namespace split.
                    authority.prepare_offline_writer_lock_source(
                        replacement_fd, uid=uid, gid=gid)
                    with authority._offline_writer_lock(
                            replacement_fd, uid=uid, gid=gid, path=str(folder)):
                        pass
                guard()
        assert not (original / authority.DIRECTORY_NAME).exists()
        if change == "renamed-and-replaced":
            assert not (folder / authority.DIRECTORY_NAME).exists()
        # Original lock and marker bytes remain inert; never repair/rewrite.
        assert (original / authority.LOCK_NAME).is_file()
        assert (original / authority.LOCK_IDENTITY_NAME).is_file()
    finally:
        if replacement_fd is not None:
            os.close(replacement_fd)
        os.close(fd)


@pytest.mark.parametrize("change", ("removed", "same-bytes-replacement",
                                     "symlink", "hardlink"))
def test_durable_marker_entry_cannot_change_during_staging(tmp_path, change):
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        marker = folder / authority.LOCK_IDENTITY_NAME
        original_bytes = marker.read_bytes()
        with pytest.raises(StateError):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid,
                                                path=str(folder)) as guard:
                if change == "removed":
                    marker.unlink()
                elif change == "same-bytes-replacement":
                    marker.rename(folder / "retained-original-marker")
                    marker.write_bytes(original_bytes)
                    marker.chmod(0o600)
                elif change == "symlink":
                    marker.rename(folder / "retained-original-marker")
                    marker.symlink_to(folder / "retained-original-marker")
                else:
                    os.link(marker, folder / "foreign-marker-link")
                guard()
        assert not (folder / authority.DIRECTORY_NAME).exists()
        assert (folder / authority.LOCK_NAME).is_file()
    finally:
        os.close(fd)


def test_missing_marker_after_completed_bootstrap_is_not_recreated(tmp_path):
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        marker = folder / authority.LOCK_IDENTITY_NAME
        marker.unlink()
        with pytest.raises(StateError):
            authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        with pytest.raises(StateError):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid,
                                                path=str(folder)):
                pytest.fail("lost marker cannot be repaired on stage")
        assert not marker.exists()
        assert (folder / authority.LOCK_NAME).is_file()
    finally:
        os.close(fd)


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned synthetic inspection")
def test_inspect_refuses_detached_original_root_after_path_replacement(tmp_path, monkeypatch):
    """Readback must not accept an old directory fd after namespace replacement."""
    value = fixture()
    receipt = verify(value)
    folder, fd, uid, gid = _writer_root(tmp_path)
    moved = folder.with_name(folder.name + "-detached")
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        with authority._offline_writer_lock(fd, uid=uid, gid=gid,
                                            path=str(folder)) as guard:
            authority._publish_bundle(fd, value["materials"], receipt, 21001,
                                      verify_writer=guard)
        assert (folder / authority.DIRECTORY_NAME /
                authority.RECEIPT_NAME).read_bytes() == canonical(receipt)
        folder.rename(moved)
        folder.mkdir(mode=0o700)
        # Even with an otherwise intact original lock, marker, all material
        # bytes and receipt at the *detached* inode, inspection must not claim
        # authority for the new selected path.
        monkeypatch.setattr(authority, "_offline_root", lambda _:
                            os.open(moved, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW))
        monkeypatch.setattr(authority, "_observe_database",
                            lambda _: value["observed"])
        monkeypatch.setattr(authority, "RETAINED_CERTIFICATE_SIGNER_SHA256",
                            value["certificate_sha"])
        with pytest.raises(StateError, match="offline directory pathname was replaced"):
            authority.inspect_offline(
                offline_directory=str(folder), reader_gid=21001,
                expected_operator_pin_sha256=value["operator_sha"],
                expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
                expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
                expected_authorization_issuer=value["issuer"], now=NOW)
        assert not (folder / authority.DIRECTORY_NAME).exists()
        assert (moved / authority.DIRECTORY_NAME /
                authority.RECEIPT_NAME).read_bytes() == canonical(receipt)
    finally:
        os.close(fd)


# Additional stage-entry checks independently authored for PR #19; run
# against the final PR #18 original lock, marker and directory fences.


def test_staged_child_entry_substitution_fails_before_receipt(tmp_path):
    value = fixture()
    receipt = verify(value)
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        touched = []
        with pytest.raises(StateError, match="authority subdirectory pathname was replaced"):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid) as check:
                def replace_child(event=None):
                    # Let the original fsync/checkpoint finish; then displace
                    # the public name while the writer keeps its child fd.
                    if event == "linked:root-grant.json" and not touched:
                        touched.append(event)
                        child = folder / authority.DIRECTORY_NAME
                        child.rename(folder / "retained-offline-bundle")
                        child.mkdir(mode=0o700)
                        child.chmod(0o700)
                    check()
                authority._publish_bundle(
                    fd, value["materials"], receipt, os.getgid(),
                    verify_writer=replace_child)
        assert touched
        assert not (folder / authority.DIRECTORY_NAME /
                    authority.RECEIPT_NAME).exists()
        assert not (folder / "retained-offline-bundle" /
                    authority.RECEIPT_NAME).exists()
    finally:
        os.close(fd)


def test_staged_child_entry_disappearance_fails_closed(tmp_path):
    value = fixture()
    receipt = verify(value)
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        with pytest.raises(StateError, match="authority subdirectory pathname missing"):
            with authority._offline_writer_lock(fd, uid=uid, gid=gid) as check:
                def unlink_child(event=None):
                    if event == "staged:root-grant.json":
                        (folder / authority.DIRECTORY_NAME).rename(
                            folder / "renamed-no-name")
                    check()
                authority._publish_bundle(
                    fd, value["materials"], receipt, os.getgid(),
                    verify_writer=unlink_child)
        assert not (folder / "renamed-no-name" /
                    authority.RECEIPT_NAME).exists()
    finally:
        os.close(fd)


def test_intact_original_child_entry_preserves_same_byte_retry(tmp_path):
    value = fixture()
    receipt = verify(value)
    folder, fd, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        child = folder / authority.DIRECTORY_NAME
        with authority._offline_writer_lock(fd, uid=uid, gid=gid) as check:
            authority._publish_bundle(fd, value["materials"], receipt,
                                      os.getgid(), verify_writer=check)
        before = child.stat().st_ino
        initial_inodes = {name:(child / name).stat().st_ino
                          for name in authority.FILES}
        with authority._offline_writer_lock(fd, uid=uid, gid=gid) as check:
            authority._publish_bundle(fd, value["materials"], receipt,
                                      os.getgid(), verify_writer=check)
        assert child.stat().st_ino == before
        assert initial_inodes == {name:(child / name).stat().st_ino
                                  for name in authority.FILES}
    finally:
        os.close(fd)


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned ephemeral inspection")
def test_inspection_readback_rejects_child_replacement_during_material_read(tmp_path, monkeypatch):
    """An inspection cannot approve bytes from a detached staged child fd."""
    value = fixture()
    receipt = verify(value)
    folder, root, uid, gid = _writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(root, uid=uid, gid=gid)
        with authority._offline_writer_lock(root, uid=uid, gid=gid,
                                            path=str(folder)) as check:
            authority._publish_bundle(root, value["materials"], receipt,
                                      21001, verify_writer=check)
        named = folder / authority.DIRECTORY_NAME
        original = folder / "inert-staging-moved"
        monkeypatch.setattr(authority, "_offline_root",
                            lambda _: os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        monkeypatch.setattr(authority, "_observe_database",
                            lambda _: value["observed"])
        monkeypatch.setattr(authority, "RETAINED_CERTIFICATE_SIGNER_SHA256",
                            value["certificate_sha"])
        actual_raw = authority.raw
        changed = []
        def adversarial_raw(fd, name, **kwargs):
            response = actual_raw(fd, name, **kwargs)
            if name == "operator-ed25519.pub" and not changed:
                changed.append(name)
                named.rename(original)
                named.mkdir(mode=0o700)
            return response
        with monkeypatch.context() as patcher:
            patcher.setattr(authority, "raw", adversarial_raw)
            with pytest.raises(StateError, match="authority subdirectory pathname was replaced"):
                authority.inspect_offline(
                    offline_directory=str(folder), reader_gid=21001,
                    expected_operator_pin_sha256=value["operator_sha"],
                    expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
                    expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
                    expected_authorization_issuer=value["issuer"], now=NOW)
        assert changed == ["operator-ed25519.pub"]
        assert not (named / authority.RECEIPT_NAME).exists()
        assert (original / authority.RECEIPT_NAME).read_bytes() == canonical(receipt)
    finally:
        os.close(root)


def test_renamed_ancestor_of_writer_root_does_not_preserve_path_authority(tmp_path):
    """Renaming a parent directory is distinct from renaming the leaf itself."""
    folder, fd, uid, gid = _writer_root(tmp_path)
    original_path = str(folder)
    moved = tmp_path.with_name(tmp_path.name + "-renamed-parent")
    try:
        authority.prepare_offline_writer_lock_source(fd, uid=uid, gid=gid)
        with pytest.raises(StateError, match="original offline directory pathname was replaced"):
            with authority._offline_writer_lock(
                    fd, uid=uid, gid=gid, path=original_path) as check:
                tmp_path.rename(moved)
                tmp_path.mkdir(mode=0o700)
                (tmp_path / folder.name).mkdir(mode=0o700)
                check()
        assert not (tmp_path / folder.name / authority.DIRECTORY_NAME).exists()
        assert (moved / folder.name / authority.LOCK_IDENTITY_NAME).is_file()
    finally:
        os.close(fd)


@pytest.mark.skipif(os.geteuid() != 0, reason="ephemeral protected inspection requires root")
def test_inspection_rejects_same_byte_marker_replacement_during_read(tmp_path, monkeypatch):
    """Pinned marker inode is a readback invariant, not just a stage invariant."""
    value=fixture()
    receipt=verify(value)
    folder,fd,uid,gid=_writer_root(tmp_path)
    try:
        authority.prepare_offline_writer_lock_source(fd,uid=uid,gid=gid)
        with authority._offline_writer_lock(fd,uid=uid,gid=gid,
                                            path=str(folder)) as check:
            authority._publish_bundle(fd,value["materials"],receipt,21001,
                                      verify_writer=check)
        marker=folder/authority.LOCK_IDENTITY_NAME
        original=marker.read_bytes()
        monkeypatch.setattr(authority,"_offline_root",
                            lambda _:os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
        monkeypatch.setattr(authority,"_observe_database",
                            lambda _:value["observed"])
        monkeypatch.setattr(authority,"RETAINED_CERTIFICATE_SIGNER_SHA256",
                            value["certificate_sha"])
        actual_raw=authority.raw
        touched=[]
        def substituted(fd,name,**kwargs):
            result=actual_raw(fd,name,**kwargs)
            if name=="operator-ed25519.pub" and not touched:
                touched.append(name)
                marker.rename(folder/"retained-original-marker")
                marker.write_bytes(original)
                marker.chmod(0o600)
            return result
        with monkeypatch.context() as patched:
            patched.setattr(authority,"raw",substituted)
            with pytest.raises(StateError,match="durable writer marker inode was replaced"):
                authority.inspect_offline(
                    offline_directory=str(folder),reader_gid=21001,
                    expected_operator_pin_sha256=value["operator_sha"],
                    expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
                    expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
                    expected_authorization_issuer=value["issuer"],now=NOW)
        assert touched==["operator-ed25519.pub"]
        assert marker.read_bytes()==original
        assert (folder/authority.DIRECTORY_NAME/authority.RECEIPT_NAME).read_bytes()==canonical(receipt)
    finally:
        os.close(fd)
