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


def fixture():
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
        "station_registry_id": "primary",
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
        "registry_id": "primary",
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
        "registry_id": "primary",
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


def test_three_signing_roles_must_remain_distinct():
    value = fixture()
    value["materials"]["authority_pin"] = value["materials"]["operator_pin"]
    with pytest.raises(StateError, match="three distinct"):
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
