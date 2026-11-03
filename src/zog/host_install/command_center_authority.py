"""Protected offline adoption for the externally managed Command-Center.

This is deliberately separate from canonical host-install STATE. It never
calls state_inspect.inspect_live(), creates /state, formats a disk, installs a
live service, enables a socket, reads a credential, or signs operator policy.

The protected owner supplies an independently authenticated operator public
key fingerprint and already-signed authority material. This module verifies
the exact Command-Center/consumer separation and PR #9/#11 trust graph, then
publishes the same bytes under an existing inert root-private offline station
directory with durable no-replacement semantics.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import fcntl
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .state_contract import StateError, canonical, require
from .state_io import ensure_directory, publish, raw

SCHEMA = "zog-host-install-command-center-authority-offline-v1"
IDENTITY_SCHEMA = "zog-command-center-offline-installation-identity-v1"
IDENTITY_DOMAIN = (IDENTITY_SCHEMA + "\0").encode("ascii")
GRANT_SCHEMA = "zog-command-center-credential-authority-grant-v1"
GRANT_APPROVAL_SCHEMA = "zog-credential-delivery-operator-approval-v1"
GRANT_APPROVAL_DOMAIN = (GRANT_APPROVAL_SCHEMA + "\0").encode("ascii")
AUTHORIZATION_SCHEMA = "zog-credential-authorization-v1"
AUTHORIZATION_ENVELOPE_SCHEMA = "zog-credential-authorization-envelope-v1"
AUTHORIZATION_DOMAIN = (AUTHORIZATION_SCHEMA + "\0").encode("ascii")
ROLE_APPROVAL_SCHEMA = "zog-credential-v1-authority-signing-approval-v1"
ROLE_APPROVAL_DOMAIN = (ROLE_APPROVAL_SCHEMA + "\0").encode("ascii")
PROJECTION_SCHEMA = "zog-station-issuer-reader-authorization-v1"
PROJECTION_AUTH_SCHEMA = "zog-issuer-cloudflare-credential-v1"

PURPOSE = "issuer-cloudflare-dns01"
CONSUMER = "certify-manage"
DESTINATION = "issuer-dns-cloudflare"

COMMAND_CENTER_INSTANCE_ID = "i-0c676721165320da0"
RETAINED_CERTIFICATE_SIGNER_SHA256 = (
    "1ecf7d17bd8abc00ca50bde297f427b0fa28f2f6894b0a0cb71ae8d1237425cb"
)
STATION_ACCESS_COMMIT = "c2540cc5c9a3a0c1fff2748552819685ed2fdff4"
HOST_IDENTIFY_COMMIT = "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
HOST_DISCOVER_COMMIT = "ebe83775e9099fd406f6ad9213a42b25bade5b13"
COMPANION_HOST_INSTALL_COMMIT = "6e8b3792c6bc43e6b55dd254892105f7abea5a29"

DIRECTORY_NAME = "host-install-command-center-authority"
LOCK_NAME = ".host-install-command-center-authority.lock"
LOCK_IDENTITY_NAME = ".host-install-command-center-authority.lock-identity-v1.json"
LOCK_IDENTITY_SCHEMA = "zog-host-install-command-center-stable-writer-lock-v1"
RECEIPT_NAME = "receipt.json"

FILES = {
    "operator-ed25519.pub": (0o444, "root"),
    "command-center-offline-identity.json": (0o600, "root"),
    "aws-iid-evidence.json": (0o600, "root"),
    "certificate-assignment-signer-ed25519.pub": (0o444, "root"),
    "root-grant.json": (0o600, "root"),
    "root-grant-operator-approval.json": (0o600, "root"),
    "issuer-reader-projection.json": (0o440, "reader"),
    "credential-v1-authority-key.pem": (0o600, "root"),
    "credential-v1-authority-ed25519.pub": (0o444, "root"),
    "credential-v1-authorization.json": (0o600, "root"),
    "credential-v1-authority-approval.json": (0o600, "root"),
    RECEIPT_NAME: (0o600, "root"),
}

IDENTITY_FIELDS = frozenset((
    "schema", "station_role", "installation_mode", "state_mode",
    "command_center_host_id", "command_center_installation_id",
    "external_host_instance_id", "external_host_evidence_sha256",
    "station_registry_id", "station_source_commit",
    "database_path", "database_device", "database_inode",
    "database_owner_uid", "database_mode",
    "database_parent_device", "database_parent_inode",
    "enrolled_consumer_host_id", "enrolled_consumer_installation_id",
    "enrolled_consumer_state_volume_id", "certificate_signer_pin_sha256",
    "review_revision", "issued_at", "expires_at", "signature_ed25519",
))

GRANT_FIELDS = frozenset((
    "schema", "state", "purpose", "consumer", "destination", "host_id",
    "fingerprint", "installation_id", "state_volume_id", "authority_id",
    "registry_id", "assignment_id", "assignment_revision",
    "credential_revision", "authorization_id", "grant_id", "storage_id",
    "consumer_public_key", "consumer_key_fingerprint",
    "consumer_key_revision", "operator_approval_sha256",
    "independent_signer_pin_sha256", "revision", "expires_at",
))

PROJECTION_FIELDS = frozenset((
    "schema", "authorization", "origin", "installation_id", "host_id",
    "account_id", "owner_user_id",
))
PROJECTION_AUTH_FIELDS = frozenset((
    "schema", "state", "project", "certificate_id", "assignment_id",
    "assignment_revision", "credential_id", "credential_revision", "zone_id",
    "zone_name", "grant_id", "storage_id", "policy_sha256",
    "receipt_sha256", "expires_at",
))
AUTHORIZATION_FIELDS = frozenset((
    "schema", "issuer", "host_id", "host_fingerprint", "installation_id",
    "state_volume_id", "registry_id", "consumer", "purpose", "credential_id",
    "credential_revision", "authorization_id", "revision", "status",
    "approved_at", "revoked_at", "expires_at",
))
ROLE_APPROVAL_FIELDS = frozenset((
    "schema", "grant_sha256", "authorization_envelope_sha256",
    "authority_signer_sha256", "authorization_id", "revision", "expires_at",
    "signature_ed25519",
))

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "command-center-authority-json", "duplicate field")
        result[key] = value
    return result


def _json(raw_value: bytes, fields, schema: str):
    require(type(raw_value) is bytes and 0 < len(raw_value) <= 65536,
            "command-center-authority-json", schema)
    try:
        value = json.loads(
            raw_value, object_pairs_hook=_unique,
            parse_constant=lambda _: require(
                False, "command-center-authority-json", schema
            ),
        )
    except (ValueError, TypeError, UnicodeError) as exc:
        raise StateError("command-center-authority-json", schema) from exc
    require(type(value) is dict and set(value) == set(fields)
            and value.get("schema") == schema
            and canonical(value) == raw_value,
            "command-center-authority-json", schema)
    return value


def _uuid(value, code):
    require(type(value) is str, code, "UUID required")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise StateError(code, "invalid UUID") from exc
    require(str(parsed) == value and parsed.version in (4, 5),
            code, "canonical UUID required")
    return value


def _positive(value, code):
    require(type(value) is int and 1 <= value < 2**53,
            code, "positive integer required")
    return value


def _raw_public_key(data):
    require(type(data) is bytes and len(data) == 32,
            "command-center-authority-key", "raw Ed25519 public key required")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        return Ed25519PublicKey.from_public_bytes(data)
    except Exception as exc:
        raise StateError(
            "command-center-authority-key", "invalid Ed25519 public key"
        ) from exc


def _verify_signature(public_bytes, signature_b64, message, code):
    try:
        proof = base64.b64decode(signature_b64, validate=True)
        require(len(proof) == 64
                and base64.b64encode(proof).decode("ascii") == signature_b64,
                code, "non-canonical Ed25519 signature")
        _raw_public_key(public_bytes).verify(proof, message)
    except StateError:
        raise
    except Exception as exc:
        raise StateError(code, "Ed25519 signature verification failed") from exc


def _private_matches_public(private_pem, public_bytes):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(private_pem, password=None)
        require(isinstance(key, Ed25519PrivateKey),
                "command-center-authority-key", "Ed25519 private key required")
        actual = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        require(actual == public_bytes,
                "command-center-authority-key", "private/public signer mismatch")
    except StateError:
        raise
    except Exception as exc:
        raise StateError(
            "command-center-authority-key", "invalid private key"
        ) from exc


def _protected(path, *, mode, gid=0, maximum=65536):
    require(type(path) is str and path.startswith("/") and len(path) <= 512,
            "command-center-authority-path", "absolute protected path required")
    target = Path(path)
    try:
        for parent in reversed(target.parents):
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                    and not stat.S_IMODE(info.st_mode) & 0o022,
                    "command-center-authority-path", str(parent))
        before = os.lstat(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                    and info.st_gid == gid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == mode
                    and 0 < info.st_size <= maximum
                    and (before.st_dev, before.st_ino) == (info.st_dev, info.st_ino),
                    "command-center-authority-file", path)
            data = bytearray()
            while len(data) <= maximum:
                part = os.read(fd, min(8192, maximum + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            after = os.fstat(fd)
            current = os.lstat(path)
            require(len(data) == info.st_size and len(data) <= maximum
                    and (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    and (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                    "command-center-authority-file", "file changed during read")
            return bytes(data)
        finally:
            os.close(fd)
    except StateError:
        raise
    except OSError as exc:
        raise StateError("command-center-authority-file", path) from exc


def _observe_database(path):
    require(type(path) is str and path.startswith("/") and len(path) <= 512
            and Path(path).as_posix() == path and ".." not in Path(path).parts
            and path not in ("/", "/state"),
            "command-center-authority-database", "unsafe database path")
    try:
        target = Path(path)
        parent = target.parent
        for ancestor in reversed(parent.parents):
            info = ancestor.lstat()
            require(stat.S_ISDIR(info.st_mode)
                    and not stat.S_IMODE(info.st_mode) & 0o022,
                    "command-center-authority-database", str(ancestor))
        parent_info = parent.lstat()
        before = os.lstat(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISDIR(parent_info.st_mode)
                    and not stat.S_IMODE(parent_info.st_mode) & 0o022
                    and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and (before.st_dev, before.st_ino) == (info.st_dev, info.st_ino),
                    "command-center-authority-database", "unsafe database identity")
            return {
                "path": path,
                "device": info.st_dev,
                "inode": info.st_ino,
                "owner_uid": info.st_uid,
                "mode": stat.S_IMODE(info.st_mode),
                "parent_device": parent_info.st_dev,
                "parent_inode": parent_info.st_ino,
            }
        finally:
            os.close(fd)
    except StateError:
        raise
    except OSError as exc:
        raise StateError("command-center-authority-database", path) from exc


def _identity(raw_identity, operator_pin, certificate_pin, aws_evidence, *,
              expected_operator_pin_sha256,
              expected_certificate_signer_sha256,
              expected_instance_id, expected_station_source_commit,
              observed_database, now):
    require(expected_instance_id == COMMAND_CENTER_INSTANCE_ID
            and expected_station_source_commit == STATION_ACCESS_COMMIT,
            "command-center-authority-source",
            "unexpected protected bootstrap target")
    require(_HEX64.fullmatch(expected_operator_pin_sha256 or "") is not None
            and _digest(operator_pin) == expected_operator_pin_sha256,
            "command-center-authority-operator-pin",
            "independently expected operator pin mismatch")
    certificate_sha = _digest(certificate_pin)
    require(_HEX64.fullmatch(expected_certificate_signer_sha256 or "") is not None
            and certificate_sha == expected_certificate_signer_sha256
            and certificate_sha != expected_operator_pin_sha256,
            "command-center-authority-key-role",
            "certificate signer/operator role collision or unexpected signer")
    claim = _json(raw_identity, IDENTITY_FIELDS, IDENTITY_SCHEMA)
    require(claim["station_role"] == "command-center-host"
            and claim["installation_mode"] == "externally-managed"
            and claim["state_mode"] == "existing-station-application-database"
            and claim["external_host_instance_id"] == expected_instance_id
            and claim["station_source_commit"] == expected_station_source_commit
            and claim["external_host_evidence_sha256"] == _digest(aws_evidence)
            and claim["certificate_signer_pin_sha256"] == certificate_sha
            and type(claim["station_registry_id"]) is str
            and _TOKEN.fullmatch(claim["station_registry_id"]) is not None,
            "command-center-authority-identity", "identity binding mismatch")
    for key in (
        "command_center_host_id", "command_center_installation_id",
        "enrolled_consumer_host_id", "enrolled_consumer_installation_id",
        "enrolled_consumer_state_volume_id",
    ):
        _uuid(claim[key], "command-center-authority-identity")
    require(claim["command_center_host_id"] != claim["enrolled_consumer_host_id"]
            and claim["command_center_installation_id"]
                != claim["enrolled_consumer_installation_id"],
            "command-center-authority-identity",
            "consumer identity reused as Command-Center")
    for key in (
        "database_device", "database_inode", "database_owner_uid",
        "database_mode", "database_parent_device", "database_parent_inode",
        "review_revision", "issued_at", "expires_at",
    ):
        require(type(claim[key]) is int and claim[key] >= 0,
                "command-center-authority-identity", key)
    require(claim["database_inode"] > 0 and claim["database_parent_inode"] > 0
            and claim["review_revision"] >= 1
            and claim["issued_at"] <= now < claim["expires_at"]
            and claim["expires_at"] <= claim["issued_at"] + 30 * 86400
            and not claim["database_mode"] & 0o7022,
            "command-center-authority-identity",
            "invalid review lifetime or database mode")
    for observed_key, claim_key in (
        ("path", "database_path"), ("device", "database_device"),
        ("inode", "database_inode"), ("owner_uid", "database_owner_uid"),
        ("mode", "database_mode"), ("parent_device", "database_parent_device"),
        ("parent_inode", "database_parent_inode"),
    ):
        require(observed_database.get(observed_key) == claim[claim_key],
                "command-center-authority-identity", "database identity changed")
    unsigned = dict(claim)
    signature = unsigned.pop("signature_ed25519")
    _verify_signature(
        operator_pin, signature, IDENTITY_DOMAIN + canonical(unsigned),
        "command-center-authority-identity-signature",
    )
    return claim


def _projection(raw_projection, grant, now):
    projection = _json(raw_projection, PROJECTION_FIELDS, PROJECTION_SCHEMA)
    auth = projection["authorization"]
    require(type(auth) is dict and set(auth) == set(PROJECTION_AUTH_FIELDS)
            and auth.get("schema") == PROJECTION_AUTH_SCHEMA
            and auth.get("state") == "approved"
            and projection["origin"] == "managed"
            and projection["host_id"] == grant["host_id"]
            and projection["installation_id"] == grant["installation_id"]
            and auth["assignment_id"] == grant["assignment_id"]
            and auth["assignment_revision"] == grant["assignment_revision"]
            and auth["credential_revision"] == grant["credential_revision"]
            and auth["grant_id"] == grant["grant_id"]
            and auth["storage_id"] == grant["storage_id"]
            and type(auth["expires_at"]) is int
            and auth["expires_at"] >= grant["expires_at"]
            and auth["expires_at"] > now,
            "command-center-authority-projection",
            "issuer-reader projection mismatch")
    require(_digest(canonical(auth)) == grant["authorization_id"],
            "command-center-authority-projection",
            "authorization digest mismatch")
    _uuid(auth["credential_id"], "command-center-authority-projection")
    return projection


def _grant(raw_grant, raw_approval, raw_projection, operator_pin,
           certificate_pin, identity, now):
    grant = _json(raw_grant, GRANT_FIELDS, GRANT_SCHEMA)
    require(grant["state"] == "approved" and grant["purpose"] == PURPOSE
            and grant["consumer"] == CONSUMER
            and grant["destination"] == DESTINATION
            and grant["host_id"] == identity["enrolled_consumer_host_id"]
            and grant["installation_id"]
                == identity["enrolled_consumer_installation_id"]
            and grant["state_volume_id"]
                == identity["enrolled_consumer_state_volume_id"]
            # Both identities are operator-signed independently. They must
            # select one exact registry; syntax validation alone permits
            # cross-registry authority substitution.
            and grant["registry_id"] == identity["station_registry_id"]
            and grant["independent_signer_pin_sha256"]
                == _digest(certificate_pin)
            and type(grant["registry_id"]) is str
            and _TOKEN.fullmatch(grant["registry_id"]) is not None
            and type(grant["fingerprint"]) is str
            and _HEX64.fullmatch(grant["fingerprint"]) is not None
            and type(grant["authorization_id"]) is str
            and _HEX64.fullmatch(grant["authorization_id"]) is not None
            and type(grant["grant_id"]) is str
            and _HEX32.fullmatch(grant["grant_id"]) is not None
            and type(grant["storage_id"]) is str
            and _HEX32.fullmatch(grant["storage_id"]) is not None
            and type(grant["expires_at"]) is int and grant["expires_at"] > now,
            "command-center-authority-grant", "root grant binding mismatch")
    for key in ("host_id", "installation_id", "state_volume_id", "assignment_id"):
        _uuid(grant[key], "command-center-authority-grant")
    for key in (
        "revision", "assignment_revision", "credential_revision",
        "consumer_key_revision",
    ):
        _positive(grant[key], "command-center-authority-grant")
    try:
        consumer_key = base64.b64decode(grant["consumer_public_key"], validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise StateError(
            "command-center-authority-grant", "invalid consumer key"
        ) from exc
    require(len(consumer_key) == 32
            and base64.b64encode(consumer_key).decode("ascii")
                == grant["consumer_public_key"]
            and _digest(consumer_key) == grant["consumer_key_fingerprint"],
            "command-center-authority-grant",
            "consumer key fingerprint mismatch")
    approval = _json(
        raw_approval,
        {"schema", "grant_sha256", "signature_ed25519"},
        GRANT_APPROVAL_SCHEMA,
    )
    packet = dict(grant)
    packet.pop("operator_approval_sha256")
    require(approval["grant_sha256"] == _digest(canonical(packet))
            and _digest(raw_approval) == grant["operator_approval_sha256"],
            "command-center-authority-grant-approval",
            "operator approval digest mismatch")
    _verify_signature(
        operator_pin, approval["signature_ed25519"],
        GRANT_APPROVAL_DOMAIN + canonical(packet),
        "command-center-authority-grant-approval",
    )
    projection = _projection(raw_projection, grant, now)
    return grant, projection


def _authorization(raw_envelope, authority_pin, grant, projection,
                   expected_issuer, now):
    envelope = _json(
        raw_envelope,
        {"schema", "key_id", "authorization", "signature"},
        AUTHORIZATION_ENVELOPE_SCHEMA,
    )
    authority_sha = _digest(authority_pin)
    require(envelope["key_id"] == authority_sha,
            "command-center-authority-authorization",
            "authority key id mismatch")
    authorization = envelope["authorization"]
    require(type(authorization) is dict
            and set(authorization) == set(AUTHORIZATION_FIELDS)
            and authorization.get("schema") == AUTHORIZATION_SCHEMA
            and authorization.get("issuer") == expected_issuer
            and authorization.get("host_id") == grant["host_id"]
            and authorization.get("host_fingerprint") == grant["fingerprint"]
            and authorization.get("installation_id") == grant["installation_id"]
            and authorization.get("state_volume_id") == grant["state_volume_id"]
            and authorization.get("registry_id") == grant["registry_id"]
            and authorization.get("consumer") == CONSUMER
            and authorization.get("purpose") == PURPOSE,
            "command-center-authority-authorization",
            "authorization binding mismatch")
    credential_id = (
        "cloudflare-" + projection["authorization"]["credential_id"].replace("-", "")
    )
    require(authorization["credential_id"] == credential_id
            and authorization["credential_revision"] == grant["credential_revision"]
            and authorization["revision"] == grant["revision"]
            and authorization["status"] == grant["state"]
            and type(authorization["approved_at"]) is int
            and authorization["approved_at"] <= now
            and authorization["revoked_at"] is None
            and type(authorization["expires_at"]) is int
            and now < authorization["expires_at"] <= grant["expires_at"]
            and authorization["expires_at"] - authorization["approved_at"]
                <= 7 * 86400,
            "command-center-authority-authorization",
            "authorization lifetime/revision mismatch")
    _uuid(
        authorization["authorization_id"],
        "command-center-authority-authorization",
    )
    _verify_signature(
        authority_pin, envelope["signature"],
        AUTHORIZATION_DOMAIN + canonical(authorization),
        "command-center-authority-authorization",
    )
    return authorization


def _role_approval(raw_approval, operator_pin, grant, raw_envelope,
                   authority_pin, authorization, now):
    approval = _json(raw_approval, ROLE_APPROVAL_FIELDS, ROLE_APPROVAL_SCHEMA)
    require(approval["grant_sha256"] == _digest(canonical(grant))
            and approval["authorization_envelope_sha256"]
                == _digest(raw_envelope)
            and approval["authority_signer_sha256"] == _digest(authority_pin)
            and approval["authorization_id"]
                == authorization["authorization_id"]
            and approval["revision"] == authorization["revision"]
            and type(approval["expires_at"]) is int
            and authorization["expires_at"]
                <= approval["expires_at"] <= grant["expires_at"]
            and approval["expires_at"] > now,
            "command-center-authority-role-approval",
            "role approval binding mismatch")
    unsigned = dict(approval)
    proof = unsigned.pop("signature_ed25519")
    _verify_signature(
        operator_pin, proof, ROLE_APPROVAL_DOMAIN + canonical(unsigned),
        "command-center-authority-role-approval",
    )
    return approval


def verify_materials(materials, *, expected_operator_pin_sha256,
                     expected_certificate_signer_sha256,
                     expected_instance_id, expected_station_source_commit,
                     expected_authorization_issuer, observed_database, now=None):
    """Verify all non-live authority inputs; return only a secret-free receipt."""
    now = int(time.time()) if now is None else now
    require(type(materials) is dict and set(materials) == {
        "operator_pin", "identity", "aws_evidence", "certificate_pin",
        "grant", "grant_approval", "projection", "authority_private_key",
        "authority_pin", "authorization", "authority_approval",
    }, "command-center-authority-inputs", "unexpected material set")
    require(all(type(value) is bytes for value in materials.values()),
            "command-center-authority-inputs", "all materials must be bytes")
    operator_pin = materials["operator_pin"]
    certificate_pin = materials["certificate_pin"]
    authority_pin = materials["authority_pin"]
    require(len(operator_pin) == len(certificate_pin) == len(authority_pin) == 32,
            "command-center-authority-key",
            "all public pins must be raw Ed25519")
    operator_sha, certificate_sha, authority_sha = (
        _digest(operator_pin), _digest(certificate_pin), _digest(authority_pin)
    )
    require(len({operator_sha, certificate_sha, authority_sha}) == 3,
            "command-center-authority-key-role",
            "three distinct signing roles required")
    _private_matches_public(materials["authority_private_key"], authority_pin)
    identity = _identity(
        materials["identity"], operator_pin, certificate_pin,
        materials["aws_evidence"],
        expected_operator_pin_sha256=expected_operator_pin_sha256,
        expected_certificate_signer_sha256=expected_certificate_signer_sha256,
        expected_instance_id=expected_instance_id,
        expected_station_source_commit=expected_station_source_commit,
        observed_database=observed_database, now=now,
    )
    grant, projection = _grant(
        materials["grant"], materials["grant_approval"],
        materials["projection"], operator_pin, certificate_pin, identity, now,
    )
    authorization = _authorization(
        materials["authorization"], authority_pin, grant, projection,
        expected_authorization_issuer, now,
    )
    role = _role_approval(
        materials["authority_approval"], operator_pin, grant,
        materials["authorization"], authority_pin, authorization, now,
    )
    return {
        "schema": SCHEMA,
        "status": "protected-offline-authority-materials-verified",
        "command_center_host_id": identity["command_center_host_id"],
        "command_center_installation_id":
            identity["command_center_installation_id"],
        "external_host_instance_id": identity["external_host_instance_id"],
        "station_registry_id": identity["station_registry_id"],
        "station_source_commit": identity["station_source_commit"],
        "database_path": identity["database_path"],
        "database_device": identity["database_device"],
        "database_inode": identity["database_inode"],
        "enrolled_consumer_host_id": grant["host_id"],
        "enrolled_consumer_installation_id": grant["installation_id"],
        "enrolled_consumer_state_volume_id": grant["state_volume_id"],
        "operator_pin_sha256": operator_sha,
        "certificate_signer_pin_sha256": certificate_sha,
        "credential_authority_pin_sha256": authority_sha,
        "signed_identity_sha256": _digest(materials["identity"]),
        "external_host_evidence_sha256": _digest(materials["aws_evidence"]),
        "root_grant_sha256": _digest(materials["grant"]),
        "root_grant_operator_approval_sha256":
            _digest(materials["grant_approval"]),
        "issuer_reader_projection_sha256": _digest(materials["projection"]),
        "authorization_envelope_sha256": _digest(materials["authorization"]),
        "authority_role_approval_sha256":
            _digest(materials["authority_approval"]),
        "grant_revision": grant["revision"],
        "grant_expires_at": grant["expires_at"],
        "authorization_id": authorization["authorization_id"],
        "authorization_revision": authorization["revision"],
        "authorization_expires_at": authorization["expires_at"],
        "authority_approval_expires_at": role["expires_at"],
        "source_closure": {
            "station_access": STATION_ACCESS_COMMIT,
            "host_identify": HOST_IDENTIFY_COMMIT,
            "host_discover": HOST_DISCOVER_COMMIT,
            "host_install_companion": COMPANION_HOST_INSTALL_COMMIT,
        },
        "canonical_host_install_state_verified": False,
        "canonical_host_install_state_created": False,
        "aws_iid_cryptographically_verified_by_this_module": False,
        "operator_pin_origin_authenticated_by_this_module": False,
        "offline_materials_only": True,
        "production_activation_authorized": False,
        "credential_delivery_authorized": False,
        "credential_transferred": False,
    }


def _offline_root(path):
    require(os.geteuid() == 0 and type(path) is str
            and path.startswith("/opt/station-trust/")
            and Path(path).name.endswith("-offline")
            and Path(path).as_posix() == path
            and ".." not in Path(path).parts and len(path) <= 300,
            "command-center-authority-offline-root",
            "approved offline path required")
    try:
        for parent in reversed(Path(path).parents):
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                    and not stat.S_IMODE(info.st_mode) & 0o022,
                    "command-center-authority-offline-root", str(parent))
        fd = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        info = os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                "command-center-authority-offline-root",
                "root:root 0700 required")
        return fd
    except StateError:
        raise
    except OSError as exc:
        raise StateError(
            "command-center-authority-offline-root", path
        ) from exc


def _read_inputs(paths, reader_gid):
    expected = {
        "operator_pin": (0o444, 0, 32),
        "identity": (0o600, 0, 8192),
        "aws_evidence": (0o600, 0, 65536),
        "certificate_pin": (0o444, 0, 32),
        "grant": (0o600, 0, 16384),
        "grant_approval": (0o600, 0, 8192),
        "projection": (0o440, reader_gid, 16384),
        "authority_private_key": (0o600, 0, 8192),
        "authority_pin": (0o444, 0, 32),
        "authorization": (0o600, 0, 16384),
        "authority_approval": (0o600, 0, 8192),
    }
    require(type(paths) is dict and set(paths) == set(expected),
            "command-center-authority-inputs",
            "missing protected material")
    return {
        name: _protected(paths[name], mode=mode, gid=gid, maximum=maximum)
        for name, (mode, gid, maximum) in expected.items()
    }




def _writer_root_shape(root_fd, uid, gid):
    info = os.fstat(root_fd)
    require(stat.S_ISDIR(info.st_mode)
            and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                == (uid, gid, 0o700),
            "command-center-authority-writer-root",
            "protected writer directory must be owned and 0700")
    return info


def _writer_identity(root_fd, handle, uid, gid):
    folder = _writer_root_shape(root_fd, uid, gid)
    held = os.fstat(handle)
    require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1
            and (held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode))
                == (uid, gid, 0o600),
            "command-center-authority-writer-lock",
            "protected lock identity or permissions changed")
    try:
        named = os.stat(LOCK_NAME, dir_fd=root_fd,
                        follow_symlinks=False)
    except OSError as exc:
        raise StateError("command-center-authority-writer-lock",
                         "original lock pathname disappeared") from exc
    require((named.st_dev, named.st_ino) ==
            (held.st_dev, held.st_ino),
            "command-center-authority-writer-lock",
            "writer lock pathname was replaced")
    expected = canonical({
        "schema": LOCK_IDENTITY_SCHEMA,
        "root_device": folder.st_dev,
        "root_inode": folder.st_ino,
        "lock_device": held.st_dev,
        "lock_inode": held.st_ino,
    })
    marker = raw(root_fd, LOCK_IDENTITY_NAME,
                 uid=uid, gid=gid, mode=0o600)
    require(marker == expected,
            "command-center-authority-writer-lock",
            "durable lock identity missing, stale or substituted")
    return expected


def prepare_offline_writer_lock_source(root_fd, *, uid, gid,
                                       checkpoint=lambda _: None):
    """Synthetic owner bootstrap; NOT called by stage_offline.

    Real 0700 root writer and inode marker require a separately authorized
    native bootstrap. An interrupted initial bootstrap is a HOLD, never
    silently reinitialized or repaired by staging/inspection. The trusted
    directory inode is the second serialization fence during bootstrap.
    """
    _writer_root_shape(root_fd, uid, gid)
    fcntl.flock(root_fd, fcntl.LOCK_EX)
    try:
        existing = set(os.listdir(root_fd))
        if LOCK_NAME in existing or LOCK_IDENTITY_NAME in existing:
            require({LOCK_NAME, LOCK_IDENTITY_NAME} <= existing,
                    "command-center-authority-writer-lock",
                    "partial first writer bootstrap")
            handle = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=root_fd)
            try:
                _writer_identity(root_fd, handle, uid, gid)
                return
            finally:
                os.close(handle)
        require(not existing,
                "command-center-authority-writer-lock",
                "first writer bootstrap requires an empty protected root")
        handle = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root_fd)
        try:
            os.fchown(handle, uid, gid)
            os.fchmod(handle, 0o600)
            os.fsync(handle)
            os.fsync(root_fd)
            checkpoint("writer-created")
            folder = os.fstat(root_fd)
            leaf = os.fstat(handle)
            publish(root_fd, LOCK_IDENTITY_NAME, canonical({
                "schema": LOCK_IDENTITY_SCHEMA,
                "root_device": folder.st_dev,
                "root_inode": folder.st_ino,
                "lock_device": leaf.st_dev,
                "lock_inode": leaf.st_ino,
            }), mode=0o600, uid=uid, gid=gid)
            _writer_identity(root_fd, handle, uid, gid)
        finally:
            os.close(handle)
    finally:
        fcntl.flock(root_fd, fcntl.LOCK_UN)


def _writer_root_path_identity(root_fd, path):
    """The configured pathname must still resolve to the held root inode.

    A directory can be renamed while its flock is held. Without this check
    a replacement directory could be independently bootstrapped at the same
    pathname, giving two writers different *directory* lock objects.
    """
    require(type(path) is str and path.startswith("/"),
            "command-center-authority-writer-root", "absolute offline root required")
    try:
        named = os.lstat(path)
        held = os.fstat(root_fd)
    except OSError as exc:
        raise StateError("command-center-authority-writer-root",
                         "original offline pathname disappeared") from exc
    require(stat.S_ISDIR(named.st_mode)
            and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino),
            "command-center-authority-writer-root",
            "original offline directory pathname was replaced")


def _writer_ancestor_identities(path):
    """Bind each original protected ancestor, not just the final leaf inode.

    A renamed parent replaced with a symlink pointing at the same opened
    offline root would pass a final-leaf st_dev/st_ino comparison. Preserve
    the namespace identity of each original ancestor throughout stage
    and inspect. _offline_root independently validates their owner and DAC.
    """
    try:
        entries = []
        for parent in reversed(Path(path).parents):
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode),
                    "command-center-authority-writer-root",
                    "original offline ancestor is not a directory")
            entries.append((str(parent), info.st_dev, info.st_ino))
        return tuple(entries)
    except OSError as exc:
        raise StateError("command-center-authority-writer-root",
                         "original offline ancestor pathname disappeared") from exc


def _writer_marker_inode(root_fd, marker_fd, uid, gid):
    held = os.fstat(marker_fd)
    try:
        named = os.stat(LOCK_IDENTITY_NAME, dir_fd=root_fd,
                        follow_symlinks=False)
    except OSError as exc:
        raise StateError("command-center-authority-writer-lock",
                         "durable writer marker disappeared") from exc
    require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1
            and (held.st_uid, held.st_gid, stat.S_IMODE(held.st_mode))
                == (uid, gid, 0o600)
            and (named.st_dev, named.st_ino) == (held.st_dev, held.st_ino),
            "command-center-authority-writer-lock",
            "durable writer marker inode was replaced")


@contextmanager
def _offline_writer_lock(root_fd, *, uid=0, gid=0, path=None):
    """Hold original root DIRECTORY flock plus persisted exact lock inode.

    If path is supplied by stage/inspect, also bind the configured directory
    namespace entry. A same-byte marker replacement *during* this operation
    is not accepted, even though its contents still describe the original
    lock inode. Neither stage nor inspect creates a new lock or marker.
    """
    _writer_root_shape(root_fd, uid, gid)
    fcntl.flock(root_fd, fcntl.LOCK_EX)
    handle = None
    marker_fd = None
    original_ancestors = None
    try:
        if path is not None:
            _writer_root_path_identity(root_fd, path)
            original_ancestors = _writer_ancestor_identities(path)
        try:
            handle = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=root_fd)
            marker_fd = os.open(LOCK_IDENTITY_NAME,
                                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=root_fd)
        except OSError as exc:
            raise StateError("command-center-authority-writer-lock",
                             "durable lock identity missing or independently provisioned lock absent") from exc
        original = _writer_identity(root_fd, handle, uid, gid)
        fcntl.flock(handle, fcntl.LOCK_EX)
        def check(*_):
            if path is not None:
                _writer_root_path_identity(root_fd, path)
                require(_writer_ancestor_identities(path) == original_ancestors,
                        "command-center-authority-writer-root",
                        "original offline ancestor pathname was replaced")
            _writer_marker_inode(root_fd, marker_fd, uid, gid)
            require(_writer_identity(root_fd, handle, uid, gid) == original,
                    "command-center-authority-writer-lock",
                    "protected writer identity changed during publication")
        check()
        yield check
        check()
    finally:
        if marker_fd is not None:
            os.close(marker_fd)
        if handle is not None:
            os.close(handle)
        fcntl.flock(root_fd, fcntl.LOCK_UN)

def _assert_original_child(root_fd, child_fd):
    """The public offline subdirectory name must retain the opened inode."""
    child = os.fstat(child_fd)
    try:
        named = os.stat(DIRECTORY_NAME, dir_fd=root_fd,
                        follow_symlinks=False)
    except OSError as exc:
        raise StateError("command-center-authority-publication",
                         "authority subdirectory pathname missing") from exc
    require(stat.S_ISDIR(child.st_mode) and
            (child.st_dev, child.st_ino) == (named.st_dev, named.st_ino),
            "command-center-authority-publication",
            "authority subdirectory pathname was replaced")
    # Publication and inspection readback require the same root-only
    # 0700 namespace protection for the *entire* operation. Checking mode
    # only at opening would allow mid-operation permission relaxation.
    require((child.st_uid, child.st_gid, stat.S_IMODE(child.st_mode))
                == (0, 0, 0o700)
            and child.st_dev == os.fstat(root_fd).st_dev,
            "command-center-authority-publication",
            "protected authority subdirectory ownership or mode changed")


def _publish_bundle(root_fd, materials, receipt, reader_gid, *,
                    verify_writer=lambda *_: None):
    verify_writer()
    child = ensure_directory(root_fd, DIRECTORY_NAME, 0, 0, 0o700,
                             checkpoint=verify_writer)
    verify_writer()
    def check_child(*event):
        verify_writer(*event)
        _assert_original_child(root_fd, child)
    try:
        check_child()
        allowed = set(FILES) | {".pending." + name for name in FILES}
        present = set(os.listdir(child))
        require(present <= allowed,
                "command-center-authority-publication",
                "unrecognized file in protected authority directory")
        # Receipt publication is the *last* file. Once a receipt exists
        # (or its publication has started), all other material files must
        # already be complete. Reject malformed/partial receipt states
        # before creating or modifying any missing material. The legitimate
        # two-link .pending.receipt state remains resumable.
        if RECEIPT_NAME in present or ".pending." + RECEIPT_NAME in present:
            require(present - {RECEIPT_NAME, ".pending." + RECEIPT_NAME}
                    == set(FILES) - {RECEIPT_NAME},
                    "command-center-authority-publication",
                    "receipt present before complete authority bundle")
        rows = {
            "operator-ed25519.pub": materials["operator_pin"],
            "command-center-offline-identity.json": materials["identity"],
            "aws-iid-evidence.json": materials["aws_evidence"],
            "certificate-assignment-signer-ed25519.pub":
                materials["certificate_pin"],
            "root-grant.json": materials["grant"],
            "root-grant-operator-approval.json": materials["grant_approval"],
            "issuer-reader-projection.json": materials["projection"],
            "credential-v1-authority-key.pem":
                materials["authority_private_key"],
            "credential-v1-authority-ed25519.pub":
                materials["authority_pin"],
            "credential-v1-authorization.json": materials["authorization"],
            "credential-v1-authority-approval.json":
                materials["authority_approval"],
        }
        for name, data in rows.items():
            check_child()
            mode, role = FILES[name]
            publish(
                child, name, data, mode=mode, uid=0,
                gid=reader_gid if role == "reader" else 0,
                checkpoint=check_child,
            )
            check_child()
        check_child()
        publish(
            child, RECEIPT_NAME, canonical(receipt),
            mode=0o600, uid=0, gid=0,
            checkpoint=check_child,
        )
        check_child()
        require(set(os.listdir(child)) == set(FILES),
                "command-center-authority-publication",
                "incomplete protected authority publication")
        os.fsync(child)
        check_child()
    finally:
        os.close(child)


def stage_offline(*, offline_directory, paths, reader_gid,
                  expected_operator_pin_sha256,
                  expected_instance_id, expected_station_source_commit,
                  expected_authorization_issuer, now=None):
    """Verify then durably publish under the inert offline tree."""
    require(os.geteuid() == 0 and type(reader_gid) is int and reader_gid > 0,
            "command-center-authority-owner",
            "root and positive reader GID required")
    materials = _read_inputs(paths, reader_gid)
    identity_value = _json(
        materials["identity"], IDENTITY_FIELDS, IDENTITY_SCHEMA
    )
    observed = _observe_database(identity_value["database_path"])
    receipt = verify_materials(
        materials,
        expected_operator_pin_sha256=expected_operator_pin_sha256,
        expected_certificate_signer_sha256=
            RETAINED_CERTIFICATE_SIGNER_SHA256,
        expected_instance_id=expected_instance_id,
        expected_station_source_commit=expected_station_source_commit,
        expected_authorization_issuer=expected_authorization_issuer,
        observed_database=observed, now=now,
    )
    root_fd = _offline_root(offline_directory)
    try:
        with _offline_writer_lock(root_fd, path=offline_directory) as verify_writer:
            # The station database is an identity input, not mutable source
            # authority. A replacement between validation and durable
            # publication must not be accepted even if all signed material
            # still verifies against the earlier observation.
            require(_observe_database(identity_value["database_path"]) == observed,
                    "command-center-authority-database",
                    "database identity changed before offline publication")
            _publish_bundle(root_fd, materials, receipt, reader_gid,
                            verify_writer=verify_writer)
            # An interruption after a durable receipt can leave inert staged
            # files. Never *report* a successful adoption of a replaced DB.
            # A subsequent inspect performs this readback again.
            require(_observe_database(identity_value["database_path"]) == observed,
                    "command-center-authority-database",
                    "database identity changed during offline publication")
    finally:
        os.close(root_fd)
    return {
        **receipt,
        "offline_directory": offline_directory + "/" + DIRECTORY_NAME,
        "same_byte_resume_supported": True,
    }


def inspect_offline(*, offline_directory, reader_gid,
                    expected_operator_pin_sha256,
                    expected_instance_id, expected_station_source_commit,
                    expected_authorization_issuer, now=None):
    """Read back staged bytes and re-run every source-level trust check."""
    require(os.geteuid() == 0 and type(reader_gid) is int and reader_gid > 0,
            "command-center-authority-owner",
            "root and positive reader GID required")
    root_fd = _offline_root(offline_directory)
    child = None
    try:
        with _offline_writer_lock(root_fd, path=offline_directory) as verify_writer:
            child = os.open(
                DIRECTORY_NAME, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            _assert_original_child(root_fd, child)
            info = os.fstat(child)
            require(info.st_uid == 0 and info.st_gid == 0
                    and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_dev == os.fstat(root_fd).st_dev
                    and set(os.listdir(child)) == set(FILES),
                    "command-center-authority-publication",
                    "unsafe staged directory")

            def get(name):
                # Inspect the original selected child, never a detached
                # directory whose no-replacement receipt is no longer at the
                # publicly configured name. Check before AND after each read.
                verify_writer()
                _assert_original_child(root_fd, child)
                mode, role = FILES[name]
                data = raw(
                    child, name, uid=0,
                    gid=reader_gid if role == "reader" else 0,
                    mode=mode,
                )
                verify_writer()
                _assert_original_child(root_fd, child)
                require(data is not None,
                        "command-center-authority-publication", name)
                return data

            materials = {
                "operator_pin": get("operator-ed25519.pub"),
                "identity": get("command-center-offline-identity.json"),
                "aws_evidence": get("aws-iid-evidence.json"),
                "certificate_pin":
                    get("certificate-assignment-signer-ed25519.pub"),
                "grant": get("root-grant.json"),
                "grant_approval": get("root-grant-operator-approval.json"),
                "projection": get("issuer-reader-projection.json"),
                "authority_private_key":
                    get("credential-v1-authority-key.pem"),
                "authority_pin": get("credential-v1-authority-ed25519.pub"),
                "authorization": get("credential-v1-authorization.json"),
                "authority_approval":
                    get("credential-v1-authority-approval.json"),
            }
            identity_value = _json(
                materials["identity"], IDENTITY_FIELDS, IDENTITY_SCHEMA
            )
            observed = _observe_database(identity_value["database_path"])
            receipt = verify_materials(
                materials,
                expected_operator_pin_sha256=expected_operator_pin_sha256,
                expected_certificate_signer_sha256=
                    RETAINED_CERTIFICATE_SIGNER_SHA256,
                expected_instance_id=expected_instance_id,
                expected_station_source_commit=expected_station_source_commit,
                expected_authorization_issuer=expected_authorization_issuer,
                observed_database=observed, now=now,
            )
            require(get(RECEIPT_NAME) == canonical(receipt),
                    "command-center-authority-publication",
                    "receipt/content mismatch")
            verify_writer()
            _assert_original_child(root_fd, child)
            return {
                **receipt,
                "status": "protected-offline-authority-materials-retained",
                "offline_directory": offline_directory + "/" + DIRECTORY_NAME,
                "same_byte_resume_supported": True,
            }
    finally:
        if child is not None:
            os.close(child)
        os.close(root_fd)
