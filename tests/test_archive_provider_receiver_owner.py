"""Offline signed archive receiver source tests using pinned canonical protocol."""
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from zog.host_identify import archive_credentials as ac
from zog.host_identify import credential_delivery as cd
from zog.host_identify import signatures
from zog.host_install.archive_provider_receiver import OfflineArchiveReceiver, ReceiverHold

URL = "https://registry.example.invalid/.well-known/zog/credential-delivery/v1"
ISSUER = "https://registry.example.invalid"


def context(tmp_path):
    path = tmp_path / "owner"
    path.mkdir(mode=0o700)
    (path / "archive-provider.lock").write_bytes(b"")
    (path / "archive-provider.lock").chmod(0o600)
    host_key = Ed25519PrivateKey.generate()
    authority_key = Ed25519PrivateKey.generate()
    scope = {
        "schema": ac.PROVIDER_SCOPE_SCHEMA,
        "host_id": str(uuid.uuid4()),
        "host_fingerprint": signatures.fingerprint(host_key.public_key()),
        "installation_id": str(uuid.uuid4()),
        "state_volume_id": str(uuid.uuid4()),
        "registry_id": "registry-a",
        "provider_id": "upstream-a",
        "provider_origin": "https://upstream.example.invalid",
        "provider_role": ac.PROVIDER_ROLE,
        "role_revision": 4,
        "collections": ["sources"],
        "operations": ["fetch"],
        "provider_credential_id": "upstream-token",
        "credential_revision": 7,
    }
    return path, scope, host_key, authority_key


def signed_authorization(scope, key, now, *, status="approved", revision=3):
    authorization = {
        "schema": cd.AUTHORIZATION_SCHEMA,
        "issuer": ISSUER,
        **ac.provider_binding(scope),
        "credential_revision": scope["credential_revision"],
        "authorization_id": str(uuid.uuid4()),
        "revision": revision,
        "status": status,
        "approved_at": now - 10,
        "revoked_at": now if status == "revoked" else None,
        "expires_at": now + 3600,
    }
    return authorization, cd.sign_authorization(authorization, key)


def request(scope, authorization, host_key, now):
    value = {
        "schema": cd.REQUEST_SCHEMA,
        **ac.provider_binding(scope),
        "credential_revision": scope["credential_revision"],
        "authorization_id": authorization["authorization_id"],
        "authorization_revision": authorization["revision"],
        "request_id": str(uuid.uuid4()),
        "action": "deliver",
        "previous_delivery_id": None,
        "created_at": now - 1,
        "expires_at": now + 60,
    }
    cd.validate_request(value, authorization, now=now)
    msg = signatures.sign(URL, cd.canonical(value), host_key, value["host_id"],
                          now=datetime.fromtimestamp(now, timezone.utc),
                          nonce="K" * 24)
    return value, msg


def fixtures(tmp_path):
    path, scope, host, authority = context(tmp_path)
    now = int(time.time())
    a, envelope = signed_authorization(scope, authority, now)
    req, msg = request(scope, a, host, now)
    receiver = OfflineArchiveReceiver(path, enabled=True)
    args = {
        "scope": scope, "expected_scope": copy.deepcopy(scope),
        "signed_authorization": envelope,
        "authority_public_key": authority.public_key(),
        "expected_issuer": ISSUER, "url": URL, "method": "POST",
        "headers": dict(msg.headers), "body": msg.body,
        "host_public_key": host.public_key(), "now": now,
    }
    return path, receiver, args, a, authority, req


def test_disabled_and_signed_claim_persists_no_secrets(tmp_path):
    path, receiver, args, _, _, request_value = fixtures(tmp_path)
    with pytest.raises(ReceiverHold, match="disabled"):
        OfflineArchiveReceiver(path).claim(**args)
    assert receiver.claim(**args)["status"] == "claimed"
    stored = (path / "archive-provider-ledger.json").read_text()
    assert request_value["request_id"] in stored
    assert "secret" not in stored
    assert (path / "archive-provider-ledger.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ReceiverHold, match="incomplete"):
        OfflineArchiveReceiver(path, enabled=True).claim(**args)


@pytest.mark.parametrize("field,replacement", [
    ("host_id", lambda: str(uuid.uuid4())),
    ("installation_id", lambda: str(uuid.uuid4())),
    ("state_volume_id", lambda: str(uuid.uuid4())),
    ("registry_id", lambda: "wrong-registry"),
    ("provider_origin", lambda: "https://bad.example.invalid"),
    ("role_revision", lambda: 5),
    ("collections", lambda: ["unselected"]),
    ("provider_role", lambda: "issuer"),
    ("credential_revision", lambda: 8),
])
def test_destination_mismatch_denied(tmp_path, field, replacement):
    path, receiver, args, *_ = fixtures(tmp_path)
    args["expected_scope"][field] = replacement()
    with pytest.raises((ReceiverHold, ac.ArchiveCredentialPolicyError)):
        receiver.claim(**args)
    assert not (path / "archive-provider-ledger.json").exists()


def test_wrong_authority_tamper_wrong_http_signature_denied(tmp_path):
    path, receiver, args, *_ = fixtures(tmp_path)
    altered = dict(args)
    altered["authority_public_key"] = Ed25519PrivateKey.generate().public_key()
    with pytest.raises((ValueError, ReceiverHold)):
        receiver.claim(**altered)
    altered = dict(args)
    altered["body"] = bytes(args["body"]) + b" "
    with pytest.raises((ValueError, ReceiverHold)):
        receiver.claim(**altered)
    assert not (path / "archive-provider-ledger.json").exists()


def test_one_time_delivery_and_restart_fail_closed(tmp_path):
    path, receiver, args, auth, authority, req = fixtures(tmp_path)
    receiver.claim(**args)
    delivery = {
        "schema": cd.DELIVERY_SCHEMA, "request_id": req["request_id"],
        "delivery_id": str(uuid.uuid4()),
        "authorization_id": auth["authorization_id"],
        "authorization_revision": auth["revision"],
        "credential_id": auth["credential_id"],
        "credential_revision": auth["credential_revision"],
        "consumer": "archive-mirror",
        "purpose": "archive-mirror-upstream-fetch",
        "issued_at": args["now"] - 1,
        "expires_at": args["now"] + 60,
        "secret_format": "base64",
        "secret": "dGVzdC1zZWNyZXQ=",
    }
    signed = cd.sign_delivery(delivery, authority)
    dargs = {k: args[k] for k in (
        "scope", "expected_scope", "signed_authorization",
        "authority_public_key", "expected_issuer", "now")}
    dargs.update(request=req, signed_delivery=signed)
    assert receiver.verify_and_record_delivery(**dargs)["status"] == "delivered"
    assert "dGVzdC1zZWNyZXQ=" not in (path / "archive-provider-ledger.json").read_text()
    with pytest.raises(ReceiverHold, match="missing or interrupted"):
        OfflineArchiveReceiver(path, enabled=True).verify_and_record_delivery(**dargs)
    with pytest.raises(ReceiverHold, match="incomplete"):
        OfflineArchiveReceiver(path, enabled=True).claim(**args)
    forged = copy.deepcopy(signed)
    forged["delivery"]["secret"] = "YXR0YWNr"
    with pytest.raises((ValueError, ReceiverHold)):
        receiver.verify_and_record_delivery(**{**dargs, "signed_delivery": forged})


def test_missing_replaced_lock_and_bad_file_mode_hold(tmp_path):
    path, receiver, args, *_ = fixtures(tmp_path)
    lock = path / "archive-provider.lock"
    lock.rename(path / "renamed.lock")
    with pytest.raises(OSError):
        receiver.claim(**args)
    (path / "archive-provider.lock").write_bytes(b"")
    (path / "archive-provider.lock").chmod(0o644)
    with pytest.raises(ReceiverHold, match="unsafe permissions"):
        receiver.claim(**args)


def test_signed_revocation_persists_through_restart(tmp_path):
    path, receiver, args, auth, key, req = fixtures(tmp_path)
    receiver.claim(**args)
    newer = dict(auth)
    newer["status"] = "revoked"
    newer["revision"] = auth["revision"] + 1
    newer["revoked_at"] = args["now"]
    envelope = cd.sign_authorization(newer, key)
    rev_args = {k: args[k] for k in (
        "scope", "expected_scope", "authority_public_key", "expected_issuer", "now")}
    rev_args["signed_authorization"] = envelope
    assert receiver.hold_revoked(**rev_args)["status"] == "revocation-hold-durable"
    assert json.loads((path / "archive-provider-ledger.json").read_text())["revoked"] is True
    with pytest.raises(ReceiverHold, match="revoked ledger"):
        OfflineArchiveReceiver(path, enabled=True).claim(**args)
    with pytest.raises((ValueError, ReceiverHold)):
        receiver.hold_revoked(**{**rev_args, "signed_authorization": args["signed_authorization"]})
