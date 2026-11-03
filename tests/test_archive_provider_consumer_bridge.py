"""Cross-owner integration with the REAL pinned archive-mirror provider adapter.

All keys, provider secrets, lock roots and archive sentinels are synthetic
temporary files. No native receiver, transport, role registration or AWS.
"""
import copy
import json
import os
from pathlib import Path
import time
import uuid

import django
import pytest
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "zog.archive_mirror.settings")
django.setup()

from zog.archive_mirror import provider_credentials as consumer, store
from zog.host_identify import credential_delivery as cd

from test_archive_provider_receiver_owner import fixtures, ISSUER
from zog.host_install.archive_provider_consumer_bridge import (
    complete_offline, revoke_offline)
from zog.host_install.archive_provider_receiver import ReceiverHold, _load


def ready(tmp_path, monkeypatch):
    owner_dir, receiver, args, auth, key, request = fixtures(tmp_path)
    root = tmp_path / "archive-private"
    scope = args["scope"]
    config = {"root": str(root), "collections": ["sources"]}
    monkeypatch.setattr(consumer, "configuration", lambda: config)
    monkeypatch.setattr(store, "configuration", lambda: config)
    lease = {"host_id": scope["host_id"],
             "desired": {"revision": scope["role_revision"], "selected": True}}
    monkeypatch.setattr(consumer, "lease", lambda: lease)
    delivery = {
        "schema": cd.DELIVERY_SCHEMA, "request_id": request["request_id"],
        "delivery_id": str(uuid.uuid4()),
        "authorization_id": auth["authorization_id"],
        "authorization_revision": auth["revision"],
        "credential_id": auth["credential_id"],
        "credential_revision": auth["credential_revision"],
        "consumer": "archive-mirror",
        "purpose": "archive-mirror-upstream-fetch",
        "issued_at": args["now"] - 1,
        "expires_at": args["now"] + 60,
        "secret_format": "base64", "secret": "c3ludGhldGljLXByb3ZpZGVy",
    }
    signed = cd.sign_delivery(delivery, key)
    receiver.claim(**args)
    receiver.verify_and_record_delivery(
        scope=scope, expected_scope=args["expected_scope"],
        signed_authorization=args["signed_authorization"],
        authority_public_key=key.public_key(), expected_issuer=ISSUER,
        request=request, signed_delivery=signed, now=args["now"])
    read_current = lambda: args["signed_authorization"]
    def witness(selected, delivered, observation):
        # Synthetic app-owner witness only. A native receiver must use
        # separate protected UID/FD evidence, never read the secret as root.
        try:
            with consumer.open_for(selected, operation="fetch",
                                   collection="sources") as source:
                return source.read() == cd.secret_bytes(delivered)
        except (OSError, ValueError):
            return False
    params = dict(
        scope=scope, expected_scope=args["expected_scope"],
        signed_authorization=args["signed_authorization"],
        authority_public_key=key.public_key(),
        expected_issuer=ISSUER, request=request, signed_delivery=signed,
        read_current=read_current, consumer=consumer,
        installed_witness=witness, now=args["now"])
    return owner_dir, root, receiver, params, auth, key, delivery


def test_actual_archive_install_and_secret_free_receipt(tmp_path, monkeypatch):
    owner, root, receiver, params, auth, key, delivery = ready(tmp_path, monkeypatch)
    result = complete_offline(receiver, **params, permit_first_install=True)
    assert result["disposition"] == "first-install"
    assert result["status"] == "local-receipt-durable"
    assert consumer.inspect(params["scope"])["status"] == "installed"
    state = json.loads((owner / "archive-provider-ledger.json").read_text())
    assert state["phase"] == "installed"
    assert state["canonical"]["requests"][-1]["status"] == "installed"
    assert delivery["secret"] not in json.dumps(state)
    assert "synthetic-provider" not in json.dumps(result)
    assert result["receipt"]["delivery_id"] == delivery["delivery_id"]
    with pytest.raises(ReceiverHold, match="no durable one-time"):
        complete_offline(receiver, **params, permit_first_install=True)


def test_ambiguous_success_reconciled_without_second_install(tmp_path, monkeypatch):
    owner, root, receiver, params, auth, key, delivery = ready(tmp_path, monkeypatch)
    original_persist = receiver._persist
    def fail_receipt(fd, lock, marker, state):
        if state["phase"] == "installed":
            raise OSError("synthetic interruption before canonical receipt")
        return original_persist(fd, lock, marker, state)
    monkeypatch.setattr(receiver, "_persist", fail_receipt)
    with pytest.raises(OSError, match="interruption"):
        complete_offline(receiver, **params, permit_first_install=True)
    assert consumer.inspect(params["scope"])["status"] == "installed"
    secret_path = next((root / "provider-credentials").glob("*.secret"))
    inode = secret_path.stat().st_ino
    assert _load_owner(receiver)["phase"] == "delivered"
    monkeypatch.setattr(receiver, "_persist", original_persist)
    def forbidden(*args, **kwargs):
        pytest.fail("recovery must not call install_verified again")
    monkeypatch.setattr(consumer, "install_verified", forbidden)
    repaired = complete_offline(receiver, **params, permit_first_install=False)
    assert repaired["disposition"] == "reconciled-without-redelivery"
    assert secret_path.stat().st_ino == inode
    assert _load_owner(receiver)["phase"] == "installed"


def _load_owner(receiver):
    fd, lock, marker = receiver._open()
    try:
        return _load(fd)
    finally:
        receiver._close(fd, lock, marker)


def test_uncertain_or_false_byte_witness_holds_without_redelivery(tmp_path, monkeypatch):
    owner, root, receiver, params, *_ = ready(tmp_path, monkeypatch)
    blocked = dict(params, installed_witness=lambda *_: False)
    with pytest.raises(ReceiverHold, match="installed-byte witness denied"):
        complete_offline(receiver, **blocked, permit_first_install=True)
    assert consumer.inspect(params["scope"])["status"] == "installed"
    assert _load_owner(receiver)["phase"] == "delivered"
    with pytest.raises(ReceiverHold, match="installed-byte witness denied"):
        complete_offline(receiver, **blocked, permit_first_install=False)
    assert _load_owner(receiver)["phase"] == "delivered"


def test_pending_or_wrong_purpose_denies_before_consumer_install(tmp_path, monkeypatch):
    owner, root, receiver, params, *_ = ready(tmp_path, monkeypatch)
    called = []
    original = consumer.install_verified
    monkeypatch.setattr(consumer, "install_verified",
                        lambda *a, **kw: called.append(True))
    changed = dict(params, expected_scope={**params["scope"],
                                            "provider_id": "different"})
    with pytest.raises((ReceiverHold, ValueError)):
        complete_offline(receiver, **changed, permit_first_install=True)
    assert called == []
    changed = dict(params, read_current=lambda: {
        **params["signed_authorization"],
        "authorization": {**params["signed_authorization"]["authorization"],
                          "purpose": "issuer-cloudflare-dns01"}})
    with pytest.raises((ReceiverHold, ValueError)):
        complete_offline(receiver, **changed, permit_first_install=True)
    assert called == []


def test_actual_signed_revocation_and_interruption_preserve_objects(tmp_path, monkeypatch):
    owner, root, receiver, params, auth, key, delivery = ready(tmp_path, monkeypatch)
    complete_offline(receiver, **params, permit_first_install=True)
    objects = root / "objects"; objects.mkdir()
    pins = root / "retained-pins"; pins.mkdir()
    (objects / "sample-object").write_bytes(b"immutable-object")
    (pins / "pin-evidence").write_bytes(b"retained-pin")
    revoked = {**auth, "status": "revoked",
               "revision": auth["revision"] + 1,
               "revoked_at": params["now"]}
    signed_revoked = cd.sign_authorization(revoked, key)
    original = consumer.apply_signed_revocation
    def interrupt(*args, **kwargs):
        raise OSError("crash after common ledger, before application")
    monkeypatch.setattr(consumer, "apply_signed_revocation", interrupt)
    call = dict(scope=params["scope"], expected_scope=params["expected_scope"],
                signed_revocation=signed_revoked, authority_public_key=key.public_key(),
                expected_issuer=ISSUER, consumer=consumer, now=params["now"])
    with pytest.raises(OSError, match="crash"):
        revoke_offline(receiver, **call)
    assert _load_owner(receiver)["revoked"] is True
    with pytest.raises(ReceiverHold, match="no durable one-time"):
        complete_offline(receiver, **params, permit_first_install=False)
    monkeypatch.setattr(consumer, "apply_signed_revocation", original)
    assert revoke_offline(receiver, **call)["status"] == (
        "application-revocation-observed-no-native-ack")
    assert consumer.inspect(params["scope"])["status"] == "blocked"
    with pytest.raises((ValueError, OSError)):
        consumer.open_for(params["scope"], operation="fetch", collection="sources")
    assert (objects / "sample-object").read_bytes() == b"immutable-object"
    assert (pins / "pin-evidence").read_bytes() == b"retained-pin"
    assert revoke_offline(receiver, **call)["status"] == (
        "application-revocation-observed-no-native-ack")
