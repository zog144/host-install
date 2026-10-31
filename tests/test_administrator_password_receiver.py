"""The receiver has no ingress/installation side effects; exact 0.3.5 interop."""
import base64
import hashlib
import uuid

import pytest

cd = pytest.importorskip("zog.host_identify.credential_delivery")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.host_install import administrator_password_receiver as receiver


NOW = 1793440000


def sample(password="Installed-fixture-password-829!"):
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    pin = public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    proposal = {
        "schema": receiver.PROPOSAL_SCHEMA,
        "purpose": receiver.PURPOSE,
        "consumer": receiver.CONSUMER,
        "credential_id": receiver.CREDENTIAL_ID,
        "operation": "first-provision",
        "host_id": str(uuid.uuid4()),
        "host_fingerprint": "a" * 64,
        "installation_id": str(uuid.uuid4()),
        "state_volume_id": str(uuid.uuid4()),
        "registry_id": "primary",
        "account_id": 1,
        "account": "station-admin",
        "credential_revision": 1,
        "operator_approval_sha256": "b" * 64,
        "destination": receiver.DESTINATION,
        "source_kind": "operator-provisioned-new-secret",
        "source_password_verified": True,
        "receiver_grant_id": str(uuid.uuid4()),
        "account_revision": "c" * 64,
        "session_revocation_required": True,
    }
    issuer = "https://host-registry.hosts.zog-network-demo.uk"
    auth = {
        "schema": cd.AUTHORIZATION_SCHEMA,
        "issuer": issuer,
        **cd.binding(proposal),
        "credential_revision": 1,
        "authorization_id": str(uuid.uuid4()),
        "revision": 2,
        "status": "approved",
        "approved_at": NOW - 60,
        "revoked_at": None,
        "expires_at": NOW + 600,
    }
    request = {
        "schema": cd.REQUEST_SCHEMA,
        **cd.binding(proposal),
        "credential_revision": 1,
        "authorization_id": auth["authorization_id"],
        "authorization_revision": 2,
        "request_id": str(uuid.uuid4()),
        "action": "deliver",
        "previous_delivery_id": None,
        "created_at": NOW - 20,
        "expires_at": NOW + 80,
    }
    delivery = {
        "schema": cd.DELIVERY_SCHEMA,
        "request_id": request["request_id"],
        "delivery_id": str(uuid.uuid4()),
        "authorization_id": auth["authorization_id"],
        "authorization_revision": 2,
        "credential_id": "station-admin",
        "credential_revision": 1,
        "consumer": "station-access",
        "purpose": "station-administrator-password",
        "issued_at": NOW - 5,
        "expires_at": NOW + 80,
        "secret_format": "base64",
        "secret": base64.b64encode(password.encode()).decode("ascii"),
    }
    ledger = cd.record_delivery(
        cd.admit_request(cd.new_ledger(auth), request), delivery
    )
    return {
        "proposal": proposal,
        "authorization_envelope": cd.sign_authorization(auth, key),
        "delivery_envelope": cd.sign_delivery(delivery, key),
        "request": request,
        "ledger": ledger,
        "local_binding": cd.binding(proposal),
        "expected_issuer": issuer,
        "authority_public_key": public,
        "expected_authority_pin_sha256": hashlib.sha256(pin).hexdigest(),
        "expected_proposal_sha256": hashlib.sha256(
            cd.canonical(proposal)
        ).hexdigest(),
        "expected_operator_approval_sha256": "b" * 64,
        "nonce_checkpoint_sha256": "d" * 64,
        "now": NOW,
    }, delivery


def review(args):
    return receiver.review_delivered(**args)


def test_signed_admitted_delivery_to_only_station_admin_with_no_secret_in_proof():
    args, delivery = sample()
    proof, password = review(args)
    assert password == "Installed-fixture-password-829!"
    assert proof["status"] == "root-verified-delivered-not-installed"
    assert proof["account_id"] == 1
    assert proof["request_id"] == args["request"]["request_id"]
    assert proof["delivery_id"] == delivery["delivery_id"]
    assert password not in repr(proof)
    assert delivery["secret"] not in repr(proof)
    assert proof["ledger_checkpoint_sha256"] == hashlib.sha256(
        cd.canonical(args["ledger"])
    ).hexdigest()


def test_signed_delivery_unrecorded_or_cancelled_is_not_installable():
    args, delivery = sample()
    args["ledger"]["requests"][0]["status"] = "pending"
    args["ledger"]["requests"][0]["delivery_id"] = None
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)
    args, delivery = sample()
    args["ledger"]["requests"][0]["status"] = "cancelled-after-delivery"
    args["ledger"]["rotation_required"] = True
    args["ledger"]["requests"][0]["cancel_id"] = str(uuid.uuid4())
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)


@pytest.mark.parametrize("field,value", [
    ("purpose", "issuer-cloudflare-dns01"),
    ("consumer", "certify-manage"),
    ("credential_id", "other-user"),
    ("destination", "generic-file"),
    ("session_revocation_required", False),
    ("source_password_verified", False),
    ("account_revision", ""),
    ("operator_approval_sha256", ""),
])
def test_proposal_cannot_override_account_destination(field,value):
    args, delivery = sample()
    args["proposal"][field] = value
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)


def test_proposal_requires_independently_expected_digest():
    args, _ = sample()
    args["expected_proposal_sha256"] = "0"*64
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)


def test_wrong_credential_authority_pin_and_wrong_local_host_fail():
    args, _ = sample()
    args["expected_authority_pin_sha256"] = "0"*64
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)
    args, _ = sample()
    args["local_binding"]["host_id"] = str(uuid.uuid4())
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)


def test_wrong_signed_authorization_or_delivery_fails():
    args, _ = sample()
    args["authorization_envelope"]["authorization"]["credential_revision"] = 2
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)
    args, _ = sample()
    args["delivery_envelope"]["delivery"]["secret"] = base64.b64encode(b"other").decode()
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        review(args)


def test_unsigned_receipt_candidate_requires_django_durable_readback_and_revocation():
    args, delivery = sample()
    proof, _ = review(args)
    result = {
        "schema": receiver.MUTATION_RESULT_SCHEMA,
        "status": "django-password-committed",
        "audit_id": 987,
        "account_id": 1,
        "account_revision_before": proof["account_revision"],
        "account_revision_after": "e"*64,
        "request_id": proof["request_id"],
        "delivery_id": proof["delivery_id"],
        "credential_revision": proof["credential_revision"],
        "session_revocation_verified": True,
        "vnc_grants_revoked": True,
        "shared_v1_receipt_signed": False,
    }
    receipt = receiver.receipt_candidate(
        proof=proof, request=args["request"], delivery=delivery,
        mutation_result=result, django_readback=dict(result),
        receipt_id=str(uuid.uuid4()), installed_at=NOW, now=NOW,
    )
    assert cd.validate_receipt(receipt, args["request"], delivery, now=NOW) == receipt
    assert "account_revision" not in receipt
    altered = dict(result, vnc_grants_revoked=False)
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        receiver.receipt_candidate(
            proof=proof, request=args["request"], delivery=delivery,
            mutation_result=altered, django_readback=altered,
            receipt_id=str(uuid.uuid4()), installed_at=NOW, now=NOW,
        )
    with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
        receiver.receipt_candidate(
            proof=proof, request=args["request"], delivery=delivery,
            mutation_result=result, django_readback=dict(result,audit_id=988),
            receipt_id=str(uuid.uuid4()), installed_at=NOW, now=NOW,
        )


def test_bad_utf8_nul_and_too_long_are_rejected_without_django_call():
    for password in ("abcd\x00efgh", "Z"*1025):
        args,_=sample(password)
        with pytest.raises(receiver.AdministratorPasswordReceiverDenied):
            review(args)
