"""Source-only HTTPS-v1 station administrator receiver contract.

No socket, host-install STATE creation, plaintext file, CLI password argument,
Django model edit or receipt signer exists in this module. The native protected
receiver must supply trusted root-owned authorization/key, HostIdentity HTTP
request and persisted nonce/ledger evidence. Account mutation is delegated
synchronously to station-access's SecurityGate-locked Django ceremony.
"""
from __future__ import annotations

import hashlib
import re
import uuid

CONSUMER = "station-access"
PURPOSE = "station-administrator-password"
CREDENTIAL_ID = "station-admin"
DESTINATION = "protected-station-admin-state"
PROPOSAL_SCHEMA = "zog-admin-credential-provisioning-proposal-v1"
PROOF_SCHEMA = "zog-admin-credential-protected-handoff-v1"
MUTATION_RESULT_SCHEMA = "zog-admin-credential-django-mutation-v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40,128}\Z")

PROPOSAL_FIELDS = frozenset((
    "schema", "purpose", "consumer", "credential_id", "operation",
    "host_id", "host_fingerprint", "installation_id", "state_volume_id",
    "registry_id", "account_id", "account", "credential_revision",
    "operator_approval_sha256", "destination", "source_kind",
    "source_password_verified", "receiver_grant_id", "account_revision",
    "session_revocation_required",
))


class AdministratorPasswordReceiverDenied(ValueError):
    """Never include a secret or signed delivery bytes in an exception."""


def deny(code="administrator-password-receiver-denied"):
    raise AdministratorPasswordReceiverDenied(code) from None


def _cd():
    try:
        from zog.host_identify import credential_delivery
    except ImportError:
        deny("host-identify-035-protocol-not-installed")
    return credential_delivery


def _uuid(value):
    if type(value) is not str:
        deny("invalid-uuid")
    try:
        x = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        deny("invalid-uuid")
    if str(x) != value:
        deny("invalid-uuid")


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _hex64(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


def _proposal(value, cd):
    if type(value) is not dict or set(value) != PROPOSAL_FIELDS:
        deny("proposal-schema-mismatch")
    if (value["schema"] != PROPOSAL_SCHEMA
            or value["purpose"] != PURPOSE
            or value["consumer"] != CONSUMER
            or value["credential_id"] != CREDENTIAL_ID
            or value["account"] != CREDENTIAL_ID
            or value["destination"] != DESTINATION
            or value["operation"] not in {"first-provision", "rotate"}
            or value["source_kind"] not in {
                "first-login-verified-export", "operator-provisioned-new-secret"
            }
            or value["source_password_verified"] is not True
            or value["session_revocation_required"] is not True
            or type(value["account_id"]) is not int or value["account_id"] < 1
            or type(value["credential_revision"]) is not int
            or value["credential_revision"] < 1
            or not _hex64(value["operator_approval_sha256"])
            or type(value["account_revision"]) is not str
            or _REVISION.fullmatch(value["account_revision"]) is None):
        deny("proposal-profile-mismatch")
    _uuid(value["receiver_grant_id"])
    return cd.binding(value)


def review_delivered(*, proposal, authorization_envelope, delivery_envelope,
                     request, ledger, local_binding, expected_issuer,
                     authority_public_key, expected_authority_pin_sha256,
                     expected_proposal_sha256,
                     expected_operator_approval_sha256,
                     nonce_checkpoint_sha256, now=None):
    """Verify exact source-bound inputs and recorded-delivered ledger.

    The caller MUST independently attest source + installed signer pin, its
    protected durable nonce/request/ledger, current HostIdentity and local
    installation/STATE, and re-read the authority after delivery. A JSON
    proposal, cached ledger copy, or password alone is NEVER authority.
    Returns a nonsecret handoff and in-memory password for the Django owner.
    """
    cd = _cd()
    try:
        expected = _proposal(proposal, cd)
        if (
            type(local_binding) is not dict
            or cd.binding(local_binding) != expected
            or not _hex64(expected_authority_pin_sha256)
            or not _hex64(expected_proposal_sha256)
            or not _hex64(expected_operator_approval_sha256)
            or not _hex64(nonce_checkpoint_sha256)
            or proposal["operator_approval_sha256"]
                != expected_operator_approval_sha256
            or _hash(cd.canonical(proposal)) != expected_proposal_sha256
        ):
            deny("owner-approved-destination-mismatch")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        if not isinstance(authority_public_key, Ed25519PublicKey):
            deny("authority-public-key-unavailable")
        pin = authority_public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        if _hash(pin) != expected_authority_pin_sha256:
            deny("authority-pin-mismatch")
        authorization = cd.verify_authorization(
            authorization_envelope, authority_public_key,
            expected_issuer=expected_issuer, expected_binding=expected, now=now,
        )
        if (
            authorization["status"] != "approved"
            or authorization["credential_revision"]
                != proposal["credential_revision"]
        ):
            deny("administrator-authorization-not-current")
        cd.validate_request(request, authorization, now=now)
        if (
            request["action"] != (
                "deliver" if proposal["operation"] == "first-provision"
                else "renew"
            )
        ):
            deny("administrator-operation-mismatch")
        delivery = cd.verify_delivery(
            delivery_envelope, authority_public_key,
            request, authorization, now=now,
        )
        cd.validate_ledger(ledger)
        if (
            cd.binding(ledger) != expected
            or ledger["authorization_status"] != "approved"
            or ledger["authorization_id"] != authorization["authorization_id"]
            or ledger["authorization_revision"] != authorization["revision"]
            or ledger["credential_revision"] != proposal["credential_revision"]
            or ledger["rotation_required"] is not False
        ):
            deny("durable-ledger-binding-mismatch")
        rows = [
            row for row in ledger["requests"]
            if row["request_id"] == request["request_id"]
        ]
        if len(rows) != 1 or rows[0]["status"] != "delivered" or (
            rows[0]["delivery_id"] != delivery["delivery_id"]
        ) or rows[0]["credential_revision"] != proposal["credential_revision"] or (
            rows[0]["authorization_revision"] != authorization["revision"]
        ):
            deny("delivery-not-durably-admitted")
        raw_secret = cd.secret_bytes(delivery)
        try:
            plaintext = raw_secret.decode("utf-8", errors="strict")
        except UnicodeError:
            deny("administrator-password-invalid-encoding")
        if (
            not 1 <= len(plaintext) <= 1024
            or "\x00" in plaintext
        ):
            deny("administrator-password-invalid-shape")
        proof = {
            "schema": PROOF_SCHEMA,
            "status": "root-verified-delivered-not-installed",
            **expected,
            "credential_revision": proposal["credential_revision"],
            "authorization_id": authorization["authorization_id"],
            "authorization_revision": authorization["revision"],
            "request_id": request["request_id"],
            "delivery_id": delivery["delivery_id"],
            "account_id": proposal["account_id"],
            "account_revision": proposal["account_revision"],
            "receiver_grant_id": proposal["receiver_grant_id"],
            "operator_approval_sha256": expected_operator_approval_sha256,
            "approved_proposal_sha256": expected_proposal_sha256,
            "ledger_checkpoint_sha256": _hash(cd.canonical(ledger)),
        }
        return proof, plaintext
    except AdministratorPasswordReceiverDenied:
        raise
    except Exception:
        # Hide secret or attacker-controlled exception details.
        deny("administrator-delivery-source-verification-failed")


def receipt_candidate(*, proof, request, delivery, mutation_result,
                      django_readback, receipt_id, installed_at, now=None):
    """Nonsecret receipt candidate only after authoritative Django readback.

    The trusted HostIdentity key holder must separately sign/emit this shared
    v1 receipt and durably reconcile the root ledger before acknowledging.
    """
    cd = _cd()
    _uuid(receipt_id)
    expected_keys = {
        "schema", "status", "audit_id", "account_id",
        "account_revision_before", "account_revision_after",
        "request_id", "delivery_id", "credential_revision",
        "session_revocation_verified", "vnc_grants_revoked",
        "shared_v1_receipt_signed",
    }
    try:
        if type(mutation_result) is not dict or set(mutation_result) != expected_keys:
            deny("django-mutation-result-schema")
        if django_readback != mutation_result:
            deny("django-durable-readback-mismatch")
        if (
            mutation_result["schema"] != MUTATION_RESULT_SCHEMA
            or mutation_result["status"] != "django-password-committed"
            or type(mutation_result["audit_id"]) is not int
            or mutation_result["audit_id"] < 1
            or mutation_result["account_id"] != proof["account_id"]
            or mutation_result["request_id"] != proof["request_id"]
            or mutation_result["delivery_id"] != proof["delivery_id"]
            or mutation_result["credential_revision"]
                != proof["credential_revision"]
            or mutation_result["account_revision_before"]
                != proof["account_revision"]
            or mutation_result["account_revision_after"]
                == proof["account_revision"]
            or mutation_result["session_revocation_verified"] is not True
            or mutation_result["vnc_grants_revoked"] is not True
            or mutation_result["shared_v1_receipt_signed"] is not False
        ):
            deny("django-installation-not-proven")
        _uuid(proof["request_id"])
        _uuid(proof["delivery_id"])
        result = {
            "schema": cd.RECEIPT_SCHEMA,
            **cd.binding(proof),
            "credential_revision": proof["credential_revision"],
            "authorization_id": proof["authorization_id"],
            "authorization_revision": proof["authorization_revision"],
            "request_id": proof["request_id"],
            "delivery_id": proof["delivery_id"],
            "receipt_id": receipt_id,
            "outcome": "installed",
            "installed_at": installed_at,
        }
        cd.validate_receipt(result, request, delivery, now=now)
        return result
    except AdministratorPasswordReceiverDenied:
        raise
    except Exception:
        deny("django-installation-receipt-rejected")
