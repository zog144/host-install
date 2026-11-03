"""Archive-provider cross-owner *offline integration exercise*, disabled by default.

Test-only in-process bridge to the actual archive-mirror consumer API.
No listener, service, delivery transport or native authority selection.
Native root-control MUST NOT import/activate this bridge as its execution path:
a real application-private FD/IPC owner boundary and independently pinned
issuer/Host credentials must replace the in-process synthetic composition.
"""
from __future__ import annotations

import uuid

from zog.host_identify import archive_credentials as archive
from zog.host_identify import credential_delivery as cd

from .archive_provider_receiver import _load, _hold, ReceiverHold


def _check_current(scope, authority_key, issuer, now, read_current):
    """A second owner must supply CURRENT signed approval, not a cached boolean."""
    if not callable(read_current):
        _hold("current authorization source missing")
    value = archive.verify_provider_authorization(
        read_current(), authority_key, expected_issuer=issuer,
        scope=scope, now=now)
    if value["status"] != "approved":
        _hold("authorization no longer approved")
    return value


def _check_application(selected, delivery, consumer, witness):
    """Metadata alone is insufficient to attest installed secret bytes."""
    observation = consumer.inspect(selected)
    if (type(observation) is not dict or observation.get("status") != "installed"
            or observation.get("scope_id") != archive.provider_scope(selected)["scope_id"]
            or observation.get("credential_id") != archive.provider_scope(selected)["credential_id"]
            or observation.get("credential_revision") != selected["credential_revision"]
            or observation.get("role_revision") != selected["role_revision"]
            or observation.get("delivery_id") != delivery["delivery_id"]):
        _hold("archive private installation evidence missing or mismatched")
    if not callable(witness) or witness(selected, delivery, observation) is not True:
        _hold("archive installed-byte witness denied")
    return observation


def complete_offline(receiver, *, scope, expected_scope, signed_authorization,
                     authority_public_key, expected_issuer, request,
                     signed_delivery, read_current, consumer, installed_witness,
                     now, permit_first_install=False):
    """One source-tested application handoff; NEVER redeliver on recovery.

    The separately selected owner must first call receiver.claim() and
    receiver.verify_and_record_delivery(). This method only accepts their
    durable 'delivered' state and does not claim a request/nonce itself.
    permit_first_install is explicit and forbidden on a retry/reconciliation.
    """
    receiver._match(scope, expected_scope)
    expected_auth = receiver._authority(
        scope, signed_authorization, authority_public_key, expected_issuer, now)
    current = _check_current(scope, authority_public_key,
                             expected_issuer, now, read_current)
    if current != expected_auth:
        _hold("current archive authorization changed")
    cd.validate_request(request, current, now=now)
    delivery = cd.verify_delivery(
        signed_delivery, authority_public_key, request, current, now=now)
    archive.validate_delivery(scope, current, request, delivery, now=now)

    fd, lock, marker = receiver._open()
    try:
        state = _load(fd)
        if (state is None or state["revoked"] or state["phase"] != "delivered"
                or state["request_id"] != request["request_id"]
                or state["delivery_id"] != delivery["delivery_id"]):
            _hold("no durable one-time archive delivery claim")
        current_state = cd.advance_authorization(state["canonical"], current)
        row = next((r for r in current_state["requests"]
                    if r["request_id"] == request["request_id"]), None)
        if (row is None or row["status"] != "delivered"
                or row["delivery_id"] != delivery["delivery_id"]):
            _hold("canonical delivery ledger not ready")
        receiver._guard(fd, lock, marker)

        # inspect() is nonsecret and can detect prior completion after a
        # crash. It does NOT prove byte equality. In that case, never call
        # install_verified a second time, even if the request is identical.
        before = consumer.inspect(scope)
        if before["status"] == "installed":
            _check_application(scope, delivery, consumer, installed_witness)
            disposition = "reconciled-without-redelivery"
        elif before["status"] == "unavailable" and permit_first_install is True:
            # Application-local pending/blocked evidence always HOLDS. The
            # real adapter's own locks enforce its role and private paths.
            consumer.install_verified(scope, current, request, delivery, now=now)
            disposition = "first-install"
        else:
            _hold("ambiguous archive installation; no redelivery")
        _check_application(scope, delivery, consumer, installed_witness)
        if _check_current(scope, authority_public_key, expected_issuer, now,
                          read_current) != current:
            _hold("authorization changed before durable receipt")
        receiver._guard(fd, lock, marker)

        receipt = {
            "schema": cd.RECEIPT_SCHEMA, **cd.binding(request),
            "credential_revision": request["credential_revision"],
            "authorization_id": request["authorization_id"],
            "authorization_revision": request["authorization_revision"],
            "request_id": request["request_id"],
            "delivery_id": delivery["delivery_id"],
            "receipt_id": str(uuid.uuid4()), "outcome": "installed",
            "installed_at": int(now),
        }
        cd.validate_receipt(receipt, request, delivery, now=now)
        state["canonical"] = cd.record_installation(current_state, receipt)
        state["phase"] = "installed"
        state["receipt_id"] = receipt["receipt_id"]
        receiver._persist(fd, lock, marker, state)
        # Source receipt is a nonsecret local record, NOT a signed HTTP ack.
        return {"status": "local-receipt-durable",
                "disposition": disposition, "receipt": receipt}
    finally:
        receiver._close(fd, lock, marker)


def revoke_offline(receiver, *, scope, expected_scope, signed_revocation,
                   authority_public_key, expected_issuer, consumer, now):
    """Durable common deny first; real archive-mirror application tombstone next."""
    receiver.hold_revoked(
        scope=scope, expected_scope=expected_scope,
        signed_authorization=signed_revocation,
        authority_public_key=authority_public_key,
        expected_issuer=expected_issuer, now=now)
    # After an interruption here, a subsequent, explicitly reviewed call
    # can retry the SAME signed revocation. No delivery is ever retried.
    result = consumer.apply_signed_revocation(
        scope, signed_revocation, authority_public_key,
        expected_issuer=expected_issuer, now=now)
    if result.get("status") != "revoked" or (
            result.get("scope_id") != archive.provider_scope(scope)["scope_id"]):
        _hold("archive revocation application not confirmed")
    observation = consumer.inspect(scope)
    if (observation.get("status") != "blocked"
            or observation.get("reason") != "authorization-revoked"):
        _hold("archive secret remains usable after revocation")
    # No ack until a native owner records and attests this result.
    return {"status": "application-revocation-observed-no-native-ack"}
