"""External monotonic graphical signing checkpoint, source contract only.

The checkpoint issuer is an independent authority outside the Host's local
rollback domain, with a durable, linearizable, non-decreasing compare-and-
advance ledger. Neither this source module nor a local file can provide that
guarantee. Native transport and issuer provenance are not implemented here.

Never silently replaces authority, creates a Host credential or enables a
live signing key. Callbacks are synthetic contract harnesses, NOT native RPC.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import secrets
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from . import graphical_current_authority as local

SCHEMA="zog-host-install-graphical-external-monotonic-checkpoint-v1"
DOMAIN=b"zog-graphical-external-checkpoint-v1\x00"
FIELDS=frozenset(("schema","host_id","installation_id","epoch",
                  "pin_sha256","approval_sha256","sequence","nonce",
                  "signature_ed25519"))

def _deny():
    raise local.RotationDenied("independent graphical checkpoint unavailable") from None

def _fresh():
    return secrets.token_hex(24)

def checked_snapshot(blob, *, nonce, host_id, installation_id,
                     independently_pinned_external_key,
                     independently_expected_external_sha256,
                     independently_pinned_operator_key=None):
    """Verify an exact fresh service response, not a cached signed receipt."""
    try:
        key=independently_pinned_external_key
        if (type(key) is not bytes or len(key)!=32
                or hashlib.sha256(key).hexdigest()!=
                   independently_expected_external_sha256
                or (independently_pinned_operator_key is not None and
                    key == independently_pinned_operator_key)):
            _deny()
        row=local._parse(blob)
        if (set(row)!=FIELDS or row["schema"]!=SCHEMA
                or row["nonce"] != nonce or len(nonce)!=48
                or row["host_id"]!=host_id
                or row["installation_id"]!=installation_id
                or type(row["epoch"]) is not int or row["epoch"]<0
                or type(row["sequence"]) is not int or row["sequence"]<1
                or (row["pin_sha256"] is not None and
                    (type(row["pin_sha256"]) is not str or
                     local._HEX.fullmatch(row["pin_sha256"]) is None))
                or (row["approval_sha256"] is not None and
                    (type(row["approval_sha256"]) is not str or
                     local._HEX.fullmatch(row["approval_sha256"]) is None))
                or (row["epoch"]==0 and
                    (row["pin_sha256"] is not None or
                     row["approval_sha256"] is not None))):
            _deny()
        signature=base64.b64decode(row["signature_ed25519"],validate=True)
        if (len(signature)!=64 or
                base64.b64encode(signature).decode()!=row["signature_ed25519"]):
            _deny()
        Ed25519PublicKey.from_public_bytes(key).verify(
            signature,DOMAIN+local.canonical(
                {k:v for k,v in row.items() if k!="signature_ed25519"}))
        return row
    except (ValueError, TypeError, UnicodeError, OverflowError, KeyError, InvalidSignature):
        _deny()

def _read_external(read, *, pin, external_key, external_sha, operator_key):
    if not callable(read): _deny()
    nonce=_fresh()
    raw=read(nonce)
    return checked_snapshot(
        raw,nonce=nonce,host_id=pin["host_id"],
        installation_id=pin["installation_id"],
        independently_pinned_external_key=external_key,
        independently_expected_external_sha256=external_sha,
        independently_pinned_operator_key=operator_key)

def rotate_checked_source(*, public_fd, private_fd, approved_pin_bytes,
                          approval_bytes, independently_pinned_operator_public_key,
                          independently_expected_operator_sha256,
                          independently_pinned_external_public_key,
                          independently_expected_external_sha256,
                          read_independent_checkpoint,
                          compare_and_advance_independent_checkpoint,
                          uid=0, checkpoint=None):
    """Synthetic adapter: external CAS reservation BEFORE local key publication.

    All native sites must use a genuine root-authenticated external service,
    not these caller-selectable callbacks. No offline fallback is possible.
    """
    if checkpoint is None: checkpoint=lambda event:None
    local._protected_dir(public_fd,0o755,uid)
    local._protected_dir(private_fd,0o700,uid)
    with local._stable_lock(private_fd,uid):
        pin=local._pin(approved_pin_bytes)
        approval_sha=local._sha(approval_bytes)
        previous_raw=local._read(public_fd,local.PUBLIC_NAME,0o444,uid)
        previous=local._pin(previous_raw) if previous_raw is not None else None
        journal_raw=local._read(private_fd,local.PRIVATE_JOURNAL,0o600,uid)
        journal=local._parse(journal_raw) if journal_raw is not None else None
        pending=local._read(public_fd,local.PENDING_NAME,0o444,uid)
        # No new transition if local pin and private journal disagree.
        if previous is None:
            if journal is not None: _deny()
            prev_epoch=0
            prev_sha=None
        else:
            if journal is None: _deny()
            prev_epoch=previous["epoch"]
            prev_sha=local._sha(previous_raw)
            if journal["epoch"] != prev_epoch and pending is None: _deny()
            if journal["epoch"]==prev_epoch and journal["current_sha256"]!=prev_sha:
                _deny()
        reservation=local.canonical({
            "schema":local.APPROVAL_SCHEMA,"approval_sha256":approval_sha,
            "new_pin_sha256":local._sha(approved_pin_bytes),
            "new_epoch":pin["epoch"]})
        if pending is not None and pending!=reservation: _deny()
        if pending is None and pin["epoch"]==prev_epoch:
            # Same-byte idempotence is allowed ONLY with a fresh external
            # checkpoint at that exact highwater.
            if (journal is None or previous_raw!=approved_pin_bytes
                    or journal["approval_sha256"]!=approval_sha):
                _deny()
        elif (pin["epoch"]!=prev_epoch+1 and
              not (pending is not None and pin["epoch"]==prev_epoch)):
            _deny()
        local._approval(approval_bytes,independently_pinned_operator_public_key,
                        independently_expected_operator_sha256,pin,
                        previous if pin["epoch"]>prev_epoch else None,
                        check_previous=pin["epoch"]>prev_epoch)
        observed=_read_external(
            read_independent_checkpoint,pin=pin,
            external_key=independently_pinned_external_public_key,
            external_sha=independently_expected_external_sha256,
            operator_key=independently_pinned_operator_public_key)
        if pin["epoch"]==prev_epoch and pending is None:
            if (observed["epoch"]!=prev_epoch
                    or observed["pin_sha256"]!=prev_sha
                    or observed["approval_sha256"]!=approval_sha):
                _deny()
            return {"status":"same-byte-external-checked",
                    "epoch":prev_epoch,"activated":False}
        if observed["epoch"]==prev_epoch and pin["epoch"]>prev_epoch:
            if observed["pin_sha256"]!=prev_sha: _deny()
            if (prev_epoch and journal is not None and pending is None
                    and observed["approval_sha256"]!=journal["approval_sha256"]):
                _deny()
            # Deny old-key consumption before the external highwater moves.
            local._write_once(public_fd,local.PENDING_NAME,reservation,0o444)
            checkpoint("pending")
            if not callable(compare_and_advance_independent_checkpoint): _deny()
            compare_and_advance_independent_checkpoint(
                expected_epoch=prev_epoch,expected_sequence=observed["sequence"],
                expected_pin_sha256=prev_sha,
                next_epoch=pin["epoch"],next_pin_sha256=
                    local._sha(approved_pin_bytes),
                next_approval_sha256=approval_sha,
                host_id=pin["host_id"],installation_id=pin["installation_id"])
            checkpoint("external-advance")
        elif observed["epoch"]==pin["epoch"]:
            # Crash after external CAS: only the SAME reserved authority may
            # finish locally. A coherent rollback of both local records has
            # no pending marker and is permanently refused.
            if (pending is None or
                    observed["pin_sha256"]!=local._sha(approved_pin_bytes)
                    or observed["approval_sha256"]!=approval_sha):
                _deny()
        else:
            _deny()
        verified=_read_external(
            read_independent_checkpoint,pin=pin,
            external_key=independently_pinned_external_public_key,
            external_sha=independently_expected_external_sha256,
            operator_key=independently_pinned_operator_public_key)
        if (verified["epoch"]!=pin["epoch"]
                or verified["pin_sha256"]!=local._sha(approved_pin_bytes)
                or verified["approval_sha256"]!=approval_sha
                or verified["sequence"]<observed["sequence"]):
            _deny()
        # Local operation shares the SAME flock already held. No second
        # authority-selection layer or separate lock identity.
        outcome=local._rotate_locked(
            public_fd=public_fd,private_fd=private_fd,
            approved_pin_bytes=approved_pin_bytes,approval_bytes=approval_bytes,
            independently_pinned_operator_public_key=
                independently_pinned_operator_public_key,
            independently_expected_operator_sha256=
                independently_expected_operator_sha256,
            uid=uid,checkpoint=checkpoint)
        checkpoint("local-committed")
        final=_read_external(read_independent_checkpoint,pin=pin,
            external_key=independently_pinned_external_public_key,
            external_sha=independently_expected_external_sha256,
            operator_key=independently_pinned_operator_public_key)
        if (final["epoch"]!=pin["epoch"]
                or final["pin_sha256"]!=local._sha(approved_pin_bytes)
                or final["approval_sha256"]!=approval_sha
                or final["sequence"]<verified["sequence"]):
            _deny()
        return {**outcome,"externally_checked":True,"activated":False}

def read_checked_source(*, public_fd, read_independent_checkpoint,
                        independently_pinned_external_public_key,
                        independently_expected_external_sha256,uid=0):
    """Source-level local reader that refuses coherent public+private rollback.

    Actual host-deploy consumer/native relay must independently integrate
    this online gate. The existing gateway read alone remains insufficient.
    """
    pin=local.current_source_read(public_fd=public_fd,uid=uid)
    raw=local._read(public_fd,local.PUBLIC_NAME,0o444,uid)
    external=_read_external(read_independent_checkpoint,pin=pin,
        external_key=independently_pinned_external_public_key,
        external_sha=independently_expected_external_sha256,
        operator_key=None)
    if (external["epoch"]!=pin["epoch"]
            or external["pin_sha256"]!=local._sha(raw)):
        _deny()
    # A concurrent rotation can complete while the remote signed response is
    # in flight. Refuse an already-obsolete local authority even when the
    # response faithfully describes the state at the start of this call.
    # This is a source-level postcheck, NOT native atomic admission; the
    # installed gateway still needs its final protected commit fence.
    if (local._read(public_fd,local.PENDING_NAME,0o444,uid) is not None
            or local._read(public_fd,local.PUBLIC_NAME,0o444,uid)!=raw
            or local._read(public_fd,local.PENDING_NAME,0o444,uid) is not None):
        _deny()
    return pin
