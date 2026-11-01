"""Recovery-only denial of an incomplete selected issuer installation.

Never authenticates a normal launch and never supplies missing wheel provenance.
Requires original signed revocation evidence AND a distinct root-protected,
operator-signed recovery decision. Native owner supplies protected readers;
nothing here exposes a broker RPC, generates STATE, or clears operations.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import stat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .state_contract import canonical
from .state_io import raw
from . import certificate_selected_broker_install as broker

RECOVERY_SCHEMA = "zog-host-install-issuer-incomplete-recovery-revoke-v1"
RECOVERY_DOMAIN = b"zog-host-install-issuer-incomplete-recovery-revoke-v1\x00"
_FIELDS = frozenset(("schema", "purpose", "host_id", "installation_id",
    "state_volume_id", "commit_sha256", "revocation_approval_sha256",
    "authorization_revision", "operation_id", "operator_key_sha256",
    "signature_ed25519"))
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


def _deny():
    raise broker.StateError("issuer-recovery-revocation",
                            "recovery-authorization-unavailable") from None


def _read_signed(raw_bytes, *, pin, pin_sha, commit, revoke_approval):
    if (type(pin) is not bytes or len(pin) != 32
            or type(pin_sha) is not str or _HEX.fullmatch(pin_sha) is None
            or hashlib.sha256(pin).hexdigest() != pin_sha):
        _deny()
    try:
        def unique(pairs):
            d = {}
            for k,v in pairs:
                if k in d: _deny()
                d[k] = v
            return d
        row = json.loads(raw_bytes, object_pairs_hook=unique)
        if (type(row) is not dict or set(row) != _FIELDS
                or canonical(row) != raw_bytes
                or row["schema"] != RECOVERY_SCHEMA
                or row["purpose"] != "deny-incomplete-issuer-only"
                or row["operator_key_sha256"] != pin_sha
                or row["commit_sha256"] != hashlib.sha256(commit[1]).hexdigest()
                or row["revocation_approval_sha256"] !=
                    hashlib.sha256(revoke_approval).hexdigest()
                or any(row[name] != commit[0][name] for name in (
                    "host_id", "installation_id", "state_volume_id"))
                or type(row["authorization_revision"]) is not int
                or row["authorization_revision"] < 1
                or type(row["operation_id"]) is not str
                or _UUID.fullmatch(row["operation_id"]) is None):
            _deny()
        proof = base64.b64decode(row["signature_ed25519"], validate=True)
        if (len(proof) != 64 or base64.b64encode(proof).decode("ascii")
                != row["signature_ed25519"]):
            _deny()
        Ed25519PublicKey.from_public_bytes(pin).verify(
            proof, RECOVERY_DOMAIN + canonical({
                k:v for k,v in row.items() if k != "signature_ed25519"}))
        return row
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        _deny()


def _missing_provenance(fd):
    from zog.root_control.issuer_execution_provenance import NAME
    # Any entry, including symlink, malformed, or unreadable, is NOT a
    # missing-provenance case. Never use this route for a live/uncertain
    # provenance-bearing installation.
    try:
        os.stat(NAME, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        _deny()
    _deny()


def _existing_ledger(parent, commit_sha):
    from zog.root_control.issuer_execution_fence import (
        FIXED_DIRECTORY, LOCK, STATE, IssuerExecutionFence,
    )
    fd = os.open(FIXED_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        st = os.fstat(fd)
        parent_st = os.fstat(parent)
        if (not stat.S_ISDIR(st.st_mode) or
                (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) != (0,0,0o700)
                or st.st_dev != parent_st.st_dev):
            _deny()
        # No silent bootstrap of the lock or epoch ledger: both must already
        # exist with exact root ownership. This is NOT an installation path.
        for filename in (LOCK,STATE):
            leaf=os.stat(filename, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(leaf.st_mode) or leaf.st_nlink != 1
                    or (leaf.st_uid,leaf.st_gid) != (0,0)
                    or stat.S_IMODE(leaf.st_mode) != 0o600):
                _deny()
        fence=IssuerExecutionFence(fd)
        row=fence._read()
        if row is None or row["authority_commit_sha256"] != commit_sha:
            _deny()
        _missing_provenance(fd)
        return fd,fence
    except BaseException:
        os.close(fd)
        raise


def publish_recovery_only_revocation(
        *, trusted_original_revocation_reader,
        trusted_source_attestor,
        expected_approval_sha256,
        independently_trusted_recovery_reader,
        independently_pinned_recovery_key_reader):
    """Recovery-only root owner, with no fallback from normal revocation.

    Independent readers are protected native owner callbacks, not broker or
    caller input. Approval is for *abandoning* the current committed install,
    not for executing/replacing its signing authority or ledger.
    """
    if (os.geteuid() != 0 or
            not all(callable(x) for x in (
                trusted_original_revocation_reader, trusted_source_attestor,
                independently_trusted_recovery_reader,
                independently_pinned_recovery_key_reader))):
        _deny()
    from zog.root_control.issuer_execution_fence import (
        REVIEWED_BOX_CONTROL,
    )
    if REVIEWED_BOX_CONTROL != broker.BOX_CONTROL_REVIEWED_COMMIT:
        _deny()
    with broker._fixed_root_parent() as parent:
        # Signed original revocation is checked BEFORE any terminal epoch
        # transition. The publisher repeats the same verification under lock.
        p=raw(parent, broker.PROJECTION_NAME, uid=0,gid=0,mode=0o444)
        r=raw(parent, broker.INSTALL_RECEIPT_NAME,uid=0,gid=0,mode=0o600)
        c=raw(parent, broker.COMMIT_NAME,uid=0,gid=0,mode=0o444)
        if None in (p,r,c): _deny()
        proposal={"projection":broker._canonical_bytes(p),"projection_bytes":p}
        receipt=broker._canonical_bytes(r)
        if c != canonical(broker._installation_commit(proposal,receipt)):
            _deny()
        commit=(broker._canonical_bytes(c),c)
        if commit[0]["box_control_revision"] != REVIEWED_BOX_CONTROL:
            _deny()
        evidence=trusted_original_revocation_reader()
        if type(evidence) is not dict or set(evidence) != {
                "revoked_owner", "revoked_ledger", "approval_bytes"}: _deny()
        plan=broker.revocation_plan(
            projection_bytes=p,install_receipt=receipt,
            expected_approval_sha256=expected_approval_sha256, **evidence)
        if trusted_source_attestor(plan) is not True: _deny()
        recovery_bytes=independently_trusted_recovery_reader()
        pin=independently_pinned_recovery_key_reader()
        if (type(pin) is not dict or set(pin) != {"public_key","sha256"}):
            _deny()
        _read_signed(recovery_bytes,pin=pin["public_key"],pin_sha=pin["sha256"],
                     commit=commit,revoke_approval=evidence["approval_bytes"])
        fd,fence=_existing_ledger(parent,hashlib.sha256(c).hexdigest())
        try:
            # Execution and installer publication use the ORIGINAL shared
            # lock order: epoch lock -> installer publication lock.
            def publish():
                # Fail closed if source or recovery approval changed while
                # waiting for an already-running admission to release.
                _missing_provenance(fd)
                if (trusted_original_revocation_reader() != evidence or
                        independently_trusted_recovery_reader() != recovery_bytes
                        or independently_pinned_recovery_key_reader() != pin):
                    _deny()
                broker._publish_verified_revocation_locked(
                    trusted_original_revocation_reader=
                        trusted_original_revocation_reader,
                    trusted_source_attestor=trusted_source_attestor,
                    expected_approval_sha256=expected_approval_sha256)
                return True
            state=fence.revoke(publish_pending_revocation=publish)
            return {"status":"recovery-only-revoked",
                    "commit_sha256":hashlib.sha256(c).hexdigest(),
                    "epoch":state["epoch"], "revoked":True,
                    "uncertain_operations_retained":tuple(sorted(
                        key for key,op in state["operations"].items()
                        if op["phase"] != "terminal")),
                    "provenance_fabricated":False,
                    "execution_authorized":False,
                    "native_cleanup_verified":False}
        finally:
            os.close(fd)
