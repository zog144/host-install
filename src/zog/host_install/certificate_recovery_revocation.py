"""Recovery-only denial of an incomplete selected issuer installation.

Never authenticates a normal launch and never supplies missing wheel provenance.
Requires original signed revocation evidence AND a distinct root-protected,
operator-signed recovery decision. Native owner supplies protected readers;
nothing here exposes a broker RPC, generates STATE, or clears operations.
"""
from __future__ import annotations
import base64
import copy
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

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
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, InvalidSignature):
        _deny()



def _require_current_recovery_checkpoint(reader, signed, key):
    """Independently selected current approval epoch; stale approvals denied.

    Native reader must be root-protected and cannot be provided by an
    untrusted request, just like the protected original revocation reader.
    """
    if not callable(reader):
        _deny()
    observed=reader()
    if (type(observed) is not dict or set(observed) != {
            "authorization_revision","operation_id","commit_sha256",
            "operator_key_sha256"} or
            any(observed.get(name) != signed[name] for name in observed)):
        _deny()
    return observed

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
        independently_pinned_recovery_key_reader,
        independently_trusted_recovery_checkpoint_reader):
    """Recovery-only root owner, with no fallback from normal revocation.

    Independent readers are protected native owner callbacks, not broker or
    caller input. Approval is for *abandoning* the current committed install,
    not for executing/replacing its signing authority or ledger.
    """
    if (os.geteuid() != 0 or
            not all(callable(x) for x in (
                trusted_original_revocation_reader, trusted_source_attestor,
                independently_trusted_recovery_reader,
                independently_pinned_recovery_key_reader,
                independently_trusted_recovery_checkpoint_reader))):
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
        # Snapshot caller-provided mapping values. Never retain a mutable
        # reader-owned dictionary as the original validated authority.
        evidence=trusted_original_revocation_reader()
        if type(evidence) is dict: evidence=copy.deepcopy(evidence)
        if type(evidence) is not dict or set(evidence) != {
                "revoked_owner", "revoked_ledger", "approval_bytes"}: _deny()
        plan=broker.revocation_plan(
            projection_bytes=p,install_receipt=receipt,
            expected_approval_sha256=expected_approval_sha256, **evidence)
        if trusted_source_attestor(plan) is not True: _deny()
        recovery_bytes=independently_trusted_recovery_reader()
        pin=independently_pinned_recovery_key_reader()
        if type(pin) is dict: pin=dict(pin)
        if (type(pin) is not dict or set(pin) != {"public_key","sha256"}):
            _deny()
        signed=_read_signed(recovery_bytes,pin=pin["public_key"],pin_sha=pin["sha256"],
                     commit=commit,revoke_approval=evidence["approval_bytes"])
        current=dict(_require_current_recovery_checkpoint(
            independently_trusted_recovery_checkpoint_reader,signed,pin))
        fd,fence=_existing_ledger(parent,hashlib.sha256(c).hexdigest())
        try:
            # Provenance could appear while the owner waits for the fence.\n            # In that case the fence may already be irrevocably revoked,\n            # while marker publication stays incomplete: never report success.\n            # Execution and installer publication use the ORIGINAL shared
            # lock order: epoch lock -> installer publication lock.
            def publish():
                # Fail closed if source or recovery approval changed while
                # waiting for an already-running admission to release.
                _missing_provenance(fd)
                if (trusted_original_revocation_reader() != evidence or
                        independently_trusted_recovery_reader() != recovery_bytes
                        or independently_pinned_recovery_key_reader() != pin
                        or _require_current_recovery_checkpoint(
                            independently_trusted_recovery_checkpoint_reader,
                            signed,pin) != current):
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



def publish_recovery_only_abandonment(
        *, trusted_original_revocation_reader,
        trusted_source_attestor,
        expected_approval_sha256,
        independently_trusted_recovery_reader,
        independently_pinned_recovery_key_reader,
        independently_trusted_recovery_checkpoint_reader):
    """Abandon an irrevocably committed broker BEFORE an execution ledger exists.

    Does not create an epoch/lock/provenance or assert that no old operation
    ever ran. A PRESENT ledger, even corrupted or symlinked, MUST use
    preserved-ledger reconciliation, not this absence-only route.
    No fallback from the normal publisher and no new-launch authority.
    """
    if (os.geteuid()!=0 or not all(callable(fn) for fn in (
            trusted_original_revocation_reader, trusted_source_attestor,
            independently_trusted_recovery_reader,
            independently_pinned_recovery_key_reader,
            independently_trusted_recovery_checkpoint_reader))):
        _deny()
    from zog.root_control.issuer_execution_fence import (
        FIXED_DIRECTORY, LOCK, STATE, IssuerExecutionFence,
    )
    from zog.root_control.issuer_execution_provenance import NAME

    def check_no_ledger(parent):
        try:
            fd=os.open(FIXED_DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|
                       os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        except FileNotFoundError:
            # An absent execution directory has no stable writer lock. Its
            # creation could race this abandonment: deny, never fabricate it.
            _deny()
        try:
            st=os.fstat(fd)
            if ((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(0,0,0o700)
                    or st.st_dev!=os.fstat(parent).st_dev):
                _deny()
            try:
                lock=os.stat(LOCK,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:
                _deny()  # cannot serialize against ledger initialization
            if (not stat.S_ISREG(lock.st_mode) or lock.st_nlink!=1
                    or (lock.st_uid,lock.st_gid)!=(0,0)
                    or stat.S_IMODE(lock.st_mode)!=0o600):
                _deny()
            for leaf in (NAME,STATE):
                try:
                    os.stat(leaf,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _deny()
        finally:
            os.close(fd)

    @contextmanager
    def protected_absent_epoch():
        # The common writer lock must be acquired BEFORE the installation
        # publication lock (the same order as ordinary revocation). An
        # installer initializing its first epoch must wait for a durable
        # denial marker, or else its ledger is already present and we deny.
        with broker._fixed_root_parent() as parent:
            check_no_ledger(parent)
            fd=os.open(FIXED_DIRECTORY,os.O_RDONLY|os.O_DIRECTORY|
                       os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            try:
                fence=IssuerExecutionFence(fd)
                with fence._locked():
                    check_no_ledger(parent)
                    yield
            finally:
                os.close(fd)

    with broker._fixed_root_parent() as fd:
        p=raw(fd,broker.PROJECTION_NAME,uid=0,gid=0,mode=0o444)
        r=raw(fd,broker.INSTALL_RECEIPT_NAME,uid=0,gid=0,mode=0o600)
        c=raw(fd,broker.COMMIT_NAME,uid=0,gid=0,mode=0o444)
        if None in (p,r,c): _deny()
        proposal={"projection":broker._canonical_bytes(p),"projection_bytes":p}
        original_receipt=broker._canonical_bytes(r)
        if c!=canonical(broker._installation_commit(proposal,original_receipt)):
            _deny()
        commit=(broker._canonical_bytes(c),c)
        evidence=trusted_original_revocation_reader()
        if type(evidence) is dict: evidence=copy.deepcopy(evidence)
        if type(evidence) is not dict or set(evidence)!={
                "revoked_owner","revoked_ledger","approval_bytes"}: _deny()
        plan=broker.revocation_plan(
            projection_bytes=p,install_receipt=original_receipt,
            expected_approval_sha256=expected_approval_sha256,**evidence)
        if trusted_source_attestor(plan) is not True: _deny()
        approval=independently_trusted_recovery_reader()
        pin=independently_pinned_recovery_key_reader()
        if type(pin) is dict: pin=dict(pin)
        if type(pin) is not dict or set(pin)!={"public_key","sha256"}:
            _deny()
        signed=_read_signed(approval,pin=pin["public_key"],pin_sha=pin["sha256"],
                     commit=commit,revoke_approval=evidence["approval_bytes"])
        current=dict(_require_current_recovery_checkpoint(
            independently_trusted_recovery_checkpoint_reader,signed,pin))
        check_no_ledger(fd)

    # The underlying publisher takes the installer lock only after the
    # wrapper has acquired the ORIGINAL shared execution lock. This keeps
    # an epoch-initializing installer from overtaking the absence check.
    # Source provenance installation requires an initialized epoch ledger,
    # so an absent one cannot authorize a concurrent selected launch.
    def guarded_attestor(proposal):
        with broker._fixed_root_parent() as parent:
            if raw(parent,broker.COMMIT_NAME,uid=0,gid=0,mode=0o444)!=c:
                _deny()
            check_no_ledger(parent)
        if (independently_trusted_recovery_reader()!=approval
                or independently_pinned_recovery_key_reader()!=pin
                or _require_current_recovery_checkpoint(
                    independently_trusted_recovery_checkpoint_reader,
                    signed,pin)!=current
                or trusted_original_revocation_reader()!=evidence):
            _deny()
        return trusted_source_attestor(proposal) is True

    with protected_absent_epoch():
        result=broker._publish_verified_revocation_locked(
            trusted_original_revocation_reader=trusted_original_revocation_reader,
            trusted_source_attestor=guarded_attestor,
            expected_approval_sha256=expected_approval_sha256)
    return {**result,"status":"recovery-only-abandoned-before-epoch",
            "execution_history_unknown":True,
            "execution_provenance_fabricated":False,
            "execution_ledger_created":False,
            "execution_authorized":False,
            "native_cleanup_verified":False}
