"""Protected graphical current-signing-authority source installation contract.

NO native installer is activated here. The one exported owner entry opens only
fixed root-owned locations. Synthetic tests replace its fixed reader; NEVER
expose a directory, authority reader, issuer or callback through broker RPC.
The external monotonic checkpoint is mandatory in graphical rotate_source.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_current_authority as current
from . import graphical_rotation_checkpoint as checkpoint
from . import graphical_checkpoint_transport as online

PUBLIC_PARENT = "/etc/zog/host-deploy"
PRIVATE_PARENT = "/etc/zog/host-install/graphical-current-authority"
ORIGINAL_GRANT = "original-graphical-authority-grant-v1.json"
OPERATOR_PIN = "original-graphical-operator-pin-v1.json"
IDENTITY_PIN = "original-graphical-installation-identity-pin-v1.json"
SOURCE_ATTESTATION = "original-graphical-installed-source-v1.json"
CLAIM_PREFIX = "graphical-key-use-epoch-"
GRANT_SCHEMA = "zog-host-install-graphical-original-install-grant-v1"
OPERATOR_SCHEMA = "zog-host-install-graphical-operator-pin-v1"
IDENTITY_SCHEMA = "zog-host-install-graphical-installation-identity-pin-v1"
SOURCE_SCHEMA = "zog-host-install-graphical-source-record-v1"
CLAIM_SCHEMA = "zog-host-install-graphical-key-use-claim-v1"
GRANT_DOMAIN = b"zog-host-install-graphical-original-install-grant-v1\x00"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
GRANT_FIELDS = frozenset({
    "schema","host_id","installation_id","state_volume_id",
    "chain_policy_sha256","source_revision","wheel_record_sha256",
    "operator_key_sha256","external_key_sha256","authorization_revision",
    "signature_ed25519",
})
SOURCE_FIELDS = frozenset({
    "schema","host_id","installation_id","state_volume_id",
    "source_revision","wheel_record_sha256","original_grant_sha256",
})
CLAIM_FIELDS = frozenset({
    "schema","epoch","host_id","installation_id",
    "key_sha256","approved_pin_sha256","approval_sha256",
    "original_grant_sha256","authorization_revision",
})


def _deny():
    current._deny()


def _hash(x):
    return hashlib.sha256(x).hexdigest()


def _strict_file(fd, name, mode, uid):
    data = current._read(fd,name,mode,uid)
    if data is None:
        _deny()
    return data


def _protected_root_path(path, mode):
    """Never create or follow symlinks; preserve the directory inode."""
    if type(path) is not str or not path.startswith("/"):
        _deny()
    fd = os.open("/", os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for component in Path(path).parts[1:]:
            next_fd = os.open(component,os.O_RDONLY|os.O_DIRECTORY|
                              os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd)
            fd = next_fd
            st = os.fstat(fd)
            if (st.st_uid != 0 or st.st_gid != 0 or st.st_mode & 0o022):
                _deny()
        current._protected_dir(fd,mode,0)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def _fixed_native_directories():
    if os.geteuid() != 0:
        _deny()
    pub = _protected_root_path(PUBLIC_PARENT,0o755)
    try:
        priv = _protected_root_path(PRIVATE_PARENT,0o700)
        try:
            if os.fstat(pub).st_ino == os.fstat(priv).st_ino and (
                    os.fstat(pub).st_dev == os.fstat(priv).st_dev):
                _deny()
            yield pub,priv
        finally:
            os.close(priv)
    finally:
        os.close(pub)


def _signed_grant(raw, operator_key, sha256):
    if (type(operator_key) is not bytes or len(operator_key) != 32
            or _hash(operator_key) != sha256):
        _deny()
    grant = current._parse(raw)
    if (set(grant) != GRANT_FIELDS or grant["schema"] != GRANT_SCHEMA
            or type(grant["authorization_revision"]) is not int
            or grant["authorization_revision"] < 1
            or any(type(grant[x]) is not str or not grant[x] for x in (
                "host_id","installation_id","state_volume_id"))
            or type(grant["source_revision"]) is not str
            or _SHA40.fullmatch(grant["source_revision"]) is None
            or any(type(grant[x]) is not str or
                   _HEX.fullmatch(grant[x]) is None for x in (
                       "wheel_record_sha256","external_key_sha256"))
            or type(grant["chain_policy_sha256"]) is not str
            or not grant["chain_policy_sha256"].startswith("sha256:")
            or _HEX.fullmatch(grant["chain_policy_sha256"][7:]) is None):
        _deny()
    try:
        sig=base64.b64decode(grant["signature_ed25519"],validate=True)
        if (len(sig)!=64 or
                base64.b64encode(sig).decode()!=grant["signature_ed25519"]):
            _deny()
        Ed25519PublicKey.from_public_bytes(operator_key).verify(
            sig,GRANT_DOMAIN+current.canonical({
                k:v for k,v in grant.items() if k!="signature_ed25519"}))
    except (ValueError,TypeError,InvalidSignature,KeyError):
        _deny()
    return grant


def _read_pinned_key(private_fd, filename, schema, uid):
    raw_pin=_strict_file(private_fd,filename,0o600,uid)
    pinned=current._parse(raw_pin)
    if (set(pinned)!={"schema","public_key","sha256"} or
            pinned["schema"]!=schema):
        _deny()
    try:
        key=base64.b64decode(pinned["public_key"],validate=True)
    except (ValueError,TypeError):
        _deny()
    if (len(key)!=32 or base64.b64encode(key).decode()!=pinned["public_key"]
            or _hash(key)!=pinned["sha256"]):
        _deny()
    return key,pinned["sha256"],raw_pin


def _fixed_evidence(private_fd,uid, proposed, approval,external):
    """Immutable root-only evidence, not a caller-selected signer/source."""
    operator, operator_sha, raw_pin=_read_pinned_key(
        private_fd,OPERATOR_PIN,OPERATOR_SCHEMA,uid)
    identity, identity_sha, identity_pin=_read_pinned_key(
        private_fd,IDENTITY_PIN,IDENTITY_SCHEMA,uid)
    if (identity==operator or identity_sha==external["external_key_sha256"]
            or identity==base64.b64decode(proposed["public_key"],validate=True)):
        _deny()
    original=_strict_file(private_fd,ORIGINAL_GRANT,0o600,uid)
    grant=_signed_grant(original,identity,identity_sha)
    if grant["operator_key_sha256"]!=operator_sha:
        _deny()
    source=current._parse(_strict_file(private_fd,SOURCE_ATTESTATION,0o600,uid))
    if (set(source)!=SOURCE_FIELDS or source["schema"]!=SOURCE_SCHEMA
            or source["original_grant_sha256"]!=_hash(original)
            or any(source[x]!=grant[x] for x in (
                "host_id","installation_id","state_volume_id",
                "source_revision","wheel_record_sha256"))):
        _deny()
    approved=current._approval(
        approval,operator,operator_sha,proposed,None,
        check_previous=False)
    if (grant["host_id"]!=proposed["host_id"]
            or grant["installation_id"]!=proposed["installation_id"]
            or grant["chain_policy_sha256"]!=proposed["chain_policy_sha256"]
            or grant["source_revision"]!=proposed["source_revision"]
            or grant["authorization_revision"]>approved["authorization_revision"]
            or grant["external_key_sha256"]!=external["external_key_sha256"]
            or _hash(operator)==_hash(base64.b64decode(
                proposed["public_key"],validate=True))
            or _hash(operator)==grant["external_key_sha256"]):
        _deny()
    return {"grant":grant,"grant_bytes":original,
            "source_bytes":current.canonical(source),"operator":operator,
            "operator_sha256":operator_sha,"pin_bytes":raw_pin,
            "identity_pin_bytes":identity_pin,
            "authorization_revision":approved["authorization_revision"]}


def _claim(private_fd,uid,epoch):
    return current._read(private_fd,
                         CLAIM_PREFIX+str(epoch)+".json",0o600,uid)


def _verified_claim(raw, *, epoch, proposed, grant_sha):
    """Reject incomplete, foreign or re-bound retained key-use evidence.

    These root-private claims are durable anti-reuse evidence, not signatures
    or proof that the native Host/STATE issuer has been installed.
    """
    row=current._parse(raw)
    if (set(row)!=CLAIM_FIELDS or row["schema"]!=CLAIM_SCHEMA
            or type(row["epoch"]) is not int or row["epoch"]!=epoch
            or row["host_id"]!=proposed["host_id"]
            or row["installation_id"]!=proposed["installation_id"]
            or row["original_grant_sha256"]!=grant_sha
            or type(row["authorization_revision"]) is not int
            or row["authorization_revision"]<1
            or any(type(row[k]) is not str or _HEX.fullmatch(row[k]) is None
                   for k in ("key_sha256","approved_pin_sha256",
                             "approval_sha256","original_grant_sha256"))):
        _deny()
    return row


def _retired_preflight(private_fd,uid,proposed,grant_sha,
                       authorization_revision):
    """Reject a known retired key before creating a public pending marker.

    The same condition is revalidated while holding the rotation flock.
    """
    target=proposed["epoch"]
    if target>10000: _deny()
    key=_hash(base64.b64decode(proposed["public_key"],validate=True))
    prior_revision=0
    for epoch in range(1,target):
        raw=_claim(private_fd,uid,epoch)
        if raw is None: _deny()
        record=_verified_claim(raw,epoch=epoch,proposed=proposed,
                               grant_sha=grant_sha)
        if (record["key_sha256"]==key
                or record["authorization_revision"]<prior_revision):
            _deny()
        prior_revision=record["authorization_revision"]
    if authorization_revision<prior_revision:
        _deny()


def _claim_under_lock(private_fd,uid,proposed,approval,grant_sha,
                      authorization_revision):
    """No same signing key at any other epoch, including older retired keys."""
    target=proposed["epoch"]
    key=_hash(base64.b64decode(proposed["public_key"],validate=True))
    if target > 10000:
        _deny()  # bounded source record scan; native compaction needs approval
    prior_revision=0
    for epoch in range(1,target+1):
        raw=_claim(private_fd,uid,epoch)
        if raw is None:
            if epoch < target: _deny()
            continue
        row=_verified_claim(raw,epoch=epoch,proposed=proposed,
                            grant_sha=grant_sha)
        if (row["authorization_revision"]<prior_revision
                or (epoch<target and row["key_sha256"]==key)):
            _deny()
        prior_revision=row["authorization_revision"]
        if epoch==target and row!={
                "schema":CLAIM_SCHEMA,"epoch":target,
                "host_id":proposed["host_id"],
                "installation_id":proposed["installation_id"],
                "key_sha256":key,
                "approved_pin_sha256":_hash(current.canonical(proposed)),
                "approval_sha256":_hash(approval),
                "original_grant_sha256":grant_sha,
                "authorization_revision":authorization_revision}:
            _deny()
    if authorization_revision<prior_revision:
        _deny()
    claim={"schema":CLAIM_SCHEMA,"epoch":target,
           "host_id":proposed["host_id"],
           "installation_id":proposed["installation_id"],
           "key_sha256":key,
           "approved_pin_sha256":_hash(current.canonical(proposed)),
           "approval_sha256":_hash(approval),
           "original_grant_sha256":grant_sha,
           "authorization_revision":authorization_revision}
    current._write_once(private_fd,CLAIM_PREFIX+str(target)+".json",
                        current.canonical(claim),0o600)


def _install_source(*,public_fd,private_fd,approved_pin_bytes,approval_bytes,uid,
                    checkpoint=None):
    """Synthetic dirfd entry; native protected wrapper calls with uid=0 only."""
    current._protected_dir(public_fd,0o755,uid)
    current._protected_dir(private_fd,0o700,uid)
    proposed=current._pin(approved_pin_bytes)
    external,key=online.installed()  # exact independently pinned fixed path
    if (external["host_id"]!=proposed["host_id"]
            or external["installation_id"]!=proposed["installation_id"]):
        _deny()
    initial=_fixed_evidence(private_fd,uid,proposed,approval_bytes,external)
    _retired_preflight(private_fd,uid,proposed,
                       _hash(initial["grant_bytes"]),
                       initial["authorization_revision"])
    if key==initial["operator"] or key==base64.b64decode(
            proposed["public_key"],validate=True):
        _deny()
    if checkpoint is None: checkpoint=lambda event:None
    # The external source contract holds local._stable_lock. The 'pending'
    # callback is invoked WITHIN the shared lock, before external CAS.
    # Key-use claims are irrevocable and no-replace: a crash can only recover
    # the same signed epoch/approval/key. They are not signing private keys.
    def inside(event):
        if event=="pending":
            fresh=_fixed_evidence(
                private_fd,uid,proposed,approval_bytes,external)
            if fresh!=initial or online.installed()!=(external,key):
                _deny()
            _claim_under_lock(private_fd,uid,proposed,approval_bytes,
                              _hash(initial["grant_bytes"]),
                              initial["authorization_revision"])
        checkpoint(event)
    result=checkpoint_contract_rotation(
        public_fd,private_fd,approved_pin_bytes,approval_bytes,uid,
        key,external,initial,inside)
    fresh=_fixed_evidence(private_fd,uid,proposed,approval_bytes,external)
    if fresh!=initial or online.installed()!=(external,key):
        _deny()
    # Recheck claim even for idempotent same-byte result; no silent
    # certificate of a prior installation lacking a protected key-use claim.
    raw=_claim(private_fd,uid,proposed["epoch"])
    if raw is None: _deny()
    record=_verified_claim(raw,epoch=proposed["epoch"],
                           proposed=proposed,
                           grant_sha=_hash(initial["grant_bytes"]))
    if record!={"schema":CLAIM_SCHEMA,"epoch":proposed["epoch"],
               "host_id":proposed["host_id"],
               "installation_id":proposed["installation_id"],
               "key_sha256":_hash(base64.b64decode(
                   proposed["public_key"],validate=True)),
               "approved_pin_sha256":_hash(approved_pin_bytes),
               "approval_sha256":_hash(approval_bytes),
               "original_grant_sha256":_hash(initial["grant_bytes"]),
               "authorization_revision":initial["authorization_revision"]}:
        _deny()
    return {**result,"original_grant_sha256":_hash(initial["grant_bytes"]),
            "state_volume_id":initial["grant"]["state_volume_id"],
            "source_record_sha256":_hash(initial["source_bytes"]),
            "native_installed":False}


def checkpoint_contract_rotation(public_fd,private_fd,approved,approval,uid,
                                 key,external,original,cb):
    return checkpoint.rotate_checked_source(
        public_fd=public_fd,private_fd=private_fd,
        approved_pin_bytes=approved,approval_bytes=approval,
        independently_pinned_operator_public_key=original["operator"],
        independently_expected_operator_sha256=original["operator_sha256"],
        independently_pinned_external_public_key=key,
        independently_expected_external_sha256=external["external_key_sha256"],
        read_independent_checkpoint=online.read,
        compare_and_advance_independent_checkpoint=online.advance,
        uid=uid,checkpoint=cb)


def install_current_authority(*, approved_pin_bytes, approval_bytes):
    """One fixed native owner entry, no caller-selected trust source or path.

    Native installation must still independently verify actual wheel RECORD,
    boot/STATE, operator authority, root-only descriptor ancestry and external
    issuer nonrollbackable storage. Source must NOT activate live signing.
    """
    with _fixed_native_directories() as (pub,priv):
        return _install_source(
            public_fd=pub,private_fd=priv,
            approved_pin_bytes=approved_pin_bytes,
            approval_bytes=approval_bytes,uid=0)
