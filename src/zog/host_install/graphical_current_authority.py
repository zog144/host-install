"""Source-only graphical current-signing-authority rotation coordinator.

Native protected owner MUST independently open and attest the fixed public
/etc/zog/host-deploy and separate root-private 0700 journal directories.
Neither directory is created, selected or approved by this module. There
is NO CLI, daemon route, key generation, private-key export or activation.
"""
from __future__ import annotations

import base64
import fcntl
from contextlib import contextmanager
import hashlib
import json
import os
import re
import secrets
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PIN_SCHEMA = "zog-host-deploy-graphical-chain-remote-owner-pin-v1"
APPROVAL_SCHEMA = "zog-host-install-graphical-current-key-rotation-approval-v1"
JOURNAL_SCHEMA = "zog-host-install-graphical-current-key-epoch-v1"
PUBLIC_NAME = "graphical-chain-current-owner-pin-v1.json"
PENDING_NAME = "graphical-chain-current-owner-rotation-pending-v1.json"
PRIVATE_JOURNAL = "graphical-current-authority-epoch-v1.json"
LOCK_NAME = "graphical-current-authority.lock"
FIXED_PUBLIC_PATH = "/etc/zog/host-deploy/" + PUBLIC_NAME
FIELDS = frozenset((
    "schema", "host_id", "installation_id", "lane", "lane_owner",
    "boot_id", "chain_policy_sha256", "original_catalogue_sha256",
    "public_key", "epoch", "source_revision", "monthly_pin_identity",
    "first_base_generation_id", "first_receipt_sha256", "relay_uid",
))
APPROVAL_FIELDS = frozenset((
    "schema", "host_id", "installation_id", "previous_pin_sha256",
    "new_pin_sha256", "new_epoch", "approval_id", "authorization_revision",
    "operator_signature",
))
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class RotationDenied(ValueError):
    pass


def _deny():
    raise RotationDenied("protected graphical current authority unavailable") from None


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs):
    row = {}
    for k,v in pairs:
        if k in row: _deny()
        row[k] = v
    return row


def _parse(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 8192: _deny()
    try:
        row = json.loads(raw, object_pairs_hook=_unique,
                         parse_constant=lambda _: _deny())
        if type(row) is not dict or canonical(row) != raw: _deny()
        return row
    except (ValueError, TypeError, UnicodeError, OverflowError):
        _deny()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pin(data):
    p = _parse(data)
    if set(p) != FIELDS or p.get("schema") != PIN_SCHEMA: _deny()
    if (type(p["epoch"]) is not int or not 1 <= p["epoch"] < 2**53
            or type(p["relay_uid"]) is not int or p["relay_uid"] < 1000):
        _deny()
    for f in ("host_id", "installation_id", "boot_id", "lane", "lane_owner",
              "source_revision", "monthly_pin_identity",
              "first_base_generation_id"):
        if type(p[f]) is not str or not p[f]: _deny()
    for f in ("chain_policy_sha256", "original_catalogue_sha256",
              "first_receipt_sha256"):
        if not (type(p[f]) is str and p[f].startswith("sha256:")
                and _HEX.fullmatch(p[f][7:])): _deny()
    try:
        raw = base64.b64decode(p["public_key"], validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != p["public_key"]:
            _deny()
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError):
        _deny()
    return p


def _protected_dir(fd, mode, uid):
    if type(fd) is not int or fd < 0: _deny()
    st = os.fstat(fd)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != uid
            or stat.S_IMODE(st.st_mode) != mode): _deny()


def _read(fd, name, mode, uid):
    try:
        leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                       os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(leaf)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != uid or stat.S_IMODE(st.st_mode) != mode
                or not 0 < st.st_size <= 8192):
            _deny()
        data = os.read(leaf, st.st_size+1)
        if len(data) != st.st_size: _deny()
        return data
    finally:
        os.close(leaf)


def _write_once(fd, name, data, mode):
    previous = _read(fd, name, mode, os.geteuid())
    if previous is not None:
        if previous != data: _deny()
        return
    leaf = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                   os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=fd)
    try:
        if os.write(leaf, data) != len(data): _deny()
        os.fchmod(leaf, mode)
        os.fsync(leaf)
    finally:
        os.close(leaf)
    os.fsync(fd)


def _replace(fd, name, data, mode, checkpoint):
    temp = ".graphical-authority-" + secrets.token_hex(16)
    filefd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=fd)
    try:
        if os.write(filefd, data) != len(data): _deny()
        os.fchmod(filefd, mode)
        os.fsync(filefd)
    finally:
        os.close(filefd)
    checkpoint("staged-" + name)
    os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)
    checkpoint("replaced-" + name)


def _approval(data, expected_operator_key, expected_pin_sha256, new_pin, old, *, check_previous=True):
    a = _parse(data)
    if set(a) != APPROVAL_FIELDS or a["schema"] != APPROVAL_SCHEMA: _deny()
    if (type(expected_operator_key) is not bytes
            or len(expected_operator_key) != 32
            or _sha(expected_operator_key) != expected_pin_sha256):
        _deny()
    if (a["new_pin_sha256"] != _sha(canonical(new_pin))
            or (check_previous and a["previous_pin_sha256"] !=
                (None if old is None else _sha(canonical(old))))
            or a["new_epoch"] != new_pin["epoch"]
            or a["host_id"] != new_pin["host_id"]
            or a["installation_id"] != new_pin["installation_id"]
            or type(a["authorization_revision"]) is not int
            or a["authorization_revision"] < 1):
        _deny()
    try:
        sig = base64.b64decode(a["operator_signature"], validate=True)
        unsigned = {k:v for k,v in a.items() if k != "operator_signature"}
        Ed25519PublicKey.from_public_bytes(expected_operator_key).verify(
            sig, b"zog-graphical-current-authority-rotation-v1\x00" + canonical(unsigned))
    except (ValueError, TypeError, Exception):
        _deny()
    return a


def _rotate_locked(*, public_fd, private_fd, approved_pin_bytes, approval_bytes,
                  independently_pinned_operator_public_key,
                  independently_expected_operator_sha256,
                  uid=0, checkpoint=None):
    """Synthetic-file source implementation, NOT an installed native entry.

    Native root owner must supply exact trusted dirfds/source RECORD, a
    separately approved operator pin and original signed authorization.
    No caller may choose paths or invoke this through an RPC.
    """
    if checkpoint is None: checkpoint = lambda event: None
    _protected_dir(public_fd, 0o755, uid)
    _protected_dir(private_fd, 0o700, uid)
    pin = _pin(approved_pin_bytes)
    previous_raw = _read(public_fd, PUBLIC_NAME, 0o444, uid)
    previous = None if previous_raw is None else _pin(previous_raw)
    journal_raw = _read(private_fd, PRIVATE_JOURNAL, 0o600, uid)
    journal = None if journal_raw is None else _parse(journal_raw)
    pending = _read(public_fd, PENDING_NAME, 0o444, uid)
    # Never accept missing/private-downgraded state, extra unapproved keys,
    # or an old pin made current again after private highwater advanced.
    if (journal is None) != (previous is None) and pending is None: _deny()
    if journal is not None and (set(journal) != {
            "schema","epoch","current_sha256","host_id","installation_id",
            "approval_sha256"} or journal["schema"] != JOURNAL_SCHEMA):
        _deny()
    old = previous
    if (journal is not None and pin["epoch"] == journal["epoch"]
            and pending is None):
        if (journal["current_sha256"] != _sha(approved_pin_bytes)
                or previous_raw != approved_pin_bytes or pending is not None):
            _deny()
        # Already committed same bytes; require exact original approval.
        if journal["approval_sha256"] != _sha(approval_bytes): _deny()
        _approval(approval_bytes, independently_pinned_operator_public_key,
                  independently_expected_operator_sha256, pin, None,
                  check_previous=False)
        return {"status":"same-byte", "epoch":pin["epoch"],"activated":False}
    # A pending reservation locks the old public pin; restart must use the
    # *same* operator approval and target bytes. The journal may already
    # advance while the public pin is still old.
    reservation = canonical({"schema":APPROVAL_SCHEMA,
                             "approval_sha256":_sha(approval_bytes),
                             "new_pin_sha256":_sha(approved_pin_bytes),
                             "new_epoch":pin["epoch"]})
    if pending is not None and pending != reservation: _deny()
    if journal is None:
        if previous is not None or pin["epoch"] != 1: _deny()
    elif pending is not None and journal["epoch"] == pin["epoch"]:
        # Resume a stopped update after the durable highwater advanced.
        if journal["current_sha256"] != _sha(approved_pin_bytes): _deny()
        if previous is not None and previous["epoch"] not in (pin["epoch"]-1,pin["epoch"]):
            _deny()
    else:
        if previous is None or previous["epoch"] != journal["epoch"]: _deny()
        if _sha(previous_raw) != journal["current_sha256"]: _deny()
        if pin["epoch"] != journal["epoch"]+1: _deny()
    if previous is not None:
        for k in ("host_id","installation_id","lane","lane_owner",
                  "chain_policy_sha256","first_base_generation_id"):
            if previous[k] != pin[k]: _deny()
        if (previous["epoch"] < pin["epoch"]
                and previous["public_key"] == pin["public_key"]): _deny()
    old_for_approval = previous if previous and previous["epoch"] < pin["epoch"] else None
    approved = _approval(approval_bytes, independently_pinned_operator_public_key,
                         independently_expected_operator_sha256, pin, old_for_approval,
                         check_previous=not (pending is not None and journal is not None
                                             and journal["epoch"] == pin["epoch"]
                                             and previous is not None
                                             and previous["epoch"] == pin["epoch"]))
    if pending is not None and journal is not None and journal["epoch"] == pin["epoch"]:
        if journal["approval_sha256"] != _sha(approval_bytes): _deny()
    _write_once(public_fd, PENDING_NAME, reservation, 0o444)
    checkpoint("pending")
    state = {"schema":JOURNAL_SCHEMA,"epoch":pin["epoch"],
             "current_sha256":_sha(approved_pin_bytes),
             "host_id":pin["host_id"],"installation_id":pin["installation_id"],
             "approval_sha256":_sha(approval_bytes)}
    if journal != state:
        _replace(private_fd, PRIVATE_JOURNAL, canonical(state), 0o600, checkpoint)
    checkpoint("epoch")
    if previous_raw != approved_pin_bytes:
        _replace(public_fd, PUBLIC_NAME, approved_pin_bytes, 0o444, checkpoint)
    checkpoint("public")
    if (_read(public_fd, PUBLIC_NAME, 0o444, uid) != approved_pin_bytes
            or _read(private_fd, PRIVATE_JOURNAL, 0o600, uid) != canonical(state)):
        _deny()
    # Remove only the identical reservation, never an unrelated authority.
    if _read(public_fd, PENDING_NAME, 0o444, uid) != reservation: _deny()
    os.unlink(PENDING_NAME, dir_fd=public_fd)
    os.fsync(public_fd)
    checkpoint("complete")
    return {"status":"source-committed","epoch":pin["epoch"],"activated":False}


def current_source_read(*, public_fd, uid=0):
    """Reader parity: neither an interrupted nor an old authority may pass."""
    _protected_dir(public_fd, 0o755, uid)
    if _read(public_fd, PENDING_NAME, 0o444, uid) is not None: _deny()
    value = _read(public_fd, PUBLIC_NAME, 0o444, uid)
    if value is None: _deny()
    pin = _pin(value)
    if _read(public_fd, PENDING_NAME, 0o444, uid) is not None: _deny()
    return pin



@contextmanager
def _stable_lock(private_fd, uid):
    """Stable inode never unlinked, shared by every authorized writer."""
    try:
        try:
            lockfd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT |
                             os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=private_fd)
            os.fchmod(lockfd, 0o600)
            os.fsync(lockfd)
            os.fsync(private_fd)
        except FileExistsError:
            lockfd = os.open(LOCK_NAME, os.O_RDWR |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=private_fd)
        st = os.fstat(lockfd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != uid or stat.S_IMODE(st.st_mode) != 0o600):
            _deny()
        fcntl.flock(lockfd, fcntl.LOCK_EX)
        by_name = os.stat(LOCK_NAME, dir_fd=private_fd, follow_symlinks=False)
        if (by_name.st_dev, by_name.st_ino) != (st.st_dev, st.st_ino):
            _deny()
        yield
    finally:
        if "lockfd" in locals():
            fcntl.flock(lockfd, fcntl.LOCK_UN)
            os.close(lockfd)


def rotate_source(*, public_fd, private_fd, approved_pin_bytes, approval_bytes,
                  independently_pinned_operator_public_key,
                  independently_expected_operator_sha256,
                  uid=0, checkpoint=None):
    """Exclusive source transaction; no production fixed-path opener/activation."""
    _protected_dir(public_fd, 0o755, uid)
    _protected_dir(private_fd, 0o700, uid)
    with _stable_lock(private_fd, uid):
        return _rotate_locked(
            public_fd=public_fd, private_fd=private_fd,
            approved_pin_bytes=approved_pin_bytes, approval_bytes=approval_bytes,
            independently_pinned_operator_public_key=independently_pinned_operator_public_key,
            independently_expected_operator_sha256=independently_expected_operator_sha256,
            uid=uid, checkpoint=checkpoint)
