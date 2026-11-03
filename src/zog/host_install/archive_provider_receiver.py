"""Disabled archive-provider receiving-owner core, OFFLINE SOURCE ONLY.

There is deliberately no entrypoint, HTTP client/listener or credential writer.
The native owner must supply independently pinned public keys and exact current
authority/role evidence. Private secrets never enter this ledger. This class
does not grant authority to call archive-mirror.install_verified.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import stat
import uuid

from zog.host_identify import archive_credentials as archive
from zog.host_identify import credential_delivery as cd

CONSUMER = "archive-mirror"
PURPOSE = "archive-mirror-upstream-fetch"
SCHEMA = "zog-archive-provider-offline-receiver-ledger-v1"
MAX_LEDGER = 131072


class ReceiverHold(ValueError):
    pass


def _hold(reason):
    raise ReceiverHold(reason)


def _safe_fd(fd, *, directory=False):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or (
            not stat.S_ISDIR(info.st_mode) if directory else
            not stat.S_ISREG(info.st_mode)):
        _hold("unsafe owner/type")
    if stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        _hold("unsafe permissions")
    if not directory and info.st_nlink != 1:
        _hold("unsafe link count")
    return info


def _read(fd, name):
    try:
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        info = _safe_fd(f)
        if info.st_size > MAX_LEDGER:
            _hold("oversized ledger")
        raw = os.read(f, MAX_LEDGER + 1)
        if len(raw) != info.st_size:
            _hold("invalid ledger length")
        return json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, TypeError):
        _hold("invalid protected ledger")
    finally:
        os.close(f)


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            _hold("duplicate ledger key")
        result[key] = value
    return result


def _write(fd, name, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(raw) > MAX_LEDGER:
        _hold("ledger too large")
    temp = "." + name + "." + uuid.uuid4().hex
    f = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        _safe_fd(f)
        view = memoryview(raw)
        while view:
            n = os.write(f, view)
            if n < 1:
                _hold("short ledger write")
            view = view[n:]
        os.fsync(f)
    finally:
        os.close(f)
    try:
        os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temp, dir_fd=fd)
        except FileNotFoundError:
            pass


def _load(fd):
    value = _read(fd, "archive-provider-ledger.json")
    if value is None:
        return None
    if type(value) is not dict or set(value) != {
            "schema", "canonical", "nonces", "phase", "request_id",
            "delivery_id", "receipt_id", "revoked"} or value["schema"] != SCHEMA:
        _hold("invalid receiver ledger")
    cd.validate_ledger(value["canonical"])
    if (type(value["nonces"]) is not list or
            len(value["nonces"]) > cd.MAX_REQUESTS or
            len(set(value["nonces"])) != len(value["nonces"]) or
            not all(type(n) is str and n for n in value["nonces"]) or
            value["phase"] not in ("idle", "claimed", "delivered", "installed", "revoked") or
            type(value["revoked"]) is not bool):
        _hold("invalid receiver state")
    for key in ("request_id", "delivery_id", "receipt_id"):
        if value[key] is not None:
            try:
                if str(uuid.UUID(value[key])) != value[key]:
                    _hold("invalid identity")
            except (TypeError, ValueError, AttributeError):
                _hold("invalid identity")
    if value["revoked"] != (value["phase"] == "revoked"):
        _hold("inconsistent revocation")
    return value


class OfflineArchiveReceiver:
    """Owner-locked operations only; source tests use a disposable 0700 dir."""

    def __init__(self, directory, *, enabled=False):
        self.directory = Path(directory)
        self.enabled = enabled

    def _open(self):
        if self.enabled is not True:
            _hold("archive receiver disabled")
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _safe_fd(fd, directory=True)
            lock = os.open("archive-provider.lock", os.O_RDWR |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                _safe_fd(lock)
                fcntl.flock(lock, fcntl.LOCK_EX)
                ls = os.stat("archive-provider.lock", dir_fd=fd,
                             follow_symlinks=False)
                original = os.fstat(lock)
                if (ls.st_dev, ls.st_ino) != (original.st_dev, original.st_ino):
                    _hold("writer lock substituted")
                return fd, lock
            except BaseException:
                os.close(lock)
                raise
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _close(fd, lock):
        os.close(lock)
        os.close(fd)

    @staticmethod
    def _match(value, expected):
        if archive.provider_scope(value) != archive.provider_scope(expected):
            _hold("archive destination changed")

    @staticmethod
    def _authority(scope, envelope, key, issuer, now):
        auth = archive.verify_provider_authorization(
            envelope, key, expected_issuer=issuer, scope=scope, now=now)
        if auth["status"] != "approved":
            _hold("authorization revoked")
        return auth

    def claim(self, *, scope, expected_scope, signed_authorization,
              authority_public_key, expected_issuer, url, method,
              headers, body, host_public_key, now):
        """Verify source signatures; durably claim request/nonce before delivery."""
        self._match(scope, expected_scope)
        auth = self._authority(scope, signed_authorization,
                               authority_public_key, expected_issuer, now)
        request, nonce, _expiry = cd.verify_request_http(
            url, method, headers, body, host_public_key, auth, now=now)
        if cd.binding(request) != archive.provider_binding(scope):
            _hold("wrong consumer or purpose")
        fd, lock = self._open()
        try:
            state = _load(fd)
            if state is not None:
                if state["revoked"] or state["canonical"]["authorization_status"] == "revoked":
                    _hold("revoked ledger")
                if state["phase"] in ("claimed", "delivered"):
                    _hold("incomplete operation requires independent recovery")
                if nonce in state["nonces"]:
                    _hold("nonce replay")
                canonical = cd.advance_authorization(state["canonical"], auth)
            else:
                canonical = cd.new_ledger(auth)
                state = {"schema": SCHEMA, "canonical": canonical, "nonces": [],
                         "phase": "idle", "request_id": None, "delivery_id": None,
                         "receipt_id": None, "revoked": False}
            canonical = cd.admit_request(canonical, request)
            state["canonical"] = canonical
            state["nonces"].append(nonce)
            state["phase"] = "claimed"
            state["request_id"] = request["request_id"]
            state["delivery_id"] = None
            state["receipt_id"] = None
            _write(fd, "archive-provider-ledger.json", state)
            return {"status": "claimed", "request_id": request["request_id"]}
        finally:
            self._close(fd, lock)

    def verify_and_record_delivery(self, *, scope, expected_scope,
                                   signed_authorization, authority_public_key,
                                   expected_issuer, request,
                                   signed_delivery, now):
        """Record a verified one-time delivery, never decode or install secret."""
        self._match(scope, expected_scope)
        auth = self._authority(scope, signed_authorization,
                               authority_public_key, expected_issuer, now)
        cd.validate_request(request, auth, now=now)
        delivered = cd.verify_delivery(
            signed_delivery, authority_public_key, request, auth, now=now)
        archive.validate_delivery(scope, auth, request, delivered, now=now)
        fd, lock = self._open()
        try:
            state = _load(fd)
            if state is None or state["revoked"] or state["phase"] != "claimed":
                _hold("missing or interrupted claim")
            if state["request_id"] != request["request_id"]:
                _hold("request identity mismatch")
            canonical = cd.advance_authorization(state["canonical"], auth)
            canonical = cd.record_delivery(canonical, delivered)
            state["canonical"] = canonical
            state["phase"] = "delivered"
            state["delivery_id"] = delivered["delivery_id"]
            _write(fd, "archive-provider-ledger.json", state)
            return {"status": "delivered", "delivery_id": delivered["delivery_id"]}
        finally:
            self._close(fd, lock)

    def record_receipt(self, *, receipt, request, delivery, now):
        """Only a separately verified native installation may submit its receipt.

        This source-only method does not verify installed bytes or grant native
        use, and MUST NOT be wired to a production caller before owner review.
        """
        cd.validate_receipt(receipt, request, delivery, now=now)
        fd, lock = self._open()
        try:
            state = _load(fd)
            if (state is None or state["revoked"] or state["phase"] != "delivered" or
                    state["request_id"] != request["request_id"] or
                    state["delivery_id"] != delivery["delivery_id"]):
                _hold("no verified installation checkpoint")
            state["canonical"] = cd.record_installation(state["canonical"], receipt)
            state["phase"] = "installed"
            state["receipt_id"] = receipt["receipt_id"]
            _write(fd, "archive-provider-ledger.json", state)
            return {"status": "receipt-durable", "receipt_id": receipt["receipt_id"]}
        finally:
            self._close(fd, lock)

    def hold_revoked(self, *, scope, expected_scope, signed_authorization,
                     authority_public_key, expected_issuer, now):
        """Persist signed current revocation before archive-local tombstone.

        Does not call archive-mirror.apply_signed_revocation: separate owner
        must attest that action, then persist an independently verified receipt.
        """
        self._match(scope, expected_scope)
        auth = archive.verify_provider_authorization(
            signed_authorization, authority_public_key,
            expected_issuer=expected_issuer, scope=scope, now=now)
        if auth["status"] != "revoked":
            _hold("not a signed revocation")
        fd, lock = self._open()
        try:
            state = _load(fd)
            if state is None:
                canonical = cd.new_ledger(auth)
                state = {"schema": SCHEMA, "canonical": canonical, "nonces": [],
                         "phase": "idle", "request_id": None,
                         "delivery_id": None, "receipt_id": None,
                         "revoked": False}
            else:
                canonical = cd.advance_authorization(state["canonical"], auth)
            state["canonical"] = canonical
            state["phase"] = "revoked"
            state["revoked"] = True
            _write(fd, "archive-provider-ledger.json", state)
            return {"status": "revocation-hold-durable"}
        finally:
            self._close(fd, lock)
