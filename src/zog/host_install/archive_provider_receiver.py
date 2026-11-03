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
            value["phase"] not in ("idle", "claimed", "delivered", "installing", "installed", "revoked") or
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

    def _guard(self, fd, lock, marker):
        # Root-directory entry and original lock/marker inodes must still
        # resolve to the same held objects. Privileged rename is a hard hold.
        root = _safe_fd(fd, directory=True)
        current = os.stat(self.directory, follow_symlinks=False)
        if (root.st_dev, root.st_ino) != (current.st_dev, current.st_ino):
            _hold("receiver root directory replaced")
        for name, original in (("archive-provider.lock", lock),
                               ("archive-provider-lock-identity.json", marker)):
            held = _safe_fd(original)
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
                _hold("receiver writer identity replaced")
        expected = json.loads(os.pread(marker, 8192, 0), object_pairs_hook=_unique)
        if (type(expected) is not dict or set(expected) != {
                "schema", "root_device", "root_inode",
                "lock_device", "lock_inode"} or
                expected["schema"] != "zog-archive-provider-lock-identity-v1" or
                (root.st_dev, root.st_ino) != (
                    expected["root_device"], expected["root_inode"]) or
                (os.fstat(lock).st_dev, os.fstat(lock).st_ino) != (
                    expected["lock_device"], expected["lock_inode"])):
            _hold("receiver original lock identity mismatch")

    def _open(self):
        if self.enabled is not True:
            _hold("archive receiver disabled")
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        lock = marker = None
        try:
            _safe_fd(fd, directory=True)
            fcntl.flock(fd, fcntl.LOCK_EX)
            lock = os.open("archive-provider.lock", os.O_RDWR |
                           os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            _safe_fd(lock)
            marker = os.open("archive-provider-lock-identity.json",
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=fd)
            _safe_fd(marker)
            fcntl.flock(lock, fcntl.LOCK_EX)
            self._guard(fd, lock, marker)
            return fd, lock, marker
        except BaseException:
            if marker is not None:
                os.close(marker)
            if lock is not None:
                os.close(lock)
            os.close(fd)
            raise

    @staticmethod
    def _close(fd, lock, marker):
        os.close(marker)
        os.close(lock)
        os.close(fd)

    def _persist(self, fd, lock, marker, state):
        self._guard(fd, lock, marker)
        _write(fd, "archive-provider-ledger.json", state)
        self._guard(fd, lock, marker)

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
        fd, lock, marker = self._open()
        try:
            state = _load(fd)
            if state is not None:
                if state["revoked"] or state["canonical"]["authorization_status"] == "revoked":
                    _hold("revoked ledger")
                if state["phase"] in ("claimed", "delivered", "installing"):
                    _hold("incomplete operation requires independent recovery")
                if nonce in state["nonces"]:
                    _hold("nonce replay")
                if any(row["request_id"] == request["request_id"]
                       for row in state["canonical"]["requests"]):
                    _hold("request identity already consumed")
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
            self._persist(fd, lock, marker, state)
            return {"status": "claimed", "request_id": request["request_id"]}
        finally:
            self._close(fd, lock, marker)

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
        fd, lock, marker = self._open()
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
            self._persist(fd, lock, marker, state)
            return {"status": "delivered", "delivery_id": delivered["delivery_id"]}
        finally:
            self._close(fd, lock, marker)

    def begin_install_handoff(self, *, request, delivery):
        """Irrevocably fence the actual archive consumer call BEFORE invoking it.

        A restart in 'installing' may ONLY reconcile with independent installed
        proof. It may not re-enter install_verified, even with identical bytes.
        Archive objects and pins remain untouched.
        """
        if not isinstance(request, dict) or not isinstance(delivery, dict):
            _hold("invalid archive application handoff")
        if (request.get("request_id") != delivery.get("request_id") or
                request.get("authorization_id") != delivery.get("authorization_id") or
                request.get("credential_revision") != delivery.get("credential_revision")):
            _hold("archive application handoff identity mismatch")
        fd, lock, marker = self._open()
        try:
            state = _load(fd)
            if (state is None or state["revoked"] or state["phase"] != "delivered"
                    or state["request_id"] != request.get("request_id")
                    or state["delivery_id"] != delivery.get("delivery_id")):
                _hold("archive application handoff already claimed or uncertain")
            matched = [row for row in state["canonical"]["requests"]
                       if row["request_id"] == request["request_id"]]
            if len(matched) != 1 or matched[0]["status"] != "delivered":
                _hold("canonical archive delivery not confirmed")
            # This MUST commit before the first archive consumer side effect.
            state["phase"] = "installing"
            self._persist(fd, lock, marker, state)
            return {"status": "installation-uncertain",
                    "request_id": request["request_id"],
                    "delivery_id": delivery["delivery_id"]}
        finally:
            self._close(fd, lock, marker)

    def record_receipt(self, *, receipt, request, delivery, now,
                       verify_installed_receipt=None):
        """Only a separately verified native installation may submit its receipt.

        This source-only method does not verify installed bytes or grant native
        use, and MUST NOT be wired to a production caller before owner review.
        """
        cd.validate_receipt(receipt, request, delivery, now=now)
        if not callable(verify_installed_receipt):
            _hold("missing independent installed-byte witness")
        fd, lock, marker = self._open()
        try:
            state = _load(fd)
            if (state is None or state["revoked"] or state["phase"] != "installing" or
                    state["request_id"] != request["request_id"] or
                    state["delivery_id"] != delivery["delivery_id"]):
                _hold("no verified installation checkpoint")
            # Native owner must independently attest destination bytes and
            # durable archive application receipt while this guard is held.
            # No synthetic boolean can substitute for that owner callback.
            if verify_installed_receipt(request, delivery, receipt) is not True:
                _hold("installed-byte witness denied")
            state["canonical"] = cd.record_installation(state["canonical"], receipt)
            state["phase"] = "installed"
            state["receipt_id"] = receipt["receipt_id"]
            self._persist(fd, lock, marker, state)
            return {"status": "receipt-durable", "receipt_id": receipt["receipt_id"]}
        finally:
            self._close(fd, lock, marker)

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
        fd, lock, marker = self._open()
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
            self._persist(fd, lock, marker, state)
            return {"status": "revocation-hold-durable"}
        finally:
            self._close(fd, lock, marker)
