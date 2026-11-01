"""Fixed independently authenticated graphical checkpoint transport.

The external issuer is a *separate* rollback domain, not local STATE. Only
the independently protected installer may provision FIXED_PIN and the
separate issuer/relay. This module never creates pins, sockets or authority.

No checkpoint callback or user-selected destination is accepted here.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct

from . import graphical_current_authority as local

FIXED_PIN = "/etc/zog/host-deploy/graphical-external-checkpoint-pin-v1.json"
FIXED_SOCKET = "/run/zog/host-deploy/graphical-external-checkpoint.sock"
PIN_SCHEMA = "zog-host-install-external-checkpoint-relay-pin-v1"
READ_SCHEMA = "zog-graphical-external-checkpoint-read-v1"
CAS_SCHEMA = "zog-graphical-external-checkpoint-cas-v1"
PIN_FIELDS = frozenset(("schema", "host_id", "installation_id",
                         "external_public_key", "external_key_sha256", "relay_uid"))
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX = 8192


def _deny():
    local._deny()


def _pin():
    """No-follow root-owned ancestry, exact 0444 installed immutable pin."""
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        parts = Path(FIXED_PIN).parts[1:]
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW |
                            os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=current)
            os.close(current)
            current = child
            st = os.fstat(current)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                _deny()
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                       os.O_CLOEXEC, dir_fd=current)
        try:
            st = os.fstat(leaf)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
                    or stat.S_IMODE(st.st_mode) != 0o444 or st.st_nlink != 1
                    or not 0 < st.st_size <= MAX):
                _deny()
            raw = os.read(leaf, MAX+1)
            if len(raw) != st.st_size: _deny()
        finally:
            os.close(leaf)
    except OSError:
        _deny()
    finally:
        os.close(current)
    pin = local._parse(raw)
    if set(pin) != PIN_FIELDS or pin["schema"] != PIN_SCHEMA: _deny()
    if (type(pin["host_id"]) is not str or not pin["host_id"]
            or type(pin["installation_id"]) is not str or not pin["installation_id"]
            or type(pin["relay_uid"]) is not int or
            not 1000 <= pin["relay_uid"] < 2**31
            or type(pin["external_key_sha256"]) is not str
            or HEX.fullmatch(pin["external_key_sha256"]) is None):
        _deny()
    try:
        key = base64.b64decode(pin["external_public_key"],validate=True)
    except (ValueError, TypeError):
        _deny()
    if (len(key)!=32 or base64.b64encode(key).decode("ascii") !=
            pin["external_public_key"] or
            hashlib.sha256(key).hexdigest() != pin["external_key_sha256"]):
        _deny()
    return pin, key


def _exchange(message, *, expected_uid):
    """Relay is untrusted transport; signed nonce response is authority."""
    if type(message) is not dict or type(expected_uid) is not int:
        _deny()
    raw = local.canonical(message)
    if len(raw) > MAX: _deny()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(3.0)
            peer.connect(FIXED_SOCKET)
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", credentials)
            if uid != expected_uid: _deny()
            peer.sendall(raw + b"\n")
            result = bytearray()
            while len(result) <= MAX:
                part = peer.recv(min(4096, MAX+1-len(result)))
                if not part: break
                result.extend(part)
            if not result or len(result) > MAX: _deny()
            return bytes(result).strip()
    except OSError:
        _deny()


def installed():
    """Only fixed protected independent issuer identity is ever returned."""
    return _pin()


def read(nonce):
    pin, key = installed()
    if (type(nonce) is not str or
            re.fullmatch(r"[a-f0-9]{48}", nonce) is None):
        _deny()
    return _exchange({
        "schema": READ_SCHEMA, "nonce": nonce,
        "host_id": pin["host_id"], "installation_id": pin["installation_id"]
    }, expected_uid=pin["relay_uid"])


def advance(*, expected_epoch, expected_sequence, expected_pin_sha256,
            next_epoch, next_pin_sha256, next_approval_sha256,
            host_id, installation_id):
    pin, _key = installed()
    if host_id != pin["host_id"] or installation_id != pin["installation_id"]:
        _deny()
    if (type(expected_epoch) is not int or type(expected_sequence) is not int
            or type(next_epoch) is not int or next_epoch != expected_epoch+1
            or type(next_pin_sha256) is not str or
            HEX.fullmatch(next_pin_sha256) is None
            or type(next_approval_sha256) is not str or
            HEX.fullmatch(next_approval_sha256) is None
            or expected_pin_sha256 is not None and (
                type(expected_pin_sha256) is not str or
                HEX.fullmatch(expected_pin_sha256) is None)):
        _deny()
    # A reply to CAS isn't trusted as a checkpoint: the caller MUST demand
    # a new, distinct signed nonce-bound read before local publication.
    reply = _exchange({
        "schema": CAS_SCHEMA,
        "expected_epoch": expected_epoch,
        "expected_sequence": expected_sequence,
        "expected_pin_sha256": expected_pin_sha256,
        "next_epoch": next_epoch,
        "next_pin_sha256": next_pin_sha256,
        "next_approval_sha256": next_approval_sha256,
        "host_id": host_id,
        "installation_id": installation_id
    }, expected_uid=pin["relay_uid"])
    if reply != b'{"schema":"zog-graphical-external-checkpoint-cas-ack-v1"}':
        _deny()
