"""Disabled archive-provider Unix IPC acceptance predicates (no listener).

Native integration must authenticate SO_PEERCRED on a connected AF_UNIX socket,
match the protected application UID/GID and root sender UID, receive exactly
one SCM_RIGHTS sealed anonymous descriptor, and attest consumer receipt from
the separately selected application owner. Source tests use ephemeral FDs.
"""
from __future__ import annotations
import array
import fcntl
import hashlib
import json
import os
import socket
import stat
import struct

SCHEMA = "zog-archive-provider-protected-ipc-v1"
PURPOSE = "archive-mirror-upstream-fetch"
CONSUMER = "archive-mirror"
MAX_SECRET = 16384
MAX_MESSAGE = 4096
LIVE_ACTIVATION = False

class IPCDenied(ValueError):
    pass

def deny(reason):
    raise IPCDenied(reason)

def validate_policy(value):
    required = {"schema","enabled","purpose","consumer","root_uid","application_uid",
                "application_gid","host_id","installation_id","state_volume_id",
                "scope_id","credential_revision","authorization_revision",
                "consumer_source_sha256","socket_path","native_accepted"}
    if type(value) is not dict or set(value) != required or value["schema"] != SCHEMA:
        deny("invalid IPC schema")
    if value["enabled"] is not False or value["native_accepted"] is not False:
        deny("native IPC is not authorized")
    if value["consumer"] != CONSUMER or value["purpose"] != PURPOSE:
        deny("wrong consumer purpose")
    if type(value["root_uid"]) is not int or value["root_uid"] != 0:
        deny("receiver must be root")
    if (type(value["application_uid"]) is not int or value["application_uid"] <= 0
        or type(value["application_gid"]) is not int or value["application_gid"] <= 0):
        deny("missing protected application user/group")
    for key in ("host_id","installation_id","state_volume_id"):
        import uuid
        try:
            if str(uuid.UUID(value[key])) != value[key]:
                deny("invalid installation identity")
        except (TypeError, ValueError, AttributeError):
            deny("invalid installation identity")
    for key in ("scope_id","consumer_source_sha256"):
        if type(value[key]) is not str or len(value[key]) != 64 or any(c not in "0123456789abcdef" for c in value[key]):
            deny("invalid pinned digest")
    for key in ("credential_revision","authorization_revision"):
        if type(value[key]) is not int or value[key] < 1:
            deny("invalid revision")
    if value["socket_path"] != "/run/zog/archive-provider-credential.sock":
        deny("socket confused with issuer or general control")
    return value

def peer_credentials(sock, *, expected_uid, expected_gid):
    if sock.family != socket.AF_UNIX or sock.type & socket.SOCK_STREAM == 0:
        deny("not a Unix stream peer")
    if type(expected_uid) is not int or type(expected_gid) is not int:
        deny("unselected peer identity")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid != expected_uid or gid != expected_gid:
        deny("peer identity does not match protected owner")
    return {"uid":uid,"gid":gid,"pid":pid}

def verify_secret_fd(fd, *, expected_size, expected_sha256):
    """No secret is copied into metadata. Do not accept filesystem descriptors."""
    if type(expected_size) is not int or not 1 <= expected_size <= MAX_SECRET:
        deny("invalid secret length")
    if type(expected_sha256) is not str or len(expected_sha256) != 64:
        deny("missing secret commitment")
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size != expected_size:
        deny("wrong descriptor type or size")
    if info.st_nlink != 0:
        deny("descriptor backed by named filesystem entry")
    if not hasattr(fcntl, "F_GET_SEALS"):
        deny("memfd sealing unavailable")
    seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
    required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    if seals & required != required:
        deny("credential FD not permanently sealed")
    data = os.pread(fd, expected_size + 1, 0)
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha256:
        deny("installed input bytes mismatch")
    return {"byte_count": expected_size, "sealed": True}  # no secret or digest exposed

def receive_single_fd(sock, *, expected_uid, expected_gid, expected_size, expected_sha256):
    """Synthetic one-message receiver; caller MUST own native authorization lock."""
    peer_credentials(sock, expected_uid=expected_uid, expected_gid=expected_gid)
    data, controls, flags, addr = sock.recvmsg(MAX_MESSAGE, socket.CMSG_SPACE(4 * 8))
    fds = []
    try:
        if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or data != b"archive-provider-fd-v1":
            deny("truncated or substituted IPC message")
        for level, kind, payload in controls:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(payload) % 4:
                deny("unexpected ancillary data")
            fds.extend(array.array("i", payload))
        if len(fds) != 1:
            deny("exactly one credential FD required")
        verify_secret_fd(fds[0], expected_size=expected_size, expected_sha256=expected_sha256)
        # Return an owned descriptor; caller closes it after consumer acknowledgement.
        return fds.pop()
    finally:
        for fd in fds:
            os.close(fd)

def validate_application_ack(ack, *, policy, request_id, delivery_id, phase,
                             witness_valid):
    """Independent consumer-origin proof MUST already have been verified."""
    validate_policy(policy)
    if phase not in ("installing","revoked"):
        deny("missing durable owner operation fence")
    required = {"schema","purpose","consumer","host_id","installation_id",
                "state_volume_id","scope_id","request_id","delivery_id",
                "credential_revision","authorization_revision","application_uid",
                "application_gid","result","bytes_witness_sha256"}
    if type(ack) is not dict or set(ack) != required or ack["schema"] != "zog-archive-provider-application-ack-v1":
        deny("invalid application ack")
    for key in ("purpose","consumer","host_id","installation_id","state_volume_id",
                "scope_id","credential_revision","authorization_revision",
                "application_uid","application_gid"):
        if ack[key] != policy[key]:
            deny("ack destination or authority mismatch")
    if ack["request_id"] != request_id or ack["delivery_id"] != delivery_id:
        deny("ack operation replay")
    if ack["result"] != ("installed" if phase == "installing" else "revoked"):
        deny("wrong ack phase")
    if (type(witness_valid) is not bool or witness_valid is not True or
        type(ack["bytes_witness_sha256"]) is not str or
        len(ack["bytes_witness_sha256"]) != 64 or
        any(c not in "0123456789abcdef" for c in ack["bytes_witness_sha256"])):
        deny("missing independent installed-byte/revocation witness")
    return {"status":"source-contract-matched","native_acceptance":False}
