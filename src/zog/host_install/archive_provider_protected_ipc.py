"""Disabled archive-provider protected-process FD/peer/receipt source contract.

No socket listener, secret transfer service, real provider credential or STATE
mutation. Linux-only synthetic source functions; native root-control + host-
install must separately pin sender and consumer process/UID/installation.
"""
from __future__ import annotations
import array
import base64
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import struct
import uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

POLICY_SCHEMA = "zog-archive-provider-protected-ipc-policy-v1"
TRANSFER_SCHEMA = "zog-archive-provider-fd-handoff-v1"
ACK_SCHEMA = "zog-archive-provider-native-ack-v1"
ACK_DOMAIN = b"zog-archive-provider-native-ack-v1\\0"
PURPOSE = "archive-mirror-upstream-fetch"
CONSUMER = "archive-mirror"
MAX_SECRET = 65536
MAX_CONTROL = 4096
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "schema", "consumer", "purpose", "host_id", "installation_id",
    "state_volume_id", "registry_id", "scope_id", "authority_revision",
    "app_uid", "app_gid", "app_pid", "app_source_sha256",
    "boot_id", "invocation_id"
})
_TRANSFER_FIELDS = frozenset({
    "schema", "scope_id", "request_id", "delivery_id",
    "installation_id", "state_volume_id", "boot_id", "invocation_id",
    "authority_revision", "action", "purpose", "consumer"
})
_ACK_FIELDS = frozenset({
    "schema", "kind", "scope_id", "request_id", "delivery_id",
    "installation_id", "state_volume_id", "boot_id", "invocation_id",
    "authority_revision", "app_source_sha256", "sequence",
    "fresh_nonce", "witness", "signature_ed25519",
})


class ArchiveIpcHold(ValueError):
    pass


def _hold():
    raise ArchiveIpcHold("protected archive-provider IPC unavailable or uncertain")


def _uuid(value):
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _canonical(item):
    return json.dumps(item, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def validate_policy(policy):
    if (type(policy) is not dict or set(policy) != _FIELDS
            or policy["schema"] != POLICY_SCHEMA
            or policy["consumer"] != CONSUMER or policy["purpose"] != PURPOSE
            or any(not _uuid(policy[k]) for k in
                   ("host_id", "installation_id", "state_volume_id",
                    "boot_id", "invocation_id"))
            or not isinstance(policy["registry_id"], str)
            or not policy["registry_id"]
            or not isinstance(policy["scope_id"], str)
            or not _H64.fullmatch(policy["scope_id"])  # protected scope fingerprint
            or type(policy["authority_revision"]) is not int
            or policy["authority_revision"] < 1
            or type(policy["app_uid"]) is not int or policy["app_uid"] < 1
            or type(policy["app_gid"]) is not int or policy["app_gid"] < 1
            or type(policy["app_pid"]) is not int or policy["app_pid"] < 1
            or type(policy["app_source_sha256"]) is not str
            or not _SHA.fullmatch(policy["app_source_sha256"])):
        _hold()
    return policy


def validate_transfer(transfer, policy, *, handoff_state):
    policy = validate_policy(policy)
    if (type(transfer) is not dict or set(transfer) != _TRANSFER_FIELDS
            or transfer["schema"] != TRANSFER_SCHEMA
            or transfer["action"] != "deliver" or
            transfer["consumer"] != CONSUMER or transfer["purpose"] != PURPOSE
            or not _uuid(transfer["request_id"]) or
            not _uuid(transfer["delivery_id"])):
        _hold()
    for key in ("scope_id", "installation_id", "state_volume_id",
                "boot_id", "invocation_id", "authority_revision"):
        if transfer[key] != policy[key]:
            _hold()
    # Receipt comes from protected receiving owner's durable pre-install fence;
    # gateway JSON and a caller-supplied boolean are NOT native authority.
    if (type(handoff_state) is not dict or
            handoff_state.get("status") != "installing" or
            handoff_state.get("request_id") != transfer["request_id"] or
            handoff_state.get("delivery_id") != transfer["delivery_id"] or
            handoff_state.get("revoked") is not False):
        _hold()
    return transfer


def peer_from_kernel(sock, policy):
    """Kernel SO_PEERCRED only, not a caller-written claimed UID/GID."""
    policy=validate_policy(policy)
    if (sock.family != socket.AF_UNIX
            or sock.type & 0xf not in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET)):
        _hold()
    try:
        packed=sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                               struct.calcsize("3i"))
        pid,uid,gid=struct.unpack("3i",packed)
    except (OSError, ValueError, struct.error):
        _hold()
    if (pid,uid,gid)!=(policy["app_pid"],policy["app_uid"],
                       policy["app_gid"]):
        _hold()
    # Native installer must additionally bind PID start time, cgroup,
    # source executable hash, unit InvocationID and socket inode.
    return {"pid":pid, "uid":uid, "gid":gid}


def check_sealed_secret_fd(fd):
    """Accept only a private sealed finite anonymous memfd, never a path."""
    try:
        info=os.fstat(fd)
        seals=fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        required=(fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK |
                  fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        name=os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError):
        _hold()
    if (not stat.S_ISREG(info.st_mode)
            or not 1 <= info.st_size <= MAX_SECRET
            or info.st_nlink != 0
            or seals & required != required
            or not name.startswith("/memfd:")):
        _hold()
    return info.st_size


def send_synthetic_fd_once(sock, *, fd, transfer, policy, handoff_state):
    """Source test only: one SCM_RIGHTS FD, after the original durable intent.

    Native production code MUST NOT call this as an RPC method. It must verify
    original installed policy/boot/peer/ledger before transferring even 1 byte.
    """
    validate_transfer(transfer,policy,handoff_state=handoff_state)
    peer_from_kernel(sock,policy)
    check_sealed_secret_fd(fd)
    raw=_canonical(transfer)
    if len(raw)>MAX_CONTROL:
        _hold()
    try:
        n=sock.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                              array.array("i",[fd]))])
    except OSError:
        _hold()
    if n!=len(raw):
        _hold()
    return {"status":"fd-dispatched-unconfirmed",
            "delivery_id":transfer["delivery_id"]}


def receive_synthetic_fd(sock, *, policy, handoff_state):
    """One bounded FD; close every received FD on a denial or parse failure."""
    peer_from_kernel(sock,policy)
    fds=[]
    try:
        control,data,flags,address = None,None,None,None
        data,control,flags,address=sock.recvmsg(
            MAX_CONTROL+1,socket.CMSG_SPACE(16*array.array("i").itemsize),
            getattr(socket,"MSG_CMSG_CLOEXEC",0))
        for level,kind,body in control:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                _hold()
            ints=array.array("i")
            ints.frombytes(body[:len(body)//ints.itemsize*ints.itemsize])
            fds.extend(ints)
        if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or not 0<len(data)<=MAX_CONTROL or len(fds)!=1):
            _hold()
        def unique(pairs):
            result={}
            for k,v in pairs:
                if k in result:_hold()
                result[k]=v
            return result
        transfer=json.loads(data,object_pairs_hook=unique,
                            parse_constant=lambda _: _hold())
        if _canonical(transfer)!=data:
            _hold()
        validate_transfer(transfer,policy,handoff_state=handoff_state)
        check_sealed_secret_fd(fds[0])
        return transfer,fds.pop(0)
    except (OSError, ValueError, TypeError, UnicodeError):
        _hold()
    finally:
        for fd in fds:
            os.close(fd)


def verify_native_signed_ack(ack, *, policy, transfer, expected_kind,
                             fresh_nonce, minimum_sequence, attester_public_key):
    """Validate separately signed installed-byte or revocation observation.

    A signed acknowledgement is NOT authority to retry or move a secret FD.
    Native attester key/sequence must come from protected host-install state.
    """
    validate_policy(policy)
    if (type(ack) is not dict or set(ack) != _ACK_FIELDS
            or expected_kind not in ("installed", "revoked")
            or ack["schema"] != ACK_SCHEMA or ack["kind"] != expected_kind
            or not _uuid(fresh_nonce) or ack["fresh_nonce"] != fresh_nonce
            or type(minimum_sequence) is not int or minimum_sequence < 1
            or type(ack["sequence"]) is not int
            or ack["sequence"] < minimum_sequence
            or type(ack["witness"]) is not dict
            or ack["witness"] != {"status":expected_kind,
                                 "installed_bytes_verified":expected_kind=="installed"}
            or type(attester_public_key) is not bytes
            or len(attester_public_key) != 32):
        _hold()
    for key in ("scope_id", "installation_id", "state_volume_id",
                "boot_id", "invocation_id", "authority_revision",
                "app_source_sha256"):
        if ack[key]!=policy[key]:
            _hold()
    for key in ("request_id", "delivery_id"):
        if ack[key]!=transfer[key]:
            _hold()
    try:
        signature=base64.b64decode(ack["signature_ed25519"],validate=True)
        if (len(signature)!=64 or base64.b64encode(signature).decode("ascii")
                != ack["signature_ed25519"]):
            _hold()
        Ed25519PublicKey.from_public_bytes(attester_public_key).verify(
            signature,ACK_DOMAIN+_canonical({
                k:v for k,v in ack.items() if k!="signature_ed25519"}))
    except (InvalidSignature,ValueError,TypeError):
        _hold()
    return {"status":"verified-"+expected_kind+"-observation-no-redelivery",
            "sequence":ack["sequence"]}
