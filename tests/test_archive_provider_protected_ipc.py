"""Linux offline SCM_RIGHTS/peer/ack regressions; never a live credential receiver."""
import base64
import copy
import fcntl
import os
import socket
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.host_install import archive_provider_protected_ipc as ipc

def identity():
    uid=os.getuid();gid=os.getgid()
    assert uid>0 and gid>0  # synthetic GitHub non-root lane
    return {"schema":ipc.POLICY_SCHEMA,"consumer":ipc.CONSUMER,"purpose":ipc.PURPOSE,
            "host_id":str(uuid.uuid4()),"installation_id":str(uuid.uuid4()),
            "state_volume_id":str(uuid.uuid4()),"registry_id":"registry-a",
            "scope_id":"a"*64,"authority_revision":8,
            "app_uid":uid,"app_gid":gid,"app_pid":os.getpid(),
            "app_source_sha256":"sha256:"+"b"*64,
            "boot_id":str(uuid.uuid4()),"invocation_id":str(uuid.uuid4())}

def operation(p):
    row={key:p[key] for key in ("host_id","registry_id","scope_id","installation_id","state_volume_id",
                                "boot_id","invocation_id","authority_revision")}
    row.update(schema=ipc.TRANSFER_SCHEMA,consumer=ipc.CONSUMER,purpose=ipc.PURPOSE,
               action="deliver",request_id=str(uuid.uuid4()),
               delivery_id=str(uuid.uuid4()))
    return row

def installed(t):
    return {"status":"installing","request_id":t["request_id"],
            "delivery_id":t["delivery_id"],"revoked":False}

def secret_fd(*,seal=True):
    fd=os.memfd_create("synthetic-archive-review",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    os.write(fd,b"synthetic-private-credential")
    os.lseek(fd,0,os.SEEK_SET)
    if seal:
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|
                    fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
    return fd

def ack(p,t,*,kind="installed",sequence=2,nonce=None,key=None):
    key=key or Ed25519PrivateKey.generate()
    nonce=nonce or str(uuid.uuid4())
    body={"schema":ipc.ACK_SCHEMA,"kind":kind,
          **{k:p[k] for k in ("host_id","registry_id","scope_id","installation_id","state_volume_id",
                              "boot_id","invocation_id","authority_revision",
                              "app_source_sha256")},
          "request_id":t["request_id"],"delivery_id":t["delivery_id"],
          "sequence":sequence,"fresh_nonce":nonce,
          "witness":{"status":kind,"installed_bytes_verified":kind=="installed"}}
    raw=ipc.ACK_DOMAIN+ipc._canonical(body)
    signed={**body,"signature_ed25519":base64.b64encode(key.sign(raw)).decode("ascii")}
    pub=key.public_key().public_bytes(serialization.Encoding.Raw,
                                       serialization.PublicFormat.Raw)
    return signed,pub,nonce

def test_real_unix_peer_and_one_sealed_fd_transfer_without_secret_in_control():
    p=identity();t=operation(p);state=installed(t)
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    fd=secret_fd()
    try:
        assert ipc.peer_from_kernel(left,p)["uid"]==os.getuid()
        assert ipc.send_synthetic_fd_once(left,fd=fd,transfer=t,
                                          policy=p,handoff_state=state)["status"]=="fd-dispatched-unconfirmed"
        observed,received=ipc.receive_synthetic_fd(right,policy=p,
                                                    handoff_state=state)
        try:
            assert observed==t
            assert os.read(received,128)==b"synthetic-private-credential"
            assert "synthetic-private-credential" not in ipc._canonical(observed).decode()
            assert fcntl.fcntl(received,fcntl.F_GETFD)&fcntl.FD_CLOEXEC
        finally:os.close(received)
    finally:
        os.close(fd);left.close();right.close()

@pytest.mark.parametrize("change",[
    lambda p:p.update(app_uid=p["app_uid"]+1),
    lambda p:p.update(app_gid=p["app_gid"]+1),
    lambda p:p.update(app_pid=p["app_pid"]+1000),
    lambda p:p.update(app_source_sha256="not-original"),
    lambda p:p.update(purpose="cloudflare-dns-01"),
    lambda p:p.update(installation_id=str(uuid.uuid4())),
])
def test_foreign_peer_and_nonselected_source_or_purpose_denied(change):
    p=identity();t=operation(p);s=installed(t);change(p)
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);fd=secret_fd()
    try:
        with pytest.raises(ipc.ArchiveIpcHold):
            ipc.send_synthetic_fd_once(a,fd=fd,transfer=t,policy=p,handoff_state=s)
    finally:
        os.close(fd);a.close();b.close()

def test_unsealed_fd_regular_disk_and_wrong_phase_denied(tmp_path):
    p=identity();t=operation(p);s=installed(t)
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    fd=secret_fd(seal=False)
    try:
        with pytest.raises(ipc.ArchiveIpcHold):
            ipc.send_synthetic_fd_once(a,fd=fd,transfer=t,policy=p,handoff_state=s)
        os.close(fd)
        path=tmp_path/"not-an-anonymous-memfd";path.write_bytes(b"secret")
        fd=os.open(path,os.O_RDONLY)
        with pytest.raises(ipc.ArchiveIpcHold):
            ipc.send_synthetic_fd_once(a,fd=fd,transfer=t,policy=p,handoff_state=s)
        os.close(fd)
        fd=secret_fd()
        with pytest.raises(ipc.ArchiveIpcHold):
            ipc.send_synthetic_fd_once(a,fd=fd,transfer=t,policy=p,
                                       handoff_state={**s,"status":"delivered"})
        with pytest.raises(ipc.ArchiveIpcHold):
            ipc.send_synthetic_fd_once(a,fd=fd,transfer=t,policy=p,
                                       handoff_state={**s,"revoked":True})
    finally:
        os.close(fd);a.close();b.close()

def test_multiple_fd_ancillary_is_rejected_without_leaking_received_handles():
    import array
    p=identity();t=operation(p);s=installed(t)
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    first=secret_fd();second=secret_fd()
    try:
        a.sendmsg([ipc._canonical(t)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                       array.array("i",[first,second]))])
        with pytest.raises(ipc.ArchiveIpcHold):
            ipc.receive_synthetic_fd(b,policy=p,handoff_state=s)
    finally:
        os.close(first);os.close(second);a.close();b.close()

def test_signed_native_install_byte_witness_and_revocation_ack_exact_binding():
    p=identity();t=operation(p)
    attester=Ed25519PrivateKey.generate()
    signed,pub,nonce=ack(p,t,key=attester)
    assert ipc.verify_native_signed_ack(
        signed,policy=p,transfer=t,expected_kind="installed",
        fresh_nonce=nonce,minimum_sequence=2,
        attester_public_key=pub)["status"]=="verified-installed-observation-no-redelivery"
    revoked,pub,nonce2=ack(p,t,key=attester,kind="revoked",sequence=3)
    assert ipc.verify_native_signed_ack(
        revoked,policy=p,transfer=t,expected_kind="revoked",
        fresh_nonce=nonce2,minimum_sequence=3,
        attester_public_key=pub)["status"]=="verified-revoked-observation-no-redelivery"
    with pytest.raises(ipc.ArchiveIpcHold):
        ipc.verify_native_signed_ack(
            revoked,policy=p,transfer=t,expected_kind="installed",
            fresh_nonce=nonce2,minimum_sequence=3,attester_public_key=pub)
    with pytest.raises(ipc.ArchiveIpcHold):
        ipc.verify_native_signed_ack(
            signed,policy=p,transfer=t,expected_kind="installed",
            fresh_nonce=nonce,minimum_sequence=3,attester_public_key=pub)

@pytest.mark.parametrize("change",[
    lambda row:row.update(host_id=str(uuid.uuid4())),
    lambda row:row.update(registry_id="foreign-registry"),
    lambda row:row.update(scope_id="f"*64),
    lambda row:row.update(installation_id=str(uuid.uuid4())),
    lambda row:row.update(state_volume_id=str(uuid.uuid4())),
    lambda row:row.update(boot_id=str(uuid.uuid4())),
    lambda row:row.update(invocation_id=str(uuid.uuid4())),
    lambda row:row.update(authority_revision=9),
    lambda row:row.update(app_source_sha256="sha256:"+"f"*64),
    lambda row:row.update(witness={"status":"installed","installed_bytes_verified":False}),
])
def test_tampered_native_ack_denied_despite_valid_original_signature(change):
    p=identity();t=operation(p);signed,pub,nonce=ack(p,t)
    altered=copy.deepcopy(signed);change(altered)
    with pytest.raises(ipc.ArchiveIpcHold):
        ipc.verify_native_signed_ack(
            altered,policy=p,transfer=t,expected_kind="installed",
            fresh_nonce=nonce,minimum_sequence=2,attester_public_key=pub)

def test_wrong_attester_nonce_and_ack_after_power_loss_is_not_send_permission():
    p=identity();t=operation(p);signed,pub,nonce=ack(p,t)
    wrong=Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    with pytest.raises(ipc.ArchiveIpcHold):
        ipc.verify_native_signed_ack(
            signed,policy=p,transfer=t,expected_kind="installed",
            fresh_nonce=nonce,minimum_sequence=2,attester_public_key=wrong)
    with pytest.raises(ipc.ArchiveIpcHold):
        ipc.verify_native_signed_ack(
            signed,policy=p,transfer=t,expected_kind="installed",
            fresh_nonce=str(uuid.uuid4()),minimum_sequence=2,attester_public_key=pub)
    # A valid old installed/revoked ack proves state, never authorizes another
    # FD send: the owner durable pre-install fence has now been consumed.
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);fd=secret_fd()
    try:
        with pytest.raises(ipc.ArchiveIpcHold):
            ipc.send_synthetic_fd_once(
                a,fd=fd,transfer=t,policy=p,
                handoff_state={"status":"installed","request_id":t["request_id"],
                               "delivery_id":t["delivery_id"],"revoked":False})
    finally:os.close(fd);a.close();b.close()
