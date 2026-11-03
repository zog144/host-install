import array
import fcntl
import hashlib
import os
import socket
import uuid
import pytest
from zog.host_install import archive_provider_ipc_contract as ipc

def policy():
    return dict(schema=ipc.SCHEMA, enabled=False, native_accepted=False,
        purpose=ipc.PURPOSE, consumer=ipc.CONSUMER, root_uid=0,
        application_uid=2345, application_gid=2346,
        host_id=str(uuid.uuid4()), installation_id=str(uuid.uuid4()),
        state_volume_id=str(uuid.uuid4()), scope_id="a"*64,
        credential_revision=3, authorization_revision=4,
        consumer_source_sha256="b"*64,
        socket_path="/run/zog/archive-provider-credential.sock")

def sealed(data=b"synthetic-only"):
    fd=os.memfd_create("archive-provider-test", os.MFD_ALLOW_SEALING)
    os.write(fd,data)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    return fd

def test_policy_disabled_and_archive_only():
    good=policy()
    assert ipc.validate_policy(good)["enabled"] is False
    for key,value in [("enabled",True),("native_accepted",True),
        ("purpose","issuer-cloudflare-dns01"),("consumer","certify-manage"),
        ("root_uid",1000),("application_uid",0),("application_gid",0),
        ("socket_path","/run/zog/root-control.sock"),
        ("credential_revision",0),("scope_id","forged")]:
        other={**good,key:value}
        with pytest.raises(ipc.IPCDenied):
            ipc.validate_policy(other)

def test_peer_credentials_and_exact_single_fd():
    left,right=socket.socketpair()
    data=b"synthetic-only"
    fd=sealed(data)
    try:
        uid,gid=os.getuid(),os.getgid()
        assert ipc.peer_credentials(right,expected_uid=uid,expected_gid=gid)["uid"]==uid
        with pytest.raises(ipc.IPCDenied):
            ipc.peer_credentials(right,expected_uid=uid+1,expected_gid=gid)
        left.sendmsg([b"archive-provider-fd-v1"],
                     [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd]))])
        received=ipc.receive_single_fd(right,expected_uid=uid,
            expected_gid=gid,expected_size=len(data),
            expected_sha256=hashlib.sha256(data).hexdigest())
        try:
            assert os.pread(received,len(data),0)==data
        finally:
            os.close(received)
    finally:
        os.close(fd);left.close();right.close()

def test_double_fd_rejected_without_leak():
    left,right=socket.socketpair()
    fd=sealed()
    try:
        left.sendmsg([b"archive-provider-fd-v1"],[
            (socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[fd,fd]))])
        with pytest.raises(ipc.IPCDenied,match="exactly one"):
            ipc.receive_single_fd(right,expected_uid=os.getuid(),expected_gid=os.getgid(),
                expected_size=14,expected_sha256="a"*64)
    finally:
        os.close(fd);left.close();right.close()

def test_named_unsealed_or_wrong_digest_fd_rejected(tmp_path):
    fd=sealed()
    try:
        with pytest.raises(ipc.IPCDenied,match="mismatch"):
            ipc.verify_secret_fd(fd,expected_size=14,expected_sha256="0"*64)
    finally: os.close(fd)
    f=tmp_path/"named";f.write_bytes(b"synthetic-only")
    with f.open("rb") as handle:
        with pytest.raises(ipc.IPCDenied,match="named filesystem"):
            ipc.verify_secret_fd(handle.fileno(),expected_size=14,
                                 expected_sha256=hashlib.sha256(b"synthetic-only").hexdigest())
    unsealed=os.memfd_create("unsealed")
    try:
        os.write(unsealed,b"synthetic-only")
        with pytest.raises(ipc.IPCDenied,match="not permanently sealed"):
            ipc.verify_secret_fd(unsealed,expected_size=14,
                                 expected_sha256=hashlib.sha256(b"synthetic-only").hexdigest())
    finally: os.close(unsealed)

def test_ack_exact_identity_and_operation_and_witness():
    p=policy()
    req,delivery=str(uuid.uuid4()),str(uuid.uuid4())
    ack=dict(schema="zog-archive-provider-application-ack-v1",
             **{k:p[k] for k in ("purpose","consumer","host_id","installation_id",
                 "state_volume_id","scope_id","credential_revision","authorization_revision",
                 "application_uid","application_gid")},
             request_id=req,delivery_id=delivery,result="installed",
             bytes_witness_sha256="f"*64)
    def verify(v, phase="installing", witness=True):
        return ipc.validate_application_ack(v,policy=p,request_id=req,
            delivery_id=delivery,phase=phase,witness_valid=witness)
    assert verify(ack)["native_acceptance"] is False
    for key,value in [("scope_id","0"*64),("installation_id",str(uuid.uuid4())),
        ("application_gid",p["application_gid"]+1),("request_id",str(uuid.uuid4())),
        ("purpose","issuer-cloudflare-dns01"),("result","revoked"),
        ("bytes_witness_sha256","forged")]:
        with pytest.raises(ipc.IPCDenied):
            verify({**ack,key:value})
    with pytest.raises(ipc.IPCDenied):
        verify(ack,witness=False)
    with pytest.raises(ipc.IPCDenied):
        verify(ack,phase="delivered")
    revoked={**ack,"result":"revoked"}
    assert verify(revoked,phase="revoked")["native_acceptance"] is False
