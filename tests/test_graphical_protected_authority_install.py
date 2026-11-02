"""Source-only protected graphical installer + fixed checkpoint synthetic tests."""
import base64
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from zog.host_install import graphical_current_authority as g
from zog.host_install import graphical_checkpoint_transport as transport
from zog.host_install import graphical_protected_authority_install as protected
from test_graphical_current_authority import pin,approval,public
from test_graphical_rotation_checkpoint import Remote

def put(path,raw):
    path.write_bytes(raw)
    path.chmod(0o600)

@pytest.fixture
def authority(tmp_path,monkeypatch):
    pub=tmp_path/"public"
    private=tmp_path/"original-private"
    pub.mkdir(mode=0o755);private.mkdir(mode=0o700)
    pub.chmod(0o755);private.chmod(0o700)
    fd_pub=os.open(pub,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fd_private=os.open(private,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    operator=Ed25519PrivateKey.generate()
    identity=Ed25519PrivateKey.generate()
    keys=[Ed25519PrivateKey.generate() for _ in range(3)]
    remote=Remote(pin(keys[0],1))
    remote_key=public(remote.signer)
    anchor={
        "schema":transport.PIN_SCHEMA,"host_id":"host-approved",
        "installation_id":"installation-approved",
        "external_key_sha256":g._sha(remote_key),
        "relay_uid":21001,
        "external_public_key":base64.b64encode(remote_key).decode(),
    }
    monkeypatch.setattr(transport,"installed",lambda:(anchor,remote_key))
    monkeypatch.setattr(transport,"read",remote.read)
    monkeypatch.setattr(transport,"advance",remote.advance)
    operator_pub=public(operator)
    op_pin={
        "schema":protected.OPERATOR_SCHEMA,
        "public_key":base64.b64encode(operator_pub).decode(),
        "sha256":g._sha(operator_pub),
    }
    put(private/protected.OPERATOR_PIN,g.canonical(op_pin))
    identity_pub=public(identity)
    put(private/protected.IDENTITY_PIN,g.canonical({
        "schema":protected.IDENTITY_SCHEMA,
        "public_key":base64.b64encode(identity_pub).decode(),
        "sha256":g._sha(identity_pub)}))
    unsigned={
        "schema":protected.GRANT_SCHEMA,
        "host_id":"host-approved","installation_id":"installation-approved",
        "state_volume_id":"state-approved","chain_policy_sha256":"sha256:"+"a"*64,
        "source_revision":"c"*40,"wheel_record_sha256":"b"*64,
        "operator_key_sha256":g._sha(operator_pub),
        "external_key_sha256":g._sha(remote_key),
        "authorization_revision":1,
    }
    proof=identity.sign(protected.GRANT_DOMAIN+g.canonical(unsigned))
    grant=g.canonical({**unsigned,"signature_ed25519":
        base64.b64encode(proof).decode()})
    put(private/protected.ORIGINAL_GRANT,grant)
    source={
        "schema":protected.SOURCE_SCHEMA,
        "host_id":unsigned["host_id"],
        "installation_id":unsigned["installation_id"],
        "state_volume_id":unsigned["state_volume_id"],
        "source_revision":unsigned["source_revision"],
        "wheel_record_sha256":unsigned["wheel_record_sha256"],
        "original_grant_sha256":g._sha(grant),
    }
    put(private/protected.SOURCE_ATTESTATION,g.canonical(source))
    def args(epoch):
        nxt=pin(keys[epoch-1],epoch)
        old=pin(keys[epoch-2],epoch-1) if epoch>1 else None
        return {
            "public_fd":fd_pub,"private_fd":fd_private,
            "approved_pin_bytes":g.canonical(nxt),
            "approval_bytes":approval(operator,nxt,old),
            "uid":os.geteuid(),
        }
    def install(epoch,**kwargs):
        return protected._install_source(**args(epoch),**kwargs)
    install.original_identity_signer=identity
    yield install,args,pub,private,remote,operator,keys,(fd_pub,fd_private)
    os.close(fd_pub);os.close(fd_private)

def test_original_signed_install_rotation_and_same_byte(authority):
    install,args,pub,priv,remote,_,keys,_=authority
    first=install(1)
    assert first["epoch"]==1 and first["native_installed"] is False
    assert first["state_volume_id"]=="state-approved"
    assert install(1)["status"]=="same-byte-external-checked"
    assert install(2)["epoch"]==2
    assert g.current_source_read(public_fd=args(1)["public_fd"],
                                 uid=os.geteuid())["epoch"]==2
    with pytest.raises(g.RotationDenied):install(1)
    assert remote.epoch==2

def test_retired_older_key_cannot_return_as_new_epoch(authority):
    install,args,pub,priv,remote,operator,keys,fds=authority
    install(1);install(2)
    # New signed approval from same approved operator cannot return a key
    # already used in epoch 1, even if a fresh external epoch exists.
    old_key_pin=pin(keys[0],3)
    revision3=approval(operator,old_key_pin,pin(keys[1],2))
    with pytest.raises(g.RotationDenied):
        protected._install_source(
            public_fd=fds[0],private_fd=fds[1],
            approved_pin_bytes=g.canonical(old_key_pin),
            approval_bytes=revision3,uid=os.geteuid())
    assert remote.epoch==2
    assert not (pub/g.PENDING_NAME).exists()

@pytest.mark.parametrize("event",[
    "pending","external-advance",
    "staged-"+g.PRIVATE_JOURNAL,"replaced-"+g.PRIVATE_JOURNAL,
    "staged-"+g.PUBLIC_NAME,"replaced-"+g.PUBLIC_NAME,
])
def test_interrupted_protected_rotation_resumes_only_same_approval(authority,event):
    install,args,pub,priv,remote,operator,keys,_=authority
    install(1)
    def interrupt(point):
        if point==event:raise RuntimeError("simulated crash")
    with pytest.raises(RuntimeError):
        install(2,checkpoint=interrupt)
    assert (pub/g.PENDING_NAME).exists()
    with pytest.raises(g.RotationDenied):
        g.current_source_read(public_fd=args(1)["public_fd"],uid=os.geteuid())
    assert install(2)["epoch"]==2
    assert not (pub/g.PENDING_NAME).exists()
    assert remote.epoch==2
    assert install(2)["status"]=="same-byte-external-checked"

def test_operator_key_and_original_source_or_state_substitution_denied(authority):
    install,args,pub,priv,remote,operator,keys,_=authority
    identity_path=priv/protected.IDENTITY_PIN
    original_identity=identity_path.read_bytes()
    other_identity=Ed25519PrivateKey.generate()
    put(identity_path,g.canonical({
        "schema":protected.IDENTITY_SCHEMA,
        "public_key":base64.b64encode(public(other_identity)).decode(),
        "sha256":g._sha(public(other_identity))}))
    with pytest.raises(g.RotationDenied):install(1)
    put(identity_path,original_identity)
    old=(priv/protected.OPERATOR_PIN).read_bytes()
    other=Ed25519PrivateKey.generate()
    put(priv/protected.OPERATOR_PIN,g.canonical({
        "schema":protected.OPERATOR_SCHEMA,
        "public_key":base64.b64encode(public(other)).decode(),
        "sha256":g._sha(public(other))}))
    with pytest.raises(g.RotationDenied):install(1)
    assert remote.epoch==0
    put(priv/protected.OPERATOR_PIN,old)
    source=priv/protected.SOURCE_ATTESTATION
    previous=source.read_bytes()
    altered=g._parse(previous)
    altered["state_volume_id"]="fabricated"
    put(source,g.canonical(altered))
    with pytest.raises(g.RotationDenied):install(1)
    put(source,previous)
    grant=priv/protected.ORIGINAL_GRANT
    untrusted=grant.read_bytes()
    grant.unlink()
    grant.symlink_to(source)
    with pytest.raises((g.RotationDenied,OSError)):install(1)
    grant.unlink()
    put(grant,untrusted)
    assert install(1)["epoch"]==1

def test_missing_identity_or_external_refuses_publication(authority,monkeypatch):
    install,args,pub,priv,remote,*_=authority
    original=priv/protected.ORIGINAL_GRANT
    removed=original.read_bytes()
    original.unlink()
    with pytest.raises(g.RotationDenied):install(1)
    assert not (pub/g.PUBLIC_NAME).exists()
    put(original,removed)
    remote.available=False
    with pytest.raises((g.RotationDenied,OSError)):install(1)
    assert not (pub/g.PUBLIC_NAME).exists()
    remote.available=True

def test_concurrent_protected_rotation_single_monotonic_epoch(authority):
    install,args,pub,priv,remote,*_=authority
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(lambda _:install(1),range(3)))
    assert sorted(r["status"] for r in results)==[
        "same-byte-external-checked","same-byte-external-checked",
        "source-committed"]
    assert remote.epoch==1
    assert len(list(priv.glob(protected.CLAIM_PREFIX+"*.json")))==1

def test_claim_reservation_precedes_external_commit_and_no_replacement(authority):
    install,args,pub,priv,remote,*_=authority
    def stop(point):
        if point=="pending":raise RuntimeError("lost just after durable claim")
    with pytest.raises(RuntimeError):install(1,checkpoint=stop)
    assert remote.epoch==0
    assert (pub/g.PENDING_NAME).exists()
    claims=list(priv.glob(protected.CLAIM_PREFIX+"*.json"))
    assert len(claims)==1
    assert install(1)["epoch"]==1
    claims[0].unlink()
    with pytest.raises(g.RotationDenied):
        install(1) # cannot bless a same-byte install with missing claim

def test_fixed_native_entry_has_no_caller_selected_trust_or_path(authority):
    install,args,pub,priv,remote,*_,fds=authority
    with pytest.raises(TypeError):
        protected.install_current_authority(
            approved_pin_bytes=args(1)["approved_pin_bytes"],
            approval_bytes=args(1)["approval_bytes"],
            public_fd=fds[0])
    if os.geteuid()!=0:
        with pytest.raises(g.RotationDenied):
            protected.install_current_authority(
                approved_pin_bytes=args(1)["approved_pin_bytes"],
                approval_bytes=args(1)["approval_bytes"])
    else:
        @contextmanager
        def synthetic():
            yield fds
        # Only simulate the fixed root directory provider, not real /etc.
        from unittest.mock import patch
        with patch.object(protected,"_fixed_native_directories",synthetic):
            assert protected.install_current_authority(
                approved_pin_bytes=args(1)["approved_pin_bytes"],
                approval_bytes=args(1)["approval_bytes"])["epoch"]==1


@pytest.mark.parametrize("field,change",[
    ("original_grant_sha256","f"*64),
    ("key_sha256","f"*64),
    ("host_id","different-host"),
    ("approval_sha256","f"*64),
    ("epoch",2),
    ("schema","foreign-schema"),
])
def test_same_byte_recovery_refuses_altered_retained_claim(
        authority,field,change):
    install,args,pub,priv,remote,*_=authority
    install(1)
    claim=priv/(protected.CLAIM_PREFIX+"1.json")
    altered=g._parse(claim.read_bytes())
    assert altered[field]!=change
    altered[field]=change
    put(claim,g.canonical(altered))
    with pytest.raises(g.RotationDenied):
        install(1)
    assert remote.epoch==1
    assert not (pub/g.PENDING_NAME).exists()


@pytest.mark.parametrize("field,change",[
    ("original_grant_sha256","f"*64),
    ("installation_id","different-installation"),
    ("approved_pin_sha256","not-a-sha"),
    ("approval_sha256",None),
])
def test_new_rotation_refuses_corrupt_historical_claim_before_reservation(
        authority,field,change):
    install,args,pub,priv,remote,operator,keys,fds=authority
    install(1)
    install(2)
    claim=priv/(protected.CLAIM_PREFIX+"1.json")
    altered=g._parse(claim.read_bytes())
    altered[field]=change
    put(claim,g.canonical(altered))
    third=pin(keys[2],3)
    approval3=approval(operator,third,pin(keys[1],2))
    with pytest.raises(g.RotationDenied):
        protected._install_source(
            public_fd=fds[0],private_fd=fds[1],
            approved_pin_bytes=g.canonical(third),
            approval_bytes=approval3,uid=os.geteuid())
    assert remote.epoch==2
    assert not (pub/g.PENDING_NAME).exists()
