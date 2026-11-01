"""Independent monotonic checkpoint negative tests, no live remote provider."""
import base64
import json
import os
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.host_install import graphical_rotation_checkpoint as external
from zog.host_install import graphical_current_authority as local
from test_graphical_current_authority import fixture


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)


class Remote:
    """Test-only linearizable checkpoint outside the synthetic local dir."""
    def __init__(self, original):
        self.signer=Ed25519PrivateKey.generate()
        self.host_id=original["host_id"]
        self.installation_id=original["installation_id"]
        self.epoch=0
        self.sequence=1
        self.pin_sha=None
        self.approval_sha=None
        self.available=True
        self.read_count=0
    def read(self, nonce):
        if not self.available: raise OSError("remote unavailable")
        self.read_count+=1
        row={"schema":external.SCHEMA,
             "host_id":self.host_id,"installation_id":self.installation_id,
             "epoch":self.epoch,"sequence":self.sequence,
             "pin_sha256":self.pin_sha,"approval_sha256":self.approval_sha,
             "nonce":nonce}
        proof=self.signer.sign(external.DOMAIN+local.canonical(row))
        return local.canonical({
            **row,"signature_ed25519":base64.b64encode(proof).decode()})
    def advance(self, *, expected_epoch,expected_sequence,expected_pin_sha256,
                next_epoch,next_pin_sha256,next_approval_sha256,
                host_id,installation_id):
        if not self.available:raise OSError("external CAS unavailable")
        assert host_id==self.host_id and installation_id==self.installation_id
        assert (expected_epoch,expected_sequence,expected_pin_sha256)==(
            self.epoch,self.sequence,self.pin_sha)
        assert next_epoch==self.epoch+1
        self.epoch=next_epoch
        self.sequence+=1
        self.pin_sha=next_pin_sha256
        self.approval_sha=next_approval_sha256


@pytest.fixture
def checkpointed(fixture):
    args, public_dir, private_dir, fds=fixture
    sample=args(1)
    p=local._pin(sample["approved_pin_bytes"])
    r=Remote(p)
    def invoke(epoch,**more):
        x=args(epoch)
        return external.rotate_checked_source(
            **x,
            independently_pinned_external_public_key=pub(r.signer),
            independently_expected_external_sha256=local._sha(pub(r.signer)),
            read_independent_checkpoint=r.read,
            compare_and_advance_independent_checkpoint=r.advance,
            **more)
    def checked():
        return external.read_checked_source(
            public_fd=sample["public_fd"],
            read_independent_checkpoint=r.read,
            independently_pinned_external_public_key=pub(r.signer),
            independently_expected_external_sha256=local._sha(pub(r.signer)),
            uid=os.getuid())
    return invoke,checked,r,args,public_dir,private_dir


def test_first_install_rotation_and_same_byte_external_authority(checkpointed):
    rotate,read,r,args,p,q=checkpointed
    assert rotate(1)["externally_checked"] is True
    assert r.epoch==1 and read()["epoch"]==1
    assert rotate(1)["status"]=="same-byte-external-checked"
    assert rotate(2)["epoch"]==2
    assert read()["epoch"]==2 and r.sequence==3
    with pytest.raises(local.RotationDenied):
        rotate(1)


def test_coherent_rollback_both_local_records_is_refused(checkpointed):
    rotate,read,r,args,p,q=checkpointed
    rotate(1)
    old_public=(p/local.PUBLIC_NAME).read_bytes()
    old_private=(q/local.PRIVATE_JOURNAL).read_bytes()
    rotate(2)
    # Simulate a whole local volume snapshot rollback. External is retained.
    (p/local.PUBLIC_NAME).write_bytes(old_public)
    (p/local.PUBLIC_NAME).chmod(0o444)
    (q/local.PRIVATE_JOURNAL).write_bytes(old_private)
    (q/local.PRIVATE_JOURNAL).chmod(0o600)
    with pytest.raises(local.RotationDenied):read()
    with pytest.raises(local.RotationDenied):rotate(1)
    with pytest.raises(local.RotationDenied):rotate(2)
    assert r.epoch==2


@pytest.mark.parametrize("point",["pending","external-advance",
                                  "staged-"+local.PRIVATE_JOURNAL,
                                  "replaced-"+local.PRIVATE_JOURNAL,
                                  "staged-"+local.PUBLIC_NAME,
                                  "replaced-"+local.PUBLIC_NAME])
def test_interrupted_external_then_local_advance_same_authority_only(checkpointed,point):
    rotate,read,r,args,p,q=checkpointed
    rotate(1)
    def interrupted(event):
        if event==point:raise RuntimeError("simulated loss")
    with pytest.raises(RuntimeError):
        rotate(2,checkpoint=interrupted)
    assert (p/local.PENDING_NAME).exists()
    with pytest.raises(local.RotationDenied):read()
    # If external advancement did not happen yet, the authenticated
    # compare-and-advance is performed once. If it did, retry resumes.
    assert rotate(2)["epoch"]==2
    assert not (p/local.PENDING_NAME).exists()
    assert r.epoch==2 and read()["epoch"]==2


def test_external_unavailability_refuses_mutation_and_offline_read(checkpointed):
    rotate,read,r,args,p,q=checkpointed
    r.available=False
    with pytest.raises((OSError,local.RotationDenied)):rotate(1)
    assert not (p/local.PUBLIC_NAME).exists()
    r.available=True
    rotate(1)
    r.available=False
    with pytest.raises((OSError,local.RotationDenied)):read()
    with pytest.raises((OSError,local.RotationDenied)):rotate(2)


def test_forged_external_signature_wrong_host_and_replayed_nonce(checkpointed):
    rotate,read,r,args,p,q=checkpointed
    original=r.read
    stale=original("f"*48)
    r.read=lambda nonce:stale
    with pytest.raises(local.RotationDenied):rotate(1)
    r.read=original
    original_host=r.host_id
    r.host_id="foreign-host"
    with pytest.raises(local.RotationDenied):rotate(1)
    r.host_id=original_host
    remote_other=Ed25519PrivateKey.generate()
    with pytest.raises(local.RotationDenied):
        external.checked_snapshot(
            original("f"*48),nonce="f"*48,
            host_id=original_host,installation_id=r.installation_id,
            independently_pinned_external_key=pub(remote_other),
            independently_expected_external_sha256=local._sha(pub(remote_other)))
    assert not (p/local.PUBLIC_NAME).exists()


def test_independent_checkpoint_identity_must_differ_from_operator(checkpointed):
    rotate,read,r,args,p,q=checkpointed
    x=args(1)
    with pytest.raises(local.RotationDenied):
        external.rotate_checked_source(
            **x,
            independently_pinned_external_public_key=
                x["independently_pinned_operator_public_key"],
            independently_expected_external_sha256=
                x["independently_expected_operator_sha256"],
            read_independent_checkpoint=r.read,
            compare_and_advance_independent_checkpoint=r.advance)
    assert r.epoch==0


def test_missing_public_and_private_with_advanced_external_never_reinitializes(checkpointed):
    rotate,read,r,args,p,q=checkpointed
    rotate(1)
    (p/local.PUBLIC_NAME).unlink()
    (q/local.PRIVATE_JOURNAL).unlink()
    with pytest.raises(local.RotationDenied):rotate(1)
    assert r.epoch==1
