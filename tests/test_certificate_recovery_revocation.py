"""Recovery-only incomplete broker installation; ephemeral root-only source tests."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from contextlib import contextmanager
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest

from zog.host_install import certificate_selected_broker_install as broker
from zog.host_install import certificate_recovery_revocation as recovery
from zog.host_install.state_contract import StateError,canonical
from zog.root_control import issuer_execution_fence as epoch
from zog.root_control.issuer_execution_fence import IssuerExecutionFence,IssuerFenceDenied
from zog.root_control.issuer_execution_provenance import NAME
from test_certificate_selected_broker_install import fixture,installed_and_revoked


@pytest.fixture
def staged(tmp_path,monkeypatch):
    if os.geteuid()!=0: pytest.skip("ephemeral root-owned installation required")
    @contextmanager
    def parent():
        fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: yield fd
        finally: os.close(fd)
    monkeypatch.setattr(broker,"_fixed_root_parent",parent)
    monkeypatch.setattr(epoch,"current_boot_id",lambda:"a"*32)
    values=fixture()
    broker.publish_verified_projection(
        trusted_original_root_reader=lambda:{
            k:v for k,v in values.items() if k!="expected_approval_sha256"},
        trusted_source_attestor=lambda _:True,
        expected_approval_sha256=values["expected_approval_sha256"])
    root=tmp_path/epoch.FIXED_DIRECTORY
    assert not (root/NAME).exists()
    evidence=installed_and_revoked()
    revoked={k:evidence[k] for k in (
        "revoked_owner","revoked_ledger","approval_bytes")}
    signer=Ed25519PrivateKey.generate()
    public=signer.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    commit=(tmp_path/broker.COMMIT_NAME).read_bytes()
    cp=json.loads(commit)
    unsigned={
        "schema":recovery.RECOVERY_SCHEMA,
        "purpose":"deny-incomplete-issuer-only",
        **{k:cp[k] for k in ("host_id","installation_id","state_volume_id")},
        "commit_sha256":hashlib.sha256(commit).hexdigest(),
        "revocation_approval_sha256":hashlib.sha256(
            evidence["approval_bytes"]).hexdigest(),
        "authorization_revision":2,
        "operation_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "operator_key_sha256":hashlib.sha256(public).hexdigest(),
    }
    proof=signer.sign(recovery.RECOVERY_DOMAIN+canonical(unsigned))
    signed=canonical({**unsigned,"signature_ed25519":
        base64.b64encode(proof).decode()})
    intent=[signed]
    pins=[{"public_key":public,"sha256":hashlib.sha256(public).hexdigest()}]
    approval_checkpoint=[{
        "authorization_revision":unsigned["authorization_revision"],
        "operation_id":unsigned["operation_id"],
        "commit_sha256":unsigned["commit_sha256"],
        "operator_key_sha256":unsigned["operator_key_sha256"],
    }]
    native={
        "trusted_original_revocation_reader":lambda:revoked,
        "trusted_source_attestor":lambda plan:True,
        "expected_approval_sha256":evidence["expected_approval_sha256"],
        "independently_trusted_recovery_reader":lambda:intent[0],
        "independently_pinned_recovery_key_reader":lambda:pins[0],
        "independently_trusted_recovery_checkpoint_reader":lambda:approval_checkpoint[0],
    }
    return tmp_path,root,commit,intent,pins,native


def test_durable_commit_without_provenance_can_only_be_revoked(staged):
    root,parent,commit,intent,pins,native=staged
    assert (root/broker.COMMIT_NAME).is_file()
    from zog.root_control.issuer_execution_provenance import require_installed_provenance
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        with pytest.raises(IssuerFenceDenied):
            require_installed_provenance(fd,root_control_revision=
                broker.ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT,
                box_control_revision=broker.BOX_CONTROL_REVIEWED_COMMIT,
                commit_sha256=hashlib.sha256(commit).hexdigest(),
                identities=json.loads(commit))
    finally: os.close(fd)
    result=recovery.publish_recovery_only_revocation(**native)
    assert result["status"]=="recovery-only-revoked"
    assert result["execution_authorized"] is False
    assert result["provenance_fabricated"] is False
    assert result["native_cleanup_verified"] is False
    assert (root/broker.REVOCATION_NAME).is_file()
    assert not (parent/NAME).exists()
    state=json.loads((parent/epoch.STATE).read_bytes())
    assert state["revoked"] is True
    assert recovery.publish_recovery_only_revocation(**native)["epoch"]==state["epoch"]


def test_bad_recovery_key_original_commit_and_provenance_refuse(staged):
    root,parent,commit,intent,pins,native=staged
    pins[0]={**pins[0],"sha256":"f"*64}
    with pytest.raises(StateError):recovery.publish_recovery_only_revocation(**native)
    assert not (root/broker.REVOCATION_NAME).exists()
    pins[0]["sha256"]=hashlib.sha256(pins[0]["public_key"]).hexdigest()
    (parent/NAME).write_bytes(b"malformed")
    (parent/NAME).chmod(0o600)
    with pytest.raises(StateError):recovery.publish_recovery_only_revocation(**native)
    (parent/NAME).unlink()
    (root/broker.COMMIT_NAME).unlink()
    with pytest.raises((StateError,ValueError)):
        recovery.publish_recovery_only_revocation(**native)
    assert not (root/broker.REVOCATION_NAME).exists()


def test_uncertain_operation_and_reboot_never_erased(staged):
    root,parent,commit,intent,pins,native=staged
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    fence=IssuerExecutionFence(fd)
    digest=hashlib.sha256(commit).hexdigest()
    with pytest.raises(IssuerFenceDenied):
        fence.admit(request_id="REQ-UNCERTAIN",program="renew",
                    boot_id="a"*32,trusted_commit_sha256=digest,
                    native_launch=lambda **kw:(_ for _ in ()).throw(
                        OSError("lost acknowledgement")))
    os.close(fd)
    result=recovery.publish_recovery_only_revocation(**native)
    assert result["uncertain_operations_retained"]==("REQ-UNCERTAIN",)
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    f=IssuerExecutionFence(fd)
    assert f.reboot(new_boot_id="b"*32)["revoked"] is True
    record=json.loads((parent/epoch.STATE).read_bytes())
    assert record["operations"]["REQ-UNCERTAIN"]["phase"]=="cancel-pending"
    with pytest.raises(IssuerFenceDenied):
        f.admit(request_id="REQ-2",program="inspect",
                boot_id="b"*32,trusted_commit_sha256=digest,
                native_launch=lambda **_:pytest.fail("cannot launch"))
    os.close(fd)


def test_lost_marker_response_keeps_revoke_and_same_authority_retry(staged,monkeypatch):
    root,parent,commit,intent,pins,native=staged
    original=broker._publish_verified_revocation_locked
    count=[]
    def fail_once(**kw):
        count.append(1)
        if len(count)==1:raise OSError("lost-response")
        return original(**kw)
    monkeypatch.setattr(broker,"_publish_verified_revocation_locked",fail_once)
    with pytest.raises(IssuerFenceDenied):
        recovery.publish_recovery_only_revocation(**native)
    assert json.loads((parent/epoch.STATE).read_bytes())["revoked"] is True
    assert not (root/broker.REVOCATION_NAME).exists()
    out=recovery.publish_recovery_only_revocation(**native)
    assert out["revoked"] is True and len(count)==2
    assert (root/broker.REVOCATION_NAME).exists()
    intent[0]=intent[0].replace(b'"purpose":"deny-incomplete-issuer-only"',
                                b'"purpose":"execute-program"',1)
    with pytest.raises(StateError):
        recovery.publish_recovery_only_revocation(**native)



def test_commit_before_epoch_ledger_can_be_abandoned_without_provenance(staged):
    root,parent,commit,intent,pins,native=staged
    # Synthetic reconstruction of a crash immediately after the committed
    # projection but before the EMPTY execution ledger was initialized.
    state=json.loads((parent/epoch.STATE).read_bytes())
    assert state["operations"]=={} and state["revoked"] is False
    (parent/epoch.STATE).unlink()
    result=recovery.publish_recovery_only_abandonment(**native)
    assert result["status"]=="recovery-only-abandoned-before-epoch"
    assert result["execution_history_unknown"] is True
    assert result["execution_ledger_created"] is False
    assert result["execution_authorized"] is False
    assert not (parent/epoch.STATE).exists()
    assert not (parent/NAME).exists()
    assert (root/broker.REVOCATION_NAME).exists()
    assert recovery.publish_recovery_only_abandonment(**native)["status"]==(
        "recovery-only-abandoned-before-epoch")


def test_abandonment_cannot_discard_existing_uncertain_operation(staged):
    root,parent,commit,intent,pins,native=staged
    with pytest.raises((StateError,OSError)):
        recovery.publish_recovery_only_abandonment(**native)
    assert (parent/epoch.STATE).exists()
    assert not (root/broker.REVOCATION_NAME).exists()


def test_abandonment_refuses_root_source_or_foreign_recovery_signature(staged):
    root,parent,commit,intent,pins,native=staged
    assert json.loads((parent/epoch.STATE).read_bytes())["operations"]=={}
    (parent/epoch.STATE).unlink()
    (parent/NAME).symlink_to("untrusted-provenance")
    with pytest.raises((StateError,OSError)):
        recovery.publish_recovery_only_abandonment(**native)
    (parent/NAME).unlink()
    pins[0]={**pins[0],"sha256":"f"*64}
    with pytest.raises(StateError):
        recovery.publish_recovery_only_abandonment(**native)
    assert not (root/broker.REVOCATION_NAME).exists()



def test_substituted_readers_and_current_authorization_are_denied(staged):
    root,parent,commit,intent,pins,native=staged
    for field,replacement in (
        ("independently_trusted_recovery_reader",lambda:b'{}'),
        ("independently_pinned_recovery_key_reader",
         lambda:{"public_key":b"\0"*32,"sha256":"0"*64}),
        ("independently_trusted_recovery_checkpoint_reader",
         lambda:{"authorization_revision":1,"operation_id":
                 "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                 "commit_sha256":hashlib.sha256(commit).hexdigest(),
                 "operator_key_sha256":pins[0]["sha256"]}),
        ("trusted_original_revocation_reader",lambda:{}),
        ("trusted_source_attestor",lambda plan:False),
    ):
        with pytest.raises((StateError,ValueError,KeyError)):
            recovery.publish_recovery_only_revocation(
                **{**native,field:replacement})
        assert not (root/broker.REVOCATION_NAME).exists()
    # A former valid signature has no power once the protected current
    # recovery revision/operation checkpoint advances.
    original=native["independently_trusted_recovery_checkpoint_reader"]()
    stale={**original,"authorization_revision":3}
    with pytest.raises(StateError):
        recovery.publish_recovery_only_abandonment(**{
            **native,"independently_trusted_recovery_checkpoint_reader":
            lambda:stale})
    assert not (root/broker.REVOCATION_NAME).exists()


def test_provenance_publication_after_durable_revocation_leaves_pending_denial(
        staged,monkeypatch):
    root,parent,commit,intent,pins,native=staged
    original=broker._publish_verified_revocation_locked
    def concurrent_provenance(**kwargs):
        # Model a source publisher which won the race after the initial
        # missing-provenance read but before the commit's final marker.
        (parent/NAME).write_bytes(b"provenance-present")
        (parent/NAME).chmod(0o600)
        return original(**kwargs)
    monkeypatch.setattr(broker,"_publish_verified_revocation_locked",
                        concurrent_provenance)
    # The recovery callback checks absence before invoking the publisher;
    # model it entering after the first check by replacing the callback
    # itself with a publication then denial before the final marker.
    from zog.root_control.issuer_execution_fence import IssuerExecutionFence
    baseline=IssuerExecutionFence.revoke
    def race(self,*,publish_pending_revocation):
        def publication():
            (parent/NAME).write_bytes(b"concurrent")
            (parent/NAME).chmod(0o600)
            return publish_pending_revocation()
        return baseline(self,publish_pending_revocation=publication)
    monkeypatch.setattr(IssuerExecutionFence,"revoke",race)
    with pytest.raises((StateError,IssuerFenceDenied)):
        recovery.publish_recovery_only_revocation(**native)
    ledger=json.loads((parent/epoch.STATE).read_bytes())
    assert ledger["revoked"] is True
    assert ledger["epoch"] >= 2
    assert not (root/broker.REVOCATION_NAME).exists()
    assert (parent/NAME).exists()
    # Reboot does not erase that denial or mark missing operations clean.
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        from zog.root_control.issuer_execution_fence import IssuerExecutionFence
        assert IssuerExecutionFence(fd).reboot(new_boot_id="e"*32)["revoked"]
    finally:
        os.close(fd)


def test_loss_after_tombstone_is_same_authority_only(staged,monkeypatch):
    root,parent,commit,intent,pins,native=staged
    original=broker._publish_verified_revocation_locked
    count=[]
    def ack_lost(**kw):
        result=original(**kw)
        if not count:
            count.append(1)
            raise OSError("lost acknowledgment after committed tombstone")
        return result
    monkeypatch.setattr(broker,"_publish_verified_revocation_locked",ack_lost)
    with pytest.raises(IssuerFenceDenied):
        recovery.publish_recovery_only_revocation(**native)
    assert (root/broker.REVOCATION_NAME).exists()
    assert json.loads((parent/epoch.STATE).read_bytes())["revoked"]
    assert recovery.publish_recovery_only_revocation(**native)["revoked"]
