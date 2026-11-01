"""Synthetic current signing authority rotation and crash recovery.

Uses only test-owned temporary directory descriptors, never actual /etc.
"""
import base64
import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.host_install import graphical_current_authority as g


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pin(key, epoch):
    return {
        "schema": g.PIN_SCHEMA,
        "host_id": "host-approved",
        "installation_id": "installation-approved",
        "lane": "compiler",
        "lane_owner": "image-build",
        "boot_id": "a"*32,
        "chain_policy_sha256": "sha256:"+"a"*64,
        "original_catalogue_sha256": "sha256:"+"b"*64,
        "public_key": base64.b64encode(public(key)).decode(),
        "epoch": epoch,
        "source_revision": "c"*40,
        "monthly_pin_identity": "d"*64,
        "first_base_generation_id": "e"*64,
        "first_receipt_sha256": "sha256:"+"f"*64,
        "relay_uid": 23001,
    }


def approval(operator, next_pin, previous):
    unsigned = {
        "schema":g.APPROVAL_SCHEMA, "host_id":next_pin["host_id"],
        "installation_id":next_pin["installation_id"],
        "previous_pin_sha256":None if previous is None else g._sha(g.canonical(previous)),
        "new_pin_sha256":g._sha(g.canonical(next_pin)),
        "new_epoch":next_pin["epoch"],"approval_id":"operator-1",
        "authorization_revision":next_pin["epoch"],
    }
    signature = operator.sign(
        b"zog-graphical-current-authority-rotation-v1\x00" + g.canonical(unsigned))
    return g.canonical({**unsigned,
                        "operator_signature":base64.b64encode(signature).decode()})


@pytest.fixture
def fixture(tmp_path):
    pub = tmp_path/"etc-public"
    priv = tmp_path/"root-private"
    pub.mkdir(mode=0o755)
    priv.mkdir(mode=0o700)
    os.chmod(pub, 0o755)
    os.chmod(priv, 0o700)
    fd1 = os.open(pub, os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    fd2 = os.open(priv, os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
    operator = Ed25519PrivateKey.generate()
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    def args(epoch):
        next_pin = pin(keys[epoch-1],epoch)
        previous = pin(keys[epoch-2],epoch-1) if epoch>1 else None
        return {
            "public_fd":fd1, "private_fd":fd2,
            "approved_pin_bytes":g.canonical(next_pin),
            "approval_bytes":approval(operator,next_pin,previous),
            "independently_pinned_operator_public_key":public(operator),
            "independently_expected_operator_sha256":g._sha(public(operator)),
            "uid":os.getuid(),
        }
    yield args, pub, priv, (fd1,fd2)
    os.close(fd1);os.close(fd2)


def test_first_install_rotation_rejects_old_key_and_old_epoch(fixture):
    args,pub,priv,_=fixture
    assert g.rotate_source(**args(1))["epoch"] == 1
    first = g.current_source_read(public_fd=args(1)["public_fd"],uid=os.getuid())
    assert first["epoch"] == 1
    assert g.rotate_source(**args(1))["status"] == "same-byte"
    assert g.rotate_source(**args(2))["epoch"] == 2
    second = g.current_source_read(public_fd=args(1)["public_fd"],uid=os.getuid())
    assert second["epoch"] == 2 and second["public_key"] != first["public_key"]
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**args(1))
    assert g.rotate_source(**args(2))["status"] == "same-byte"
    assert json.loads((priv/g.PRIVATE_JOURNAL).read_bytes())["epoch"] == 2


@pytest.mark.parametrize("point", [
    "pending", "staged-"+g.PRIVATE_JOURNAL,
    "replaced-"+g.PRIVATE_JOURNAL, "epoch",
    "staged-"+g.PUBLIC_NAME, "replaced-"+g.PUBLIC_NAME, "public",
])
@pytest.mark.parametrize("epoch", [1,2])
def test_interruption_denies_until_same_signed_intent_is_reconciled(fixture,point,epoch):
    args,pub,priv,_=fixture
    if epoch == 2: g.rotate_source(**args(1))
    def interrupted(where):
        if where==point: raise RuntimeError("simulated-interruption")
    with pytest.raises(RuntimeError,match="simulated-interruption"):
        g.rotate_source(**args(epoch),checkpoint=interrupted)
    with pytest.raises(g.RotationDenied):
        g.current_source_read(public_fd=args(1)["public_fd"],uid=os.getuid())
    assert (pub/g.PENDING_NAME).exists()
    assert g.rotate_source(**args(epoch))["epoch"] == epoch
    assert not (pub/g.PENDING_NAME).exists()
    assert g.current_source_read(public_fd=args(1)["public_fd"],
                                 uid=os.getuid())["epoch"] == epoch


def test_pending_rejects_foreign_signed_key_and_wrong_operator_pin(fixture):
    args,pub,priv,_=fixture
    def stop(where):
        if where=="pending": raise RuntimeError()
    with pytest.raises(RuntimeError):
        g.rotate_source(**args(1),checkpoint=stop)
    forged=args(1)
    forged["independently_expected_operator_sha256"]="9"*64
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**forged)
    wrong=args(2)
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**wrong)
    assert (pub/g.PENDING_NAME).exists()


def test_missing_private_highwater_after_commit_never_bootstraps_forged_epoch(fixture):
    args,pub,priv,_=fixture
    g.rotate_source(**args(1))
    (priv/g.PRIVATE_JOURNAL).unlink()
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**args(2))
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**args(1))


def test_public_reader_denies_pending_symlink_or_malformed_files(fixture):
    args,pub,priv,_=fixture
    g.rotate_source(**args(1))
    pending=pub/g.PENDING_NAME
    pending.symlink_to(pub/"foreign")
    with pytest.raises((OSError,g.RotationDenied)):
        g.current_source_read(public_fd=args(1)["public_fd"],uid=os.getuid())
    pending.unlink()
    pending.write_text("{invalid")
    os.chmod(pending,0o444)
    with pytest.raises(g.RotationDenied):
        g.current_source_read(public_fd=args(1)["public_fd"],uid=os.getuid())


def test_source_has_no_live_host_destination_or_private_key_writer():
    import inspect
    source=inspect.getsource(g.rotate_source)
    assert "os.open(\"/etc" not in source
    assert "private_key" not in source
    assert g.FIXED_PUBLIC_PATH == (
        "/etc/zog/host-deploy/graphical-chain-current-owner-pin-v1.json")


def test_simultaneous_same_approval_is_serialized_and_same_byte(fixture):
    from concurrent.futures import ThreadPoolExecutor
    args, pub, priv, _ = fixture
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: g.rotate_source(**args(1)), range(2)))
    assert sorted(item["status"] for item in results) == [
        "same-byte", "source-committed",
    ]
    assert g.current_source_read(
        public_fd=args(1)["public_fd"], uid=os.getuid())["epoch"] == 1
    assert json.loads((priv/g.PRIVATE_JOURNAL).read_bytes())["epoch"] == 1


def test_private_highwater_rejects_public_old_key_rollback(fixture):
    args, pub, priv, _ = fixture
    g.rotate_source(**args(1))
    old = (pub/g.PUBLIC_NAME).read_bytes()
    g.rotate_source(**args(2))
    before = (priv/g.PRIVATE_JOURNAL).read_bytes()
    (pub/g.PUBLIC_NAME).unlink()
    (pub/g.PUBLIC_NAME).write_bytes(old)
    (pub/g.PUBLIC_NAME).chmod(0o444)
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**args(2))
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**args(1))
    assert (priv/g.PRIVATE_JOURNAL).read_bytes() == before


def test_signer_substitution_and_torn_pending_are_terminal(fixture):
    args, pub, priv, _ = fixture
    proposal = args(1)
    original = proposal["approved_pin_bytes"]
    foreign = json.loads(original)
    foreign["public_key"] = base64.b64encode(public(
        Ed25519PrivateKey.generate())).decode("ascii")
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**{**proposal,
            "approved_pin_bytes": g.canonical(foreign)})
    assert not (pub/g.PUBLIC_NAME).exists()
    g.rotate_source(**proposal)
    pending = pub/g.PENDING_NAME
    pending.write_bytes(b"partial")
    pending.chmod(0o444)
    with pytest.raises(g.RotationDenied):
        g.current_source_read(public_fd=proposal["public_fd"],
                              uid=os.getuid())
    with pytest.raises(g.RotationDenied):
        g.rotate_source(**proposal)
    assert (pub/g.PUBLIC_NAME).read_bytes() == original
