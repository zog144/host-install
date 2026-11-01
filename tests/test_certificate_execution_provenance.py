"""Synthetic protected installer/wheel provenance; never attests a live Host."""
import json
import os
from contextlib import contextmanager

import pytest

from zog.host_install import certificate_selected_broker_install as broker
from zog.host_install import certificate_execution_provenance as source
from zog.root_control import issuer_execution_fence as epoch
from zog.root_control.issuer_execution_provenance import (
    NAME, require_installed_provenance,
)
from zog.root_control.issuer_execution_fence import IssuerFenceDenied, LOCK
from zog.host_install.state_contract import StateError
from test_certificate_selected_broker_install import fixture


@pytest.fixture
def protected(tmp_path, monkeypatch):
    if os.geteuid() != 0:
        pytest.skip("root-owned ephemeral source fixture")
    @contextmanager
    def parent():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)
    monkeypatch.setattr(broker, "_fixed_root_parent", parent)
    monkeypatch.setattr(source, "_fixed_root_parent", parent)
    monkeypatch.setattr(epoch, "current_boot_id", lambda: "a"*32)
    inputs = fixture()
    broker.publish_verified_projection(
        trusted_original_root_reader=lambda: {
            k:v for k,v in inputs.items() if k!="expected_approval_sha256"},
        trusted_source_attestor=lambda _: True,  # synthetic ONLY
        expected_approval_sha256=inputs["expected_approval_sha256"],
    )
    commit = json.loads((tmp_path / broker.COMMIT_NAME).read_bytes())
    folder = tmp_path / epoch.FIXED_DIRECTORY
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    evidence = {
        "root_control_revision": broker.ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT,
        "wheel_record_sha256": "d"*64,
        "box_control_revision": broker.BOX_CONTROL_REVIEWED_COMMIT,
        **{k:commit[k] for k in ("host_id","installation_id","state_volume_id")},
    }
    try:
        yield folder, fd, commit, evidence
    finally:
        os.close(fd)


def check(fd, commit, evidence):
    import hashlib
    from zog.host_install.state_contract import canonical
    return require_installed_provenance(
        fd, root_control_revision=evidence["root_control_revision"],
        box_control_revision=evidence["box_control_revision"],
        commit_sha256=hashlib.sha256(canonical(commit)).hexdigest(),
        identities=commit)


@pytest.mark.parametrize("bad", [
    {"root_control_revision":"f"*40},
    {"wheel_record_sha256":"e"*64},
    {"host_id":"foreign"},
    {"box_control_revision":"0"*40},
])
def test_foreign_source_record_or_host_never_published(protected,bad):
    folder,fd,commit,evidence=protected
    with pytest.raises(StateError):
        source.publish_verified_execution_provenance(
            independently_trusted_source_reader=lambda:{**evidence,**bad},
            independently_pinned_record_reader=lambda:"d"*64)
    assert not (folder / NAME).exists()
    with pytest.raises(IssuerFenceDenied):
        check(fd,commit,evidence)


def test_exact_source_provenance_binds_immutable_directory_and_lock(protected):
    folder,fd,commit,evidence=protected
    with pytest.raises(IssuerFenceDenied):
        check(fd,commit,evidence)
    result=source.publish_verified_execution_provenance(
        independently_trusted_source_reader=lambda:evidence,
        independently_pinned_record_reader=lambda:"d"*64)
    assert result["status"] == "source-provenance-staged"
    assert result["native_activation_authorized"] is False
    assert check(fd,commit,evidence) is True
    assert source.publish_verified_execution_provenance(
        independently_trusted_source_reader=lambda:evidence,
        independently_pinned_record_reader=lambda:"d"*64)==result
    with pytest.raises(StateError):
        source.publish_verified_execution_provenance(
            independently_trusted_source_reader=lambda:{**evidence,
                "wheel_record_sha256":"e"*64},
            independently_pinned_record_reader=lambda:"d"*64)
    assert check(fd,commit,evidence) is True


def test_changed_lock_inode_and_foreign_source_receipt_fail_closed(protected):
    folder,fd,commit,evidence=protected
    source.publish_verified_execution_provenance(
        independently_trusted_source_reader=lambda:evidence,
        independently_pinned_record_reader=lambda:"d"*64)
    assert check(fd,commit,evidence)
    (folder/LOCK).unlink()
    (folder/LOCK).write_bytes(b"")
    (folder/LOCK).chmod(0o600)
    with pytest.raises(IssuerFenceDenied):
        check(fd,commit,evidence)
    (folder/NAME).unlink()
    (folder/NAME).symlink_to("/etc/passwd")
    with pytest.raises(IssuerFenceDenied):
        check(fd,commit,evidence)


def test_missing_signed_wheel_pin_is_not_synthesized(protected):
    folder,fd,commit,evidence=protected
    with pytest.raises(StateError):
        source.publish_verified_execution_provenance(
            independently_trusted_source_reader=lambda:evidence,
            independently_pinned_record_reader=lambda:None)
    assert not (folder/NAME).exists()
