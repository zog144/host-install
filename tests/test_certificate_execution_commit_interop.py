"""Actual host-install committed projection into box-control broker authority reader.

Protected files are under a disposable temp dir, not /etc or STATE.
Source pin mismatch with host-deploy is an explicit native NO-GO.
"""
from contextlib import contextmanager
import os
import hashlib

import pytest

from zog.host_install import certificate_selected_broker_install as writer
from zog.box_control import issuer_broker_authority as reader
from zog.root_control import issuer_execution_fence
from test_certificate_selected_broker_install import fixture


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned source fixture")
def test_real_writer_to_broker_requires_exact_committed_projection(tmp_path, monkeypatch):
    @contextmanager
    def parent():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(writer, "_fixed_root_parent", parent)
    monkeypatch.setattr(issuer_execution_fence, "current_boot_id", lambda: "a"*32)
    inputs = fixture()
    root_input = {k: v for k, v in inputs.items()
                  if k != "expected_approval_sha256"}
    writer.publish_verified_projection(
        trusted_original_root_reader=lambda: root_input,
        trusted_source_attestor=lambda _: True,
        expected_approval_sha256=inputs["expected_approval_sha256"],
    )
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        accepted = reader._read_authority_in_parent(fd)
        assert accepted["box_control_revision"] == writer.BOX_CONTROL_REVIEWED_COMMIT
        assert accepted["box_control_revision"] == issuer_execution_fence.REVIEWED_BOX_CONTROL
        # A staged or incomplete final marker cannot authorize the broker.
        pending = tmp_path / (".pending." + writer.COMMIT_NAME)
        pending.write_bytes(b"interrupted")
        with pytest.raises(Exception):
            reader._read_authority_in_parent(fd)
        pending.unlink()
        assert reader._read_authority_in_parent(fd) == accepted
        # An alternative projection cannot ride an older signed commit.
        pin = tmp_path / writer.PROJECTION_NAME
        raw = pin.read_bytes()
        pin.unlink()
        pin.write_bytes(raw[:-1] + b" ")
        pin.chmod(0o444)
        with pytest.raises(Exception):
            reader._read_authority_in_parent(fd)
        pin.unlink()
        pin.write_bytes(raw)
        pin.chmod(0o444)
        assert reader._read_authority_in_parent(fd) == accepted
        # A revocation staged before its final name is already terminal.
        marker = tmp_path / (".pending." + writer.REVOCATION_NAME)
        marker.write_bytes(b"root-revocation-in-progress")
        with pytest.raises(Exception):
            reader._read_authority_in_parent(fd)
    finally:
        os.close(fd)


def test_older_host_deploy_source_cannot_authorize_new_broker_candidate():
    import ast
    from pathlib import Path
    path = Path("companions/host-deploy/src/zog/host_deploy/certificate_issuer_lifecycle.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    pinned = next(ast.literal_eval(node.value) for node in tree.body
                  if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name)
                          and target.id == "ISSUER_LIFECYCLE_BOX_CONTROL_REVISION"
                          for target in node.targets))
    assert writer.BOX_CONTROL_REVIEWED_COMMIT != pinned
    assert writer.BOX_CONTROL_REVIEWED_COMMIT == issuer_execution_fence.REVIEWED_BOX_CONTROL
