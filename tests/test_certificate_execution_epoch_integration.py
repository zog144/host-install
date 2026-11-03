"""Selected issuer root epoch + actual host-install revocation publisher.

Ephemeral root-owned directories, no native systemd, Certbot or /etc writes.
Both producer and admission use the SAME root-control flock and request log.
"""
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from threading import Event, Thread

import pytest

from zog.host_install import certificate_selected_broker_install as broker
from zog.root_control import issuer_execution_fence as fence_source
from zog.root_control.issuer_execution_fence import IssuerExecutionFence, IssuerFenceDenied
from test_certificate_selected_broker_install import fixture, installed_and_revoked

BOOT = "a" * 32


@pytest.mark.skipif(os.geteuid() != 0, reason="ephemeral protected root owner required")
@pytest.mark.parametrize("program", ["renew", "inspect", "stage"])
def test_actual_installer_revocation_serializes_with_root_admission(
        tmp_path, monkeypatch, program):
    @contextmanager
    def parent():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def installed():
        fd = os.open(tmp_path / fence_source.FIXED_DIRECTORY,
                     os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            raw = (tmp_path / broker.COMMIT_NAME).read_bytes()
            yield IssuerExecutionFence(fd), hashlib.sha256(raw).hexdigest()
        finally:
            os.close(fd)

    monkeypatch.setattr(broker, "_fixed_root_parent", parent)
    monkeypatch.setattr(fence_source, "installed_fence", installed)
    monkeypatch.setattr(fence_source, "current_boot_id", lambda: BOOT)
    evidence = fixture()
    saved = {k: v for k, v in evidence.items() if k != "expected_approval_sha256"}
    broker.publish_verified_projection(
        trusted_original_root_reader=lambda: saved,
        trusted_source_attestor=lambda _: True,
        expected_approval_sha256=evidence["expected_approval_sha256"],
    )
    revoked = installed_and_revoked()
    revoked_source = {key: revoked[key] for key in
                      ("revoked_owner", "revoked_ledger", "approval_bytes")}
    started, release, published = Event(), Event(), Event()
    replies = []

    def launch(**args):
        started.set()
        assert release.wait(3)
        return {"request_id": args["request_id"], "program": args["program"],
                "runtime_id": "RUNTIME1", "invocation_id": "b" * 32}

    def admit():
        with installed() as (fence, digest):
            replies.append(fence.admit(request_id="REQ1", program=program,
                           boot_id=BOOT, trusted_commit_sha256=digest,
                           native_launch=launch))

    def revoke():
        broker.publish_verified_revocation(
            trusted_original_revocation_reader=lambda: revoked_source,
            trusted_source_attestor=lambda _: True,
            expected_approval_sha256=revoked["expected_approval_sha256"])
        published.set()

    start_thread = Thread(target=admit)
    start_thread.start()
    assert started.wait(3)
    revoke_thread = Thread(target=revoke)
    revoke_thread.start()
    assert not published.wait(.05)
    release.set()
    start_thread.join(3)
    revoke_thread.join(3)
    assert published.is_set() and replies[0]["phase"] == "running"
    assert (tmp_path / broker.REVOCATION_NAME).exists()
    with installed() as (fence, digest):
        with pytest.raises(IssuerFenceDenied):
            fence.admit(request_id="REQ2", program=program, boot_id=BOOT,
                        trusted_commit_sha256=digest,
                        native_launch=lambda **kw: pytest.fail("replay"))
        assert fence.reconcile(
            request_id="REQ1",
            verify_stopped_and_clean=lambda **kw: kw["invocation_id"] == "b"*32
        )["phase"] == "terminal"
        assert fence.reboot(new_boot_id="c"*32)["revoked"] is True
