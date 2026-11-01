"""Exact source closure to the selected issuer broker's revocation-aware reader."""
import ast
import hashlib
import os
from pathlib import Path

import pytest

from zog.host_install import certificate_selected_broker_install as broker


def test_host_deploy_selected_broker_source_is_exact_and_revocation_fenced():
    source = os.environ.get("HOST_DEPLOY_SELECTED_BROKER_SOURCE")
    if not source:
        pytest.skip("cross-repository immutable checkout supplied by broker CI")
    contents = Path(source).read_bytes()
    actual_git_blob = hashlib.sha1(
        b"blob " + str(len(contents)).encode("ascii") + b"\0" + contents
    ).hexdigest()
    assert actual_git_blob == broker.HOST_DEPLOY_PROJECTION_BLOB
    module = ast.parse(contents)
    assignments = {
        target.id: expr.value
        for expr in module.body if isinstance(expr, ast.Assign)
        for target in expr.targets if isinstance(target, ast.Name)
    }
    assert ast.literal_eval(assignments["FIELDS"]) == broker.PROJECTION_FIELDS
    assert ast.literal_eval(assignments["ROOT_PATH"]) == broker.PROJECTION_PATH
    assert ast.literal_eval(assignments["REVOCATION_NAME"]) == (
        "certificate-issuer-broker-revoked.json"
    )
    root_file = next(
        node for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "_root_file"
    )
    calls = [
        node for node in ast.walk(root_file)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_require_not_revoked"
    ]
    assert len(calls) == 2  # both before and after reading public authority
    assert broker.HOST_DEPLOY_REVIEWED_COMMIT == (
        "e2e050a9562a07648ed58ba5a1357daed6da4e9e"
    )
    assert ast.literal_eval(assignments["COMMIT_NAME"]) == broker.COMMIT_NAME
    assert ast.literal_eval(assignments["COMMIT_SCHEMA"]) == broker.COMMIT_SCHEMA
    root_calls = [
        node for node in ast.walk(root_file)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_commit_file"
    ]
    assert len(root_calls) == 2  # before and after public projection read



@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned interop fixture")
@pytest.mark.parametrize("interrupt", (
    "published:certificate-issuer-broker-authority.json",
    "published:certificate-issuer-broker-install-receipt.json",
    "staged:certificate-issuer-broker-install-commit.json",
    "linked:certificate-issuer-broker-install-commit.json",
))
def test_actual_consumer_does_not_accept_interrupted_installation(
        monkeypatch, interrupt):
    """Run both exact pinned owner/consumer Python sources against one dirfd."""
    if not os.environ.get("HOST_DEPLOY_SELECTED_BROKER_SOURCE"):
        pytest.skip("pinned cross-repository checkout required")
    from contextlib import contextmanager
    import json
    import shutil
    import tempfile
    from zog.host_deploy import certificate_selected_broker_authority as consumer
    from zog.host_deploy.certificate_renewal import RenewalBlocked
    from test_certificate_selected_broker_install import fixture

    root = Path(tempfile.mkdtemp(prefix="zog-broker-interop-", dir="/root"))
    dest = root / "etc" / "zog" / "host-deploy"
    dest.mkdir(parents=True, mode=0o755)
    for parent in (root, root/"etc", root/"etc/zog", dest):
        parent.chmod(0o755)
    public = dest / broker.PROJECTION_NAME
    source = fixture()
    inputs = {
        "trusted_original_root_reader": lambda: {
            k: v for k, v in source.items() if k != "expected_approval_sha256"
        },
        "trusted_source_attestor": lambda _: True,
        "expected_approval_sha256": source["expected_approval_sha256"],
    }
    @contextmanager
    def protected_parent():
        fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)
    monkeypatch.setattr(broker, "_fixed_root_parent", protected_parent)
    monkeypatch.setattr(consumer, "ROOT_PATH", str(public))
    original = broker.publish
    def interrupted(fd, name, payload, *, mode, uid, gid):
        def checkpoint(point):
            if point == interrupt:
                raise RuntimeError("isolated-write-interruption")
        return original(fd, name, payload, mode=mode, uid=uid,
                        gid=gid, checkpoint=checkpoint)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(broker, "publish", interrupted)
            with pytest.raises(RuntimeError, match="isolated-write-interruption"):
                broker.publish_verified_projection(**inputs)
        # A complete public projection is NOT proof the private receipt
        # committed, nor proof the last public commit finished publication.
        with pytest.raises(RenewalBlocked):
            consumer._root_file(str(public))
        broker.publish_verified_projection(**inputs)
        expected = broker.projection_plan(
            **source)["projection"]
        assert consumer._root_file(str(public)) == expected
        assert (dest / broker.COMMIT_NAME).is_file()
    finally:
        shutil.rmtree(root)
