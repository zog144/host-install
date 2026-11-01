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
        "b4e723abab3dadcf238b0552ee4d5f108e6a6d95"
    )
