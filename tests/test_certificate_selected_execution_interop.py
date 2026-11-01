"""Exact immutable root-control launch/revocation shared-fence source contract."""
import ast
import os
from pathlib import Path
import pytest


def test_installed_root_control_and_host_install_share_one_lock_opener():
    repo=os.environ.get("ROOT_CONTROL_EPOCH_SOURCE")
    if not repo:
        pytest.skip("immutable root-control companion required")
    root=Path(repo)
    model=(root/"issuer_execution_fence.py").read_text()
    systemd=(root/"systemd.py").read_text()
    installer=(Path(__file__).resolve().parents[1]/
              "src/zog/host_install/certificate_selected_broker_install.py").read_text()
    assert "def installed_fence(*, for_revocation=False):" in model
    assert 'FIXED_DIRECTORY = "selected-issuer-execution"' in model
    assert 'LOCK = "selected-issuer-execution.lock"' in model
    assert "with installed_fence() as (fence, committed_digest):" in systemd
    assert "fence.admit(" in systemd
    assert "def publish_verified_revocation(" in installer
    assert "with installed_fence(for_revocation=True) as (fence, commit_sha):" in installer
    assert "state = fence.revoke(publish_pending_revocation=publish)" in installer
    assert "def _publish_revocation_record(" in installer
    assert "issuer_execution_adapter" not in installer
    assert "issuer_execution_adapter" not in systemd
    assert "return self._start_service_validated(" in systemd
    # No second selected-program epoch invocation hidden in generic start.
    assert systemd.count("fence.admit(") == 1
    assert model.count("fcntl.flock(fd, fcntl.LOCK_EX)") == 1
