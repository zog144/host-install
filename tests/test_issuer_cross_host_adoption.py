"""No remote transport or credential: installed-byte and owner preflight tests."""
import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_install import issuer_cross_host_adoption as bridge
from zog.host_install.state_contract import StateError


class FakeDistribution:
    def __init__(self, root, record):
        self.root = root
        self.record = record
        self.files = [Path("root_control-0.1.0.dist-info/RECORD")]
    def locate_file(self, name):
        return self.root / name
    def read_text(self, name):
        return self.record if name == "RECORD" else None


def _fixture(tmp_path, monkeypatch):
    root = tmp_path / "installed"
    src = root / "zog" / "root_control" / "issuer_cross_host.py"
    src.parent.mkdir(parents=True)
    raw = b"\n# pinned inert bridge source fixture\n"
    src.write_bytes(raw)
    record_path = root / "root_control-0.1.0.dist-info" / "RECORD"
    record_path.parent.mkdir()
    record_text = ("zog/root_control/issuer_cross_host.py,sha256=" +
                   base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode() +
                   ",\n")
    record_path.write_text(record_text)
    dist = FakeDistribution(root, record_text)
    monkeypatch.setattr(bridge.importlib.metadata, "distribution",lambda name:dist)
    monkeypatch.setattr(bridge.importlib, "import_module",
                        lambda name:SimpleNamespace(__file__=str(src)))
    monkeypatch.setattr(bridge.owner, "_protected_ancestry", lambda *a:None)
    monkeypatch.setattr(bridge, "_check_installed_stat", lambda path: None)
    return raw, src, record_path, dist


def test_installed_source_requires_blob_and_wheel_record(tmp_path,monkeypatch):
    raw,src,record,dist = _fixture(tmp_path, monkeypatch)
    sha = bridge.owner._git_blob(raw)
    attested = bridge._attest_module(
        "zog.root_control.issuer_cross_host", "root-control", sha)
    assert attested["git_blob"] == sha
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_cross_host", "root-control", "0"*40)
    # A stale wheel RECORD cannot attest newly modified installed bytes.
    src.write_bytes(raw+b"changed")
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_cross_host", "root-control", sha)


def test_missing_record_or_modified_receipt_blocks(tmp_path,monkeypatch):
    raw,src,record,dist = _fixture(tmp_path, monkeypatch)
    sha = bridge.owner._git_blob(raw)
    # Hardlink rejection belongs to _check_installed_stat and is checked
    # separately under a real file descriptor during native acceptance.
    record.write_text("zog/root_control/issuer_cross_host.py,sha256=wrong,\n")
    dist.record = record.read_text()
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_cross_host", "root-control", sha)


def test_inspector_requires_root_without_touching_credential(monkeypatch):
    monkeypatch.setattr(bridge.os,"geteuid", lambda:1000)
    with pytest.raises(StateError):
        bridge.inspect("/checked/project","/checked/policy",
                       python_executable="/usr/bin/python3")


def test_file_stat_gate_refuses_nonroot_and_multiple_links(tmp_path, monkeypatch):
    import stat
    path = tmp_path / "module.py"
    path.write_bytes(b"some source")
    from types import SimpleNamespace
    original = bridge.Path.lstat
    monkeypatch.setattr(bridge.Path, "lstat", lambda p: SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=2))
    with pytest.raises(StateError):
        bridge._check_installed_stat(path)
    monkeypatch.setattr(bridge.Path, "lstat", lambda p: SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600, st_uid=1000, st_nlink=1))
    with pytest.raises(StateError):
        bridge._check_installed_stat(path)
