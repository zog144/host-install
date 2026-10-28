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
        self.files = [Path("dist-info/RECORD")]
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
    record_path = root / "dist-info" / "RECORD"
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


def test_hardlinked_installed_source_and_wrong_record_block(tmp_path,monkeypatch):
    raw,src,record,dist = _fixture(tmp_path, monkeypatch)
    sha = bridge.owner._git_blob(raw)
    src.hardlink_to if False else None
    alias = src.parent / "second"
    import os
    os.link(src, alias)
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_cross_host", "root-control", sha)
    alias.unlink()
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
