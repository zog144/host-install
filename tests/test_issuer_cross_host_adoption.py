"""No remote transport or credential: installed-byte and owner preflight tests."""
import base64
import hashlib
import os
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


def _fixture(tmp_path, monkeypatch, raw=None):
    root = tmp_path / "installed"
    src = root / "zog" / "root_control" / "issuer_https_receiver.py"
    src.parent.mkdir(parents=True)
    if raw is None:
        raw = b"\n# pinned inert bridge source fixture\n"
    src.write_bytes(raw)
    record_path = root / "root_control-0.1.0.dist-info" / "RECORD"
    record_path.parent.mkdir()
    record_text = ("zog/root_control/issuer_https_receiver.py,sha256=" +
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


def test_reviewed_root_bridge_bytes_and_record_are_exact(tmp_path, monkeypatch):
    source_root = Path(os.environ["ROOT_CONTROL_CROSS_HOST_SOURCE"])
    source = source_root / "src/zog/root_control/issuer_https_receiver.py"
    raw = source.read_bytes()
    assert bridge.ROOT_BRIDGE_COMMIT == "d85aa7feb8a4db28249c5edde958d3d006e5e009"
    assert bridge.ROOT_BRIDGE_BLOB == "4d3d11a874203336cb5bf386e78af20e6772d21f"
    assert bridge.owner._git_blob(raw) == bridge.ROOT_BRIDGE_BLOB

    installed_raw, _src, _record, dist = _fixture(
        tmp_path, monkeypatch, raw=raw
    )
    assert installed_raw == raw
    attested = bridge._attest_module(
        "zog.root_control.issuer_https_receiver",
        "root-control",
        bridge.ROOT_BRIDGE_BLOB,
    )
    assert attested["git_blob"] == bridge.ROOT_BRIDGE_BLOB
    assert attested["sha256"] == hashlib.sha256(raw).hexdigest()
    assert attested["wheel_record_sha256"] == hashlib.sha256(
        dist.record.encode()
    ).hexdigest()

    # A predecessor pin must not attest the corrected installed bytes.
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_https_receiver",
            "root-control",
            "2f159a59bbc8fef0f53ce35fbf82833c9a88c645",
        )


def test_installed_source_requires_blob_and_wheel_record(tmp_path,monkeypatch):
    raw,src,record,dist = _fixture(tmp_path, monkeypatch)
    sha = bridge.owner._git_blob(raw)
    attested = bridge._attest_module(
        "zog.root_control.issuer_https_receiver", "root-control", sha)
    assert attested["git_blob"] == sha
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_https_receiver", "root-control", "0"*40)
    # A stale wheel RECORD cannot attest newly modified installed bytes.
    src.write_bytes(raw+b"changed")
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_https_receiver", "root-control", sha)


def test_missing_record_or_modified_receipt_blocks(tmp_path,monkeypatch):
    raw,src,record,dist = _fixture(tmp_path, monkeypatch)
    sha = bridge.owner._git_blob(raw)
    # Hardlink rejection belongs to _check_installed_stat and is checked
    # separately under a real file descriptor during native acceptance.
    record.write_text("zog/root_control/issuer_https_receiver.py,sha256=wrong,\n")
    dist.record = record.read_text()
    with pytest.raises(StateError):
        bridge._attest_module(
            "zog.root_control.issuer_https_receiver", "root-control", sha)


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


def test_canonical_host_identify_protocol_and_station_vector_are_exact():
    import json
    from zog.host_identify import credential_delivery as cd

    source_root = Path(os.environ["HOST_IDENTIFY_SOURCE"])
    raw = (source_root / "src/zog/host_identify/credential_delivery.py").read_bytes()
    assert bridge.HOST_IDENTIFY_COMMIT == "4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b"
    assert bridge.HOST_IDENTIFY_CREDENTIAL_BLOB == "02332127defe565e00e398b71ada50d5c2bdd4d6"
    assert bridge.owner._git_blob(raw) == bridge.HOST_IDENTIFY_CREDENTIAL_BLOB
    assert "zog.host_identify.credential_delivery" in bridge.SOURCE

    station_root = Path(os.environ["STATION_ACCESS_CROSS_HOST_SOURCE"])
    vector_path = (
        station_root / "tests/host_registry/fixtures/credential-delivery-v1-vector.json"
    )
    vector_raw = vector_path.read_bytes()
    assert bridge.owner._git_blob(vector_raw) == "227a043ffbf88489d2c8b65790058ef870e5c1bc"
    vector = json.loads(vector_raw)
    assert hashlib.sha256(cd.canonical(vector["authorization"])).hexdigest() == (
        vector["authorization_sha256"]
    )
    assert hashlib.sha256(cd.canonical(vector["request"])).hexdigest() == (
        vector["request_sha256"]
    )
    assert hashlib.sha256(cd.canonical(vector["delivery"])).hexdigest() == (
        vector["delivery_sha256"]
    )


def test_common_receiver_checks_have_independent_review_pin():
    source_root = Path(os.environ["ROOT_CONTROL_CROSS_HOST_SOURCE"])
    raw = (source_root / "src/zog/root_control/issuer_receipt_common.py").read_bytes()
    assert bridge.ROOT_RECEIPT_COMMON_BLOB == "4c1fe6b37c95d3cd038aba0c8a0df3b71a55d13f"
    assert bridge.owner._git_blob(raw) == bridge.ROOT_RECEIPT_COMMON_BLOB
    assert "zog.root_control.issuer_receipt_common" in bridge.SOURCE


def test_https_host_deploy_admission_and_selected_consumer_pins_are_exact():
    source_root = Path(os.environ["HOST_DEPLOY_SOURCE"])
    admission = (
        source_root / "src/zog/host_deploy/certificate_cross_host_admission.py"
    ).read_bytes()
    consumer = (
        source_root / "src/zog/host_deploy/certificate_cloudflare_https_consumer.py"
    ).read_bytes()
    assert bridge.HOST_DEPLOY_COMMIT == "e4aca5ae832b6a8bc02795db650ada9dfd1224c8"
    assert bridge.HOST_DEPLOY_BRIDGE_BLOB == "592983a3d299aaf1228248157fdea3908680f097"
    assert bridge.HOST_DEPLOY_HTTPS_CONSUMER_BLOB == "607372e25c860e18f8581e2dde2291dc2d074850"
    assert bridge.owner._git_blob(admission) == bridge.HOST_DEPLOY_BRIDGE_BLOB
    assert bridge.owner._git_blob(consumer) == bridge.HOST_DEPLOY_HTTPS_CONSUMER_BLOB
    assert "zog.host_deploy.certificate_cloudflare_https_consumer" in bridge.SOURCE


def test_canonical_adapter_and_retired_transport_are_both_attested():
    from zog.host_deploy import certificate_cloudflare_https_consumer as retired
    source_root = Path(os.environ["HOST_DEPLOY_SOURCE"])
    name = "zog.host_deploy.certificate_cloudflare_canonical"
    raw = (source_root / "src/zog/host_deploy/certificate_cloudflare_canonical.py").read_bytes()
    assert bridge.owner._git_blob(raw) == bridge.HOST_DEPLOY_CANONICAL_BLOB
    assert bridge.SOURCE[name] == ("host-deploy", bridge.HOST_DEPLOY_CANONICAL_BLOB)
    for entry in (retired.prepare, retired.check_receipt, retired.deliver_selected):
        with pytest.raises(retired.CloudflareDeliveryBlocked):
            entry()
