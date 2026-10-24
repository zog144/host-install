"""Composition with real consumer supervisor; only mount/identity evidence is synthetic."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from zog.host_identify import signatures
from zog.host_install import beacon_profile as profile
from zog.host_install.state_contract import StateError
from zog.host_install.state_provision import prepare_tree
from test_state_provision import Context
from zog.host_discover import supervisor

@pytest.fixture
def environment(tmp_path):
    c=Context(tmp_path)
    prepare_tree(c,c.bundle['bootstrap']['state']['state_volume_id'])
    observation={'recovery_hold':False,'receipt':{'fingerprint':'a'*64}}
    with patch.object(supervisor.wire,'observe',return_value=observation):
        yield c,tmp_path,c.bundle['bootstrap']['state']['state_volume_id']
    c.close()

def test_explicit_preparation_retry_upgrade_and_missing_ledger(environment):
    c,root,volume=environment
    with pytest.raises(StateError):profile.prepare(c,'wrong',supervisor)
    profile.prepare(c,volume,supervisor)
    ledger=root/supervisor.NAME/'ledger.json';original=ledger.read_bytes()
    profile.prepare(c,volume,supervisor)
    c.bundle['bootstrap']['configuration_revision']+=1
    profile.prepare(c,volume,supervisor)
    assert ledger.read_bytes()==original
    ledger.unlink()
    with pytest.raises(StateError):profile.prepare(c,volume,supervisor)
    assert not ledger.exists()

def test_operated_ledger_preserved_and_corrupt_refused(environment):
    c,root,volume=environment;profile.prepare(c,volume,supervisor)
    ledger=root/supervisor.NAME/'ledger.json'
    value=json.loads(ledger.read_text());value['revision']=5;ledger.write_text(json.dumps(value))
    original=ledger.read_bytes();profile.prepare(c,volume,supervisor);assert ledger.read_bytes()==original
    ledger.write_text('broken')
    with pytest.raises(StateError):profile.prepare(c,volume,supervisor)

def test_incomplete_provision_retries_without_competing_state(environment):
    c,root,volume=environment;original=profile.publish
    def fail(fd,name,*a,**kw):
        if name=='beacon-prepared.json':raise OSError('interruption')
        return original(fd,name,*a,**kw)
    with patch.object(profile,'publish',side_effect=fail),pytest.raises(OSError):profile.prepare(c,volume,supervisor)
    ledger=root/supervisor.NAME/'ledger.json';before=ledger.read_bytes()
    profile.prepare(c,volume,supervisor);assert ledger.read_bytes()==before

def test_unrecorded_existing_journal_is_not_adopted(environment):
    c,root,volume=environment
    journal=root/'host-discover/control/managed.json';journal.write_text('{}');journal.chmod(0o600);os.chown(journal,970,970)
    with pytest.raises(StateError):profile.prepare(c,volume,supervisor)
    assert not (root/supervisor.NAME).exists()

def test_reviewed_host_discover_successor_source_is_exact():
    consumer = Path(os.environ["HOST_DISCOVER_SOURCE"])
    observed = profile.verify_reviewed_source(consumer)
    assert profile.CONSUMER_COMMIT == (
        "9e741d9a86bb2fd466ac46b252be0b78528eeff7"
    )
    assert profile.CONSUMER_VERSION == "0.4.11"
    assert len(observed) == 17
    assert set(observed) == set(profile.HOST_DISCOVER_MODULE_BLOBS)
    assert observed["zog.host_discover.managed_transport"]["git_blob"] == (
        "386384ade8606797cd7be855e26951be63bac2e1"
    )


def test_reviewed_successor_rejects_predecessor_reporting_bytes(tmp_path):
    consumer = Path(os.environ["HOST_DISCOVER_SOURCE"])
    source = tmp_path / "host-discover"
    for relative in profile.HOST_DISCOVER_SOURCE_FILES.values():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(consumer / relative, target)
    changed = source / "src/zog/host_discover/managed_transport.py"
    changed.write_bytes(changed.read_bytes() + b"\n# changed\n")
    with pytest.raises(StateError, match="differs from reviewed successor"):
        profile.verify_reviewed_source(source)


class FakeDistribution:
    def __init__(self, root, files, record):
        self.root = Path(root)
        self.version = "0.1.0"
        self.files = files
        self.metadata = {"Name": "zog"}
        self._record = record

    def locate_file(self, value):
        return self.root / str(value)

    def read_text(self, name):
        assert name == "RECORD"
        return self._record


def fake_installed_host_discover(tmp_path):
    source = Path(os.environ["HOST_DISCOVER_SOURCE"])
    root = tmp_path / "site-packages"
    mapping = {}
    rows = []
    files = []
    for module, relative_source in profile.HOST_DISCOVER_SOURCE_FILES.items():
        relative = (
            Path("zog/host_discover/__init__.py")
            if module == "zog.host_discover"
            else Path(*module.split(".")).with_suffix(".py")
        )
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (source / relative_source).read_bytes()
        target.write_bytes(data)
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()
        ).rstrip(b"=").decode()
        rows.append(f"{relative.as_posix()},sha256={digest},{len(data)}")
        files.append(relative)
        value = SimpleNamespace(__file__=str(target))
        if module == "zog.host_discover":
            value.__version__ = "0.4.11"
        mapping[module] = value
    record_relative = Path("zog-0.1.0.dist-info/RECORD")
    record_path = root / record_relative
    record_path.parent.mkdir(parents=True, exist_ok=True)
    rows.append(f"{record_relative.as_posix()},,")
    record = "\n".join(rows) + "\n"
    record_path.write_text(record)
    files.append(record_relative)
    return root, mapping, FakeDistribution(root, files, record)


def test_installed_host_discover_attestation_checks_all_modules_and_record(
    tmp_path, monkeypatch
):
    root, mapping, distribution = fake_installed_host_discover(tmp_path)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda *a, **k: None)
    monkeypatch.setattr(
        profile.importlib.metadata, "distribution", lambda name: distribution
    )
    monkeypatch.setattr(
        profile.importlib, "import_module", lambda name: mapping[name]
    )
    result = profile.verify_installed(python_executable="/usr/bin/python3")
    assert result["status"] == "host-discover-installed-software-verified"
    assert result["consumer_commit"] == profile.CONSUMER_COMMIT
    assert result["consumer_version"] == "0.4.11"
    assert set(result["modules"]) == set(profile.HOST_DISCOVER_MODULE_BLOBS)
    assert result["modules"]["zog.host_discover.managed_transport"]["git_blob"] == (
        "386384ade8606797cd7be855e26951be63bac2e1"
    )
    assert result["distribution"]["record_sha256"]
    assert result["state_modified"] is False
    assert result["station_approval_authorized"] is False
    for value in result["modules"].values():
        assert value["origin"].startswith(str(root))


def test_installed_host_discover_attestation_rejects_modified_reporting_module(
    tmp_path, monkeypatch
):
    _root, mapping, distribution = fake_installed_host_discover(tmp_path)
    path = Path(mapping["zog.host_discover.managed_transport"].__file__)
    path.write_bytes(path.read_bytes() + b"\n# predecessor-or-modified\n")
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(profile.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(profile, "_protected_ancestry", lambda *a, **k: None)
    monkeypatch.setattr(
        profile.importlib.metadata, "distribution", lambda name: distribution
    )
    monkeypatch.setattr(
        profile.importlib, "import_module", lambda name: mapping[name]
    )
    with pytest.raises(StateError, match="differ from reviewed successor"):
        profile.verify_installed(python_executable="/usr/bin/python3")


def test_offline_profile_is_repeatable_exclusive_and_has_no_preparation(tmp_path):
    consumer=Path(os.environ['HOST_DISCOVER_SOURCE']);producer=Path(__file__).resolve().parents[1]
    out=tmp_path/'overlay';profile.stage(consumer,producer,out,'/opt/zog/bin')
    profile.stage(consumer,producer,out,'/opt/zog/bin')
    units=out/'etc/systemd/system';beacon=(units/'host-discover-beacon.service').read_text()
    assert 'Conflicts=host-discover.service host-discover-managed.service' in beacon
    assert 'KillMode=mixed\nTimeoutStopSec=90s\n' in beacon
    assert beacon.count('KillMode=') == beacon.count('TimeoutStopSec=') == 1
    assert 'ExecStart=/opt/zog/bin/host-discover --managed-beacon' in beacon
    assert not (out/'state').exists()
    for p in units.iterdir():
        assert 'beacon-prepare' not in p.read_text()
        assert 'supervisor prepare' not in p.read_text()
    with pytest.raises(StateError):profile.stage(consumer,producer,out,'/other/bin')
    with pytest.raises(StateError):profile.stage(consumer,producer,tmp_path/'bad','/bin\nExecStart=/bad')

def test_staged_profile_boot_graph(tmp_path):
    import subprocess
    consumer=Path(os.environ['HOST_DISCOVER_SOURCE']);producer=Path(__file__).resolve().parents[1]
    out=tmp_path/'overlay';profile.stage(consumer,producer,out)
    units=out/'etc/systemd/system'
    (units/'state.mount').write_text((producer/'examples/systemd/state.mount.in').read_text().replace('@STATE_PARTUUID@','11111111-1111-4111-8111-111111111111'))
    targets={'sysinit.target':'','sockets.target':'Before=basic.target\n',
        'basic.target':'Requires=sysinit.target sockets.target\nAfter=sysinit.target sockets.target\n',
        'multi-user.target':'Requires=basic.target\nAfter=basic.target\nWants=host-discover-beacon.service\n',
        'shutdown.target':'','local-fs.target':'','local-fs-pre.target':'','network-online.target':''}
    for name,body in targets.items():(units/name).write_text('[Unit]\nDefaultDependencies=no\n'+body)
    for name in ('host-install','host-discover','host-discover-supervisor'):
        exe=out/'usr/bin'/name;exe.parent.mkdir(parents=True,exist_ok=True);exe.write_text('#!/bin/sh\nexit 0\n');exe.chmod(0o755)
    (out/'etc/passwd').write_text('root:x:0:0::/root:/bin/sh\nhost-discover:x:970:970::/state/host-discover:/usr/sbin/nologin\n')
    (out/'etc/group').write_text('root:x:0:\nhost-discover:x:970:\narchive-consumers:x:972:\nhost-control:x:973:\n')
    command=['systemd-analyze','verify','--generators=no','--man=no','--root='+str(out),'multi-user.target']
    p=subprocess.run(command,capture_output=True,text=True)
    assert p.returncode==0 and 'ordering cycle' not in p.stderr.lower(),p.stderr
    socket=units/'host-discover-supervisor.socket';socket.chmod(0o644);socket.write_text(socket.read_text().replace('DefaultDependencies=no\n',''))
    p=subprocess.run(command,capture_output=True,text=True)
    assert 'ordering cycle' in p.stderr.lower(),p.stderr


def _authority_pin(tmp_path):
    key = Ed25519PrivateKey.generate()
    public = key.public_key()
    value = {
        "schema": 1,
        "kind": "zog-certificate-assignment-authority-pin",
        "registry_id": "primary",
        "authority_public_key": signatures.public_text(public),
        "authority_key_id": signatures.fingerprint(public),
    }
    path = tmp_path / "authority-pin.json"
    path.write_text(json.dumps(value))
    return path, value


def test_offline_profile_installs_reviewed_root_authority_pin(tmp_path):
    consumer = Path(os.environ["HOST_DISCOVER_SOURCE"])
    producer = Path(__file__).resolve().parents[1]
    pin_path, pin = _authority_pin(tmp_path)
    out = tmp_path / "authority-overlay"
    result = profile.stage(
        consumer,
        producer,
        out,
        authority_pin=pin_path,
    )
    installed = (
        out / "etc/zog/host-install/certificate-assignment-authority.json"
    )
    assert result["certificate_assignment_authority_pin_installed"] is True
    assert result["certificate_assignment_authority_key_id"] == pin["authority_key_id"]
    assert installed.stat().st_mode & 0o777 == 0o444
    assert json.loads(installed.read_text()) == pin
    manifest = json.loads((out / "profile.json").read_text())
    assert manifest["consumer_template_commit"] == (
        "9e741d9a86bb2fd466ac46b252be0b78528eeff7"
    )
    assert manifest["consumer_version"] == "0.4.11"
    assert set(manifest["consumer_runtime_modules"]) == set(
        profile.HOST_DISCOVER_MODULE_BLOBS
    )
    assert manifest["consumer_runtime_modules"][
        "zog.host_discover.managed_transport"
    ]["git_blob"] == "386384ade8606797cd7be855e26951be63bac2e1"
    assert manifest["certificate_assignment_authority_pin"]["path"] == (
        "/etc/zog/host-install/certificate-assignment-authority.json"
    )
    assert manifest["certificate_assignment_authority_pin"]["authority_key_id"] == (
        pin["authority_key_id"]
    )


def test_offline_profile_rejects_wrong_authority_fingerprint(tmp_path):
    consumer = Path(os.environ["HOST_DISCOVER_SOURCE"])
    producer = Path(__file__).resolve().parents[1]
    pin_path, pin = _authority_pin(tmp_path)
    pin["authority_key_id"] = "0" * 64
    pin_path.write_text(json.dumps(pin))
    with pytest.raises(StateError, match="fingerprint"):
        profile.stage(
            consumer,
            producer,
            tmp_path / "bad-authority-overlay",
            authority_pin=pin_path,
        )
