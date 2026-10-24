import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from zog.host_install import certificate_owner_authority as owner
from zog.host_install.state_contract import StateError


ROOT = Path(__file__).resolve().parents[1]
HOST_DEPLOY_SOURCE = Path(
    os.environ.get("HOST_DEPLOY_SOURCE", "companions/host-deploy")
)
NOW = 1790000000


def ident(number):
    return str(uuid.UUID(int=number))


class Context:
    bundle = {
        "bootstrap": {
            "installation_id": ident(2),
            "state": {"state_volume_id": ident(3)},
        }
    }


def fixture():
    signer = Ed25519PrivateKey.generate()
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = hashlib.sha256(raw).hexdigest()
    pin = {
        "schema": 1,
        "kind": owner.PIN_KIND,
        "registry_id": "primary",
        "authority_public_key": base64.b64encode(raw).decode("ascii"),
        "authority_key_id": key_id,
    }
    intent = {
        "schema": owner.INTENT_SCHEMA,
        "service_id": "candidate-nginx",
        "dns_mode": "local-cloudflare",
        "dns_zone": "example.org",
        "credential_id": "local-cloudflare",
        "credential_revision": 3,
    }
    policy = {
        "certificate_id": "station-web",
        "hostnames": ["candidate.example.org"],
        "contact_email": "webmaster@example.org",
        "acme_directory":
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        "challenge": "dns-01",
        "dns_plugin": "dns-cloudflare",
        "policy_sha256": "a" * 64,
        "raw_sha256": "b" * 64,
    }
    prepared = {
        "storage_id": "c" * 32,
        "grant_id": "d" * 32,
        "issuer_uid": 29001,
        "issuer_gid": 29002,
        "software_view": "sha256:" + "e" * 64,
        "certificate_data_path":
            "/home/controller/project/state/mounts/persistent/"
            + "c" * 32 + "/certificate-data",
    }
    delivery = {
        "service_id": intent["service_id"],
        "certificate_id": policy["certificate_id"],
        "hostnames": policy["hostnames"],
        "policy_sha256": policy["policy_sha256"],
        "issuer_uid": prepared["issuer_uid"],
        "peer_uid": prepared["issuer_uid"],
        "issuer_state": prepared["certificate_data_path"],
    }
    assignment = {
        "schema": "zog-certificate-assignment-v1",
        "authority_origin": "command-center",
        "host_id": ident(1),
        "installation_id": ident(2),
        "operation_id": ident(4),
        "revision": 7,
        "status": "approved",
        "approved_at": NOW - 3600,
        "revoked_at": None,
        "expires_at": NOW + 86400,
        "certificate_id": policy["certificate_id"],
        "hostnames": policy["hostnames"],
        "contact_email": policy["contact_email"],
        "acme_directory": policy["acme_directory"],
        "challenge": policy["challenge"],
        "dns_mode": intent["dns_mode"],
        "dns_zone": intent["dns_zone"],
        "credential_id": intent["credential_id"],
        "credential_revision": intent["credential_revision"],
        "consumer": owner.CONSUMER,
    }
    raw_assignment = json.dumps(
        assignment, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    assignment_sha = hashlib.sha256(raw_assignment).hexdigest()
    observation = {
        "schema": "zog-host-discover-certificate-authority-observation-v1",
        "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": ident(1),
        "installation_id": ident(2),
        "state_volume_id": ident(3),
        "registry_id": "primary",
        "authority_public_key": pin["authority_public_key"],
        "authority_key_id": key_id,
        "revision": assignment["revision"],
        "operation_id": assignment["operation_id"],
        "assignment_sha256": assignment_sha,
        "operations": [{
            "operation_id": assignment["operation_id"],
            "assignment_sha256": assignment_sha,
        }],
        "envelope": {
            "schema": "zog-certificate-assignment-envelope-v1",
            "key_id": key_id,
            "assignment": assignment,
            "signature": base64.b64encode(
                signer.sign(
                    b"zog-certificate-assignment-v1\0" + raw_assignment
                )
            ).decode("ascii"),
        },
    }
    controller = {"record_sha256": "f" * 64}
    return observation, pin, intent, policy, prepared, delivery, controller


def build_all():
    observation, pin, intent, policy, prepared, delivery, controller = fixture()
    binding = owner._binding(
        Context(), observation, pin, intent, policy, delivery, prepared
    )
    receipt = owner._owner_candidate(observation, binding)
    ledger = owner._new_ledger(
        Context(), observation, binding, receipt, "1" * 64,
        prepared, controller, intent,
    )
    return (
        observation, pin, intent, policy, prepared, delivery,
        controller, binding, receipt, ledger,
    )


def test_reviewed_host_deploy_pr3_source_is_exact():
    observed = owner.verify_reviewed_host_deploy_source(HOST_DEPLOY_SOURCE)
    assert owner.HOST_DEPLOY_COMMIT == (
        "098b6813dc1016ae748de8c5e836648a7b244c7f"
    )
    assert owner.HOST_DEPLOY_MODULE_BLOBS[
        "zog.host_deploy.certificate_hostname_authority"
    ] == "fc833cb3164e018076e2cc4a4a75aa12923c4c8d"
    assert set(observed) == set(owner.HOST_DEPLOY_MODULE_BLOBS)
    assert observed[
        "zog.host_deploy.certificate_managed_authority"
    ]["git_blob"] == "f07c0655280d9724cc59a7fc8bbd7af5e5415913"
    assert observed[
        "zog.host_deploy.certificate_hostname_authority"
    ]["git_blob"] == "fc833cb3164e018076e2cc4a4a75aa12923c4c8d"
    assert observed[
        "zog.host_deploy.certificate_delivery"
    ]["git_blob"] == "d69b59afe3060f5c92bf527c82d9aafc85127493"


def test_independent_intent_contains_no_credential_bytes():
    _obs, _pin, intent, *_ = fixture()
    assert owner._validate_intent(intent) == intent
    assert set(intent) == {
        "schema", "service_id", "dns_mode", "dns_zone",
        "credential_id", "credential_revision",
    }
    assert not any(
        word in json.dumps(intent).lower()
        for word in ("token", "secret", "password", "private_key")
    )


@pytest.mark.parametrize("change", [
    {"credential_revision": 0},
    {"credential_id": None},
    {"dns_zone": "Example.org"},
    {"service_id": "../nginx"},
])
def test_invalid_local_intent_fails_closed(change):
    _obs, _pin, intent, *_ = fixture()
    with pytest.raises(StateError):
        owner._validate_intent({**intent, **change})


def test_local_binding_joins_signed_assignment_policy_and_prepared_issuer():
    observation, pin, intent, policy, prepared, delivery, _controller = fixture()
    binding = owner._binding(
        Context(), observation, pin, intent, policy, delivery, prepared
    )
    assert binding["schema"] == owner.BINDING_SCHEMA
    assert binding["consumer"] == "host-nginx-https"
    assert binding["service_id"] == "candidate-nginx"
    assert binding["policy_sha256"] == "a" * 64
    assert binding["credential_revision"] == 3
    assert binding["host_id"] == observation["host_id"]
    assert binding["installation_id"] == ident(2)
    assert binding["state_volume_id"] == ident(3)


def test_signed_assignment_cannot_replace_local_service_or_policy():
    observation, pin, intent, policy, prepared, delivery, _controller = fixture()
    wrong_delivery = {**delivery, "service_id": "other-nginx"}
    with pytest.raises(StateError, match="local delivery policy"):
        owner._binding(
            Context(), observation, pin, intent, policy,
            wrong_delivery, prepared,
        )
    wrong_policy = {**policy, "policy_sha256": "9" * 64}
    with pytest.raises(StateError, match="local delivery policy"):
        owner._binding(
            Context(), observation, pin, intent, wrong_policy,
            delivery, prepared,
        )


def test_pr3_real_ed25519_derivation_matches_installer_receipt():
    observation, pin, _intent, _policy, _prepared, _delivery, _controller,         binding, receipt, _ledger = build_all()
    assert owner._host_deploy_validate(
        observation, pin, binding, receipt, now=NOW
    ) == receipt


def test_owner_ledger_is_idempotent_and_monotonic():
    *_, receipt, first = build_all()
    validated = owner._validate_ledger(copy.deepcopy(first))
    assert validated == first
    same, changed = owner._advance_ledger(first, copy.deepcopy(first))
    assert same == first
    assert changed is False

    newer = copy.deepcopy(first)
    newer["revision"] = 8
    newer["operation_id"] = ident(5)
    newer["assignment_sha256"] = "2" * 64
    newer["owner_authority_sha256"] = "3" * 64
    newer["status"] = "approved"
    newer["operations"] = [{
        "revision": 8,
        "operation_id": ident(5),
        "assignment_sha256": "2" * 64,
        "owner_authority_sha256": "3" * 64,
        "status": "approved",
    }]
    advanced, changed = owner._advance_ledger(first, newer)
    assert changed is True
    assert advanced["revision"] == 8
    assert len(advanced["operations"]) == 2
    assert advanced["operations"][0] == first["operations"][0]


def test_owner_ledger_rejects_local_binding_and_issuer_drift():
    *_, first = build_all()
    for mutate in (
        lambda value: value.update(binding_sha256="9" * 64),
        lambda value: value["issuer"].update(storage_id="9" * 32),
        lambda value: value.update(delivery_policy_sha256="8" * 64),
        lambda value: value.update(local_intent_sha256="7" * 64),
    ):
        proposed = copy.deepcopy(first)
        proposed["revision"] += 1
        proposed["operation_id"] = ident(6)
        proposed["assignment_sha256"] = "4" * 64
        proposed["owner_authority_sha256"] = "5" * 64
        proposed["operations"] = [{
            "revision": proposed["revision"],
            "operation_id": proposed["operation_id"],
            "assignment_sha256": proposed["assignment_sha256"],
            "owner_authority_sha256": proposed["owner_authority_sha256"],
            "status": proposed["status"],
        }]
        mutate(proposed)
        with pytest.raises(StateError, match="drift"):
            owner._advance_ledger(first, proposed)


def test_owner_ledger_revocation_is_terminal():
    *_, first = build_all()
    revoked = copy.deepcopy(first)
    revoked["revision"] = 8
    revoked["operation_id"] = ident(7)
    revoked["assignment_sha256"] = "6" * 64
    revoked["owner_authority_sha256"] = "7" * 64
    revoked["status"] = "revoked"
    revoked["operations"] = [{
        "revision": 8,
        "operation_id": ident(7),
        "assignment_sha256": "6" * 64,
        "owner_authority_sha256": "7" * 64,
        "status": "revoked",
    }]
    terminal, changed = owner._advance_ledger(first, revoked)
    assert changed is True
    assert terminal["status"] == "revoked"

    later = copy.deepcopy(revoked)
    later["revision"] = 9
    later["operation_id"] = ident(8)
    later["assignment_sha256"] = "8" * 64
    later["owner_authority_sha256"] = "9" * 64
    later["status"] = "approved"
    later["operations"] = [{
        "revision": 9,
        "operation_id": ident(8),
        "assignment_sha256": "8" * 64,
        "owner_authority_sha256": "9" * 64,
        "status": "approved",
    }]
    with pytest.raises(StateError, match="revocation"):
        owner._advance_ledger(terminal, later)


def test_pending_transaction_exactly_fences_ledger_ahead_of_receipt():
    *_, ledger = build_all()
    transaction = owner._transaction_for(ledger)
    assert owner._validate_transaction(transaction) == transaction
    assert owner._transaction_matches_ledger(transaction, ledger)
    assert not owner._transaction_matches_ledger(
        {**transaction, "owner_authority_sha256": "0" * 64},
        ledger,
    )


def test_replace_file_is_durable_and_replaces_only_under_caller_lock(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        owner._replace_file(fd, "ledger.json", b'{"revision":1}')
        assert (tmp_path / "ledger.json").read_bytes() == b'{"revision":1}'
        owner._replace_file(fd, "ledger.json", b'{"revision":2}')
        assert (tmp_path / "ledger.json").read_bytes() == b'{"revision":2}'
        assert not (tmp_path / ".next.ledger.json").exists()
    finally:
        os.close(fd)


class FakeDistribution:
    def __init__(self, root, files, record):
        self.root = Path(root)
        self.files = files
        self.version = "0.10.6"
        self.metadata = {"Name": "host-deploy"}
        self._record = record

    def locate_file(self, value):
        return self.root / str(value)

    def read_text(self, name):
        assert name == "RECORD"
        return self._record


def fake_installed_host_deploy(tmp_path):
    root = tmp_path / "site-packages"
    rows = []
    files = []
    for module, source_relative in owner.HOST_DEPLOY_SOURCE_FILES.items():
        relative = Path(source_relative.removeprefix("src/"))
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        data = (HOST_DEPLOY_SOURCE / source_relative).read_bytes()
        target.write_bytes(data)
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(data).digest()
        ).rstrip(b"=").decode()
        rows.append(f"{relative.as_posix()},sha256={digest},{len(data)}")
        files.append(relative)
    record_relative = Path("host_deploy-0.10.6.dist-info/RECORD")
    path = root / record_relative
    path.parent.mkdir(parents=True, exist_ok=True)
    rows.append(f"{record_relative.as_posix()},,")
    record = "\n".join(rows) + "\n"
    path.write_text(record)
    files.append(record_relative)
    return root, FakeDistribution(root, files, record)


def test_installed_host_deploy_attestation_checks_pr3_modules_and_record(
    tmp_path, monkeypatch
):
    root, distribution = fake_installed_host_deploy(tmp_path)
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(owner.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(owner, "_protected_ancestry", lambda *a, **k: None)
    monkeypatch.setattr(
        owner.importlib.metadata, "distribution", lambda name: distribution
    )
    result = owner.attest_installed_host_deploy(
        python_executable="/usr/bin/python3",
        distribution_name="host-deploy",
    )
    assert result["source_commit"] == owner.HOST_DEPLOY_COMMIT
    assert set(result["modules"]) == set(owner.HOST_DEPLOY_MODULE_BLOBS)
    assert result["distribution"]["record_sha256"]
    for value in result["modules"].values():
        assert value["origin"].startswith(str(root))


def test_installed_host_deploy_attestation_rejects_tamper(tmp_path, monkeypatch):
    root, distribution = fake_installed_host_deploy(tmp_path)
    target = (
        root / "zog/host_deploy/certificate_managed_authority.py"
    )
    target.write_bytes(target.read_bytes() + b"\n# changed\n")
    monkeypatch.setattr(owner.os, "geteuid", lambda: 0)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.delenv("PYTHONHOME", raising=False)
    monkeypatch.setattr(owner.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(owner, "_protected_ancestry", lambda *a, **k: None)
    monkeypatch.setattr(
        owner.importlib.metadata, "distribution", lambda name: distribution
    )
    with pytest.raises(StateError, match="differ from reviewed PR #3"):
        owner.attest_installed_host_deploy(
            python_executable="/usr/bin/python3",
            distribution_name="host-deploy",
        )
