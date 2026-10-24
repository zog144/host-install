"""Installer-owned managed certificate authority and issuer-state binding.

This module does not enroll a Host, approve a station, issue a certificate, read
provider secrets, mutate DNS, reload nginx, or run Certbot.  It joins three
already-independent trust sources:

* an independently authenticated station signer pin installed under /etc/zog;
* host-discover's root-owned signed assignment checkpoint on verified STATE;
* locally reviewed certify-manage + host-deploy consumer policy and prepared
  issuer identity/storage.

host-discover remains owner of its first monotonic root history.  host-install
owns a second durable owner ledger and the root receipt consumed by host-deploy.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from .certify_manage_profile import (
    attest_installed_controller,
    attest_prepared,
)
from .state_contract import CONFIG, StateError, canonical, decode, fields, require, sha
from .state_inspect import directory, inspect_live, metadata, read_at
from .state_io import ensure_directory, lock, publish

HOST_DEPLOY_COMMIT = "098b6813dc1016ae748de8c5e836648a7b244c7f"
HOST_DEPLOY_MODULE_BLOBS = {
    "zog.host_deploy.certificate_managed_authority":
        "f07c0655280d9724cc59a7fc8bbd7af5e5415913",
    "zog.host_deploy.certificate_hostname_authority":
        "fc833cb3164e018076e2cc4a4a75aa12923c4c8d",
    "zog.host_deploy.certificate_delivery":
        "d69b59afe3060f5c92bf527c82d9aafc85127493",
}
HOST_DEPLOY_SOURCE_FILES = {
    module: "src/" + module.replace(".", "/") + ".py"
    for module in HOST_DEPLOY_MODULE_BLOBS
}

PIN_KIND = "zog-certificate-assignment-authority-pin"
PIN_NAME = "certificate-assignment-authority.json"
PIN_PATH = "/etc/zog/host-install/" + PIN_NAME

INTENT_SCHEMA = "zog-host-install-certificate-owner-intent-v1"
INTENT_NAME = "certificate-owner-intent.json"
INTENT_PATH = "/etc/zog/host-install/" + INTENT_NAME

BINDING_SCHEMA = "zog-host-deploy-managed-certificate-consumer-binding-v1"
BINDING_PATH = "/etc/zog/host-deploy/certificate-managed-binding.json"

OWNER_SCHEMA = "zog-host-deploy-certificate-owner-authority-v1"
OWNER_DIR = "/state/host-install/certificate-owner-authority"
OWNER_PATH = OWNER_DIR + "/authority.json"
LEDGER_SCHEMA = "zog-host-install-certificate-owner-ledger-v1"
LEDGER_NAME = "ledger.json"
OWNER_NAME = "authority.json"
TRANSACTION_NAME = "transaction.json"
LOCK_NAME = "lock"

POLICY_PATH = "/etc/zog/certify-policy/policy.json"
CONSUMER = "host-nginx-https"

_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OPAQUE32 = re.compile(r"[0-9a-f]{32}\Z")
_MAX_OPERATIONS = 128


def _digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _git_blob(data):
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _record_sha256(data):
    return base64.urlsafe_b64encode(
        hashlib.sha256(data).digest()
    ).rstrip(b"=").decode()


def _validate_uuid(value, label):
    require(type(value) is str and _UUID.fullmatch(value),
            "certificate-owner", label)
    import uuid
    try:
        require(str(uuid.UUID(value)) == value, "certificate-owner", label)
    except (TypeError, ValueError, AttributeError) as exc:
        raise StateError("certificate-owner", label) from exc
    return value


def _protected_ancestry(path, stop=Path("/")):
    path = Path(path)
    stop = Path(stop)
    require(path.is_absolute() and stop.is_absolute(),
            "certificate-owner-installed", "protected path must be absolute")
    try:
        path.relative_to(stop)
    except ValueError:
        require(False, "certificate-owner-installed",
                "installed path is outside approved root")
    current = path
    while True:
        info = current.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and info.st_uid == 0
            and not (info.st_mode & 0o022),
            "certificate-owner-installed",
            "installed source ancestry is redirected or writable",
        )
        if current == stop:
            break
        current = current.parent


def verify_reviewed_host_deploy_source(source):
    """Verify exact PR #3 authority/delivery modules without executing checkout code."""
    root = Path(source)
    require(root.is_dir() and not root.is_symlink(),
            "certificate-owner-source", "reviewed host-deploy source unavailable")
    result = {}
    for module, relative in HOST_DEPLOY_SOURCE_FILES.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                "certificate-owner-source", "reviewed host-deploy module missing")
        data = path.read_bytes()
        require(0 < len(data) <= 2_000_000,
                "certificate-owner-source", "reviewed host-deploy module too large")
        blob = _git_blob(data)
        require(blob == HOST_DEPLOY_MODULE_BLOBS[module],
                "certificate-owner-source",
                "host-deploy authority/delivery source differs from reviewed PR #3")
        result[module] = {
            "path": relative,
            "git_blob": blob,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return result


def attest_installed_host_deploy(*, python_executable="/usr/bin/python3",
                                 distribution_name="host-deploy"):
    """Attest the exact local authority/delivery implementation and its RECORD."""
    require(os.geteuid() == 0, "root-required",
            "installed host-deploy attestation requires root")
    require(distribution_name in ("host-deploy", "zog"),
            "certificate-owner-installed", "unsupported host-deploy distribution")
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "certificate-owner-installed",
            "caller-selected Python import paths are not permitted")
    configured = Path(python_executable)
    require(configured.is_absolute() and configured.exists(),
            "certificate-owner-installed", "approved Python executable unavailable")
    running = Path(sys.executable).resolve()
    require(configured.resolve() == running,
            "certificate-owner-installed", "attestation interpreter differs")
    _protected_ancestry(running)

    try:
        dist = importlib.metadata.distribution(distribution_name)
    except importlib.metadata.PackageNotFoundError:
        require(False, "certificate-owner-installed",
                "selected host-deploy distribution is unavailable")
    require(dist.metadata.get("Name", "").lower() == distribution_name.lower(),
            "certificate-owner-installed", "unexpected distribution name")
    if distribution_name == "host-deploy":
        require(dist.version == "0.10.6",
                "certificate-owner-installed",
                "standalone host-deploy version differs from reviewed PR #3")
    root = Path(dist.locate_file("")).resolve()
    _protected_ancestry(root)
    text = dist.read_text("RECORD")
    require(type(text) is str and 0 < len(text) <= 4_000_000,
            "certificate-owner-installed", "installed RECORD missing or excessive")
    rows = {}
    for row in csv.reader(io.StringIO(text)):
        require(len(row) == 3 and row[0] not in rows,
                "certificate-owner-installed", "invalid installed RECORD")
        rows[row[0]] = row[1]
    record_files = [
        item for item in dist.files or ()
        if str(item).endswith(".dist-info/RECORD")
    ]
    require(len(record_files) == 1,
            "certificate-owner-installed", "installed RECORD path is ambiguous")
    record_path = Path(dist.locate_file(record_files[0]))
    _protected_ancestry(record_path, root)
    info = record_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            "certificate-owner-installed",
            "installed RECORD is not a protected regular file")

    modules = {}
    for module, expected in HOST_DEPLOY_MODULE_BLOBS.items():
        relative = HOST_DEPLOY_SOURCE_FILES[module][len("src/"):]
        path = root / relative
        _protected_ancestry(path, root)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "certificate-owner-installed",
                "host-deploy module is not a protected regular file")
        data = path.read_bytes()
        require(_git_blob(data) == expected,
                "certificate-owner-installed",
                "installed host-deploy bytes differ from reviewed PR #3")
        relative_text = Path(relative).as_posix()
        require(relative_text in rows,
                "certificate-owner-installed",
                "host-deploy module absent from installed RECORD")
        algorithm, sep, encoded = rows[relative_text].partition("=")
        require(sep == "=" and algorithm == "sha256"
                and encoded == _record_sha256(data),
                "certificate-owner-installed",
                "installed RECORD disagrees with host-deploy module")
        modules[module] = {
            "origin": str(path.resolve()),
            "git_blob": expected,
            "sha256": hashlib.sha256(data).hexdigest(),
            "record_path": relative_text,
        }
    return {
        "schema": "zog-host-install-host-deploy-installed-attestation-v1",
        "status": "host-deploy-authority-consumer-verified",
        "source_commit": HOST_DEPLOY_COMMIT,
        "distribution": {
            "name": dist.metadata["Name"],
            "version": dist.version,
            "record_origin": str(record_path),
            "record_sha256": hashlib.sha256(text.encode()).hexdigest(),
        },
        "modules": modules,
        "production_activation_authorized": False,
    }


def _validate_pin(value, *, expected_key_id=None, expected_registry=None):
    from zog.host_identify import signatures

    fields(value, "schema kind registry_id authority_public_key authority_key_id")
    require(
        type(value["schema"]) is int and value["schema"] == 1
        and value["kind"] == PIN_KIND
        and type(value["registry_id"]) is str
        and 1 <= len(value["registry_id"]) <= 64
        and type(value["authority_key_id"]) is str
        and _HEX.fullmatch(value["authority_key_id"]),
        "certificate-authority-pin", "unsupported assignment authority pin",
    )
    try:
        key = signatures.public_key(value["authority_public_key"])
    except (TypeError, ValueError) as exc:
        raise StateError(
            "certificate-authority-pin",
            "invalid assignment authority public key",
        ) from exc
    require(signatures.fingerprint(key) == value["authority_key_id"],
            "certificate-authority-pin", "assignment authority fingerprint differs")
    if expected_key_id is not None:
        require(value["authority_key_id"] == expected_key_id,
                "certificate-authority-pin",
                "pin differs from independently authenticated signer")
    if expected_registry is not None:
        require(value["registry_id"] == expected_registry,
                "certificate-authority-pin",
                "pin belongs to another registry")
    return json.loads(canonical(value))


def install_signer_pin(pin_path, expected_key_id):
    """Install an independently authenticated signer pin; never infer approval."""
    require(os.geteuid() == 0, "root-required",
            "certificate assignment signer installation requires root")
    require(type(expected_key_id) is str and _HEX.fullmatch(expected_key_id),
            "certificate-authority-pin",
            "independently authenticated expected key ID required")
    path = Path(pin_path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            "certificate-authority-pin", "pin source must be a regular file")
    raw = path.read_bytes()
    require(0 < len(raw) <= 4096,
            "certificate-authority-pin", "pin source exceeds size bound")
    value = decode(raw)

    with inspect_live() as context:
        registry = context.bundle["bootstrap"]["control_authority"]["registry_id"]
        value = _validate_pin(
            value, expected_key_id=expected_key_id, expected_registry=registry
        )
        context.recheck()
        fd = directory(CONFIG)
        try:
            metadata(fd, 0, 0, 0o755)
            with lock(fd, "certificate-authority-pin.lock"):
                publish(fd, PIN_NAME, canonical(value), 0o444)
                context.recheck()
        finally:
            os.close(fd)
        return {
            "schema": "zog-host-install-certificate-authority-pin-install-v1",
            "status": "signer-pin-installed",
            "registry_id": registry,
            "authority_key_id": expected_key_id,
            "path": PIN_PATH,
            "station_approval_performed": False,
            "state_modified": False,
        }


def _validate_intent(value):
    fields(
        value,
        "schema service_id dns_mode dns_zone credential_id credential_revision",
    )
    require(value["schema"] == INTENT_SCHEMA
            and type(value["service_id"]) is str
            and _ID.fullmatch(value["service_id"]),
            "certificate-owner-intent", "unsupported local owner intent")
    mode = value["dns_mode"]
    require(mode in (None, "local-cloudflare", "command-center-broker"),
            "certificate-owner-intent", "unsupported DNS credential mode")
    if mode is None:
        require(value["dns_zone"] is None
                and value["credential_id"] is None
                and value["credential_revision"] is None,
                "certificate-owner-intent",
                "HTTP-only intent cannot carry DNS credential identity")
    else:
        require(type(value["dns_zone"]) is str and "." in value["dns_zone"]
                and value["dns_zone"] == value["dns_zone"].lower()
                and not value["dns_zone"].endswith("."),
                "certificate-owner-intent", "canonical DNS zone required")
        if mode == "local-cloudflare":
            require(type(value["credential_id"]) is str
                    and _ID.fullmatch(value["credential_id"])
                    and type(value["credential_revision"]) is int
                    and type(value["credential_revision"]) is not bool
                    and value["credential_revision"] > 0,
                    "certificate-owner-intent",
                    "local Cloudflare credential identity/revision required")
        else:
            require(value["credential_id"] is None
                    and value["credential_revision"] is None,
                    "certificate-owner-intent",
                    "broker mode cannot install a local credential identity")
    return json.loads(canonical(value))


def install_owner_intent(intent_path):
    """Install local non-secret consumer/credential intent with no station authority."""
    require(os.geteuid() == 0, "root-required",
            "certificate owner intent installation requires root")
    path = Path(intent_path)
    require(path.is_absolute() and path.is_file() and not path.is_symlink(),
            "certificate-owner-intent", "intent source must be a regular file")
    raw = path.read_bytes()
    require(0 < len(raw) <= 8192,
            "certificate-owner-intent", "intent source exceeds size bound")
    value = _validate_intent(decode(raw))
    fd = directory(CONFIG)
    try:
        metadata(fd, 0, 0, 0o755)
        with lock(fd, "certificate-owner-intent.lock"):
            publish(fd, INTENT_NAME, canonical(value), 0o600)
    finally:
        os.close(fd)
    return {
        "schema": "zog-host-install-certificate-owner-intent-install-v1",
        "status": "local-owner-intent-installed",
        "path": INTENT_PATH,
        "credential_bytes_installed": False,
        "production_activation_authorized": False,
    }


def _installed_pin():
    fd = directory(CONFIG)
    try:
        return _validate_pin(decode(read_at(fd, PIN_NAME, 0, 0, 0o444)))
    finally:
        os.close(fd)


def _installed_intent():
    fd = directory(CONFIG)
    try:
        return _validate_intent(decode(read_at(fd, INTENT_NAME, 0, 0, 0o600)))
    finally:
        os.close(fd)


def _issuer_policy():
    from zog.certify_manage.model import Authorization
    from zog.certify_manage.security import trusted_policy

    raw = trusted_policy(Path(POLICY_PATH))
    require(type(raw) is bytes and 0 < len(raw) <= 65536,
            "certificate-owner-policy", "issuer policy is unavailable or excessive")
    try:
        parsed = json.loads(raw)
        authorization = Authorization.from_dict(parsed)
    except (TypeError, ValueError) as exc:
        raise StateError(
            "certificate-owner-policy", "issuer policy is invalid"
        ) from exc
    return authorization, {
        "certificate_id": authorization.certificate_id,
        "hostnames": list(authorization.hostnames),
        "contact_email": authorization.email,
        "acme_directory": authorization.acme_directory,
        "challenge": authorization.challenge,
        "dns_plugin": authorization.dns_plugin,
        "policy_sha256": authorization.fingerprint,
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _root_authority(context, pin):
    from zog.host_discover import supervisor

    value = supervisor.inspect_authority(context)
    require(
        value["installation_id"] == context.bundle["bootstrap"]["installation_id"]
        and value["state_volume_id"]
        == context.bundle["bootstrap"]["state"]["state_volume_id"]
        and value["registry_id"] == pin["registry_id"]
        and value["authority_public_key"] == pin["authority_public_key"]
        and value["authority_key_id"] == pin["authority_key_id"],
        "certificate-owner-authority",
        "root checkpoint disagrees with installation or signer pin",
    )
    return value


def _binding(context, authority, pin, intent, policy, delivery, prepared):
    assignment = authority["envelope"]["assignment"]
    challenge = policy["challenge"]
    if challenge == "http-01":
        require(intent["dns_mode"] is None,
                "certificate-owner-binding",
                "HTTP-01 cannot consume DNS credential intent")
        dns_mode = dns_zone = credential_id = credential_revision = None
    else:
        require(policy["dns_plugin"] == "dns-cloudflare"
                and intent["dns_mode"] in ("local-cloudflare",
                                           "command-center-broker"),
                "certificate-owner-binding",
                "DNS-01 requires reviewed Cloudflare credential mode")
        dns_mode = intent["dns_mode"]
        dns_zone = intent["dns_zone"]
        credential_id = intent["credential_id"]
        credential_revision = intent["credential_revision"]

    require(delivery["service_id"] == intent["service_id"]
            and delivery["certificate_id"] == policy["certificate_id"]
            and delivery["hostnames"] == policy["hostnames"]
            and delivery["policy_sha256"] == policy["policy_sha256"]
            and delivery["issuer_uid"] == prepared["issuer_uid"]
            and delivery["peer_uid"] == prepared["issuer_uid"]
            and delivery["issuer_state"] == prepared["certificate_data_path"],
            "certificate-owner-binding",
            "local delivery policy disagrees with issuer or certificate policy")

    binding = {
        "schema": BINDING_SCHEMA,
        "host_id": authority["host_id"],
        "installation_id": context.bundle["bootstrap"]["installation_id"],
        "state_volume_id": context.bundle["bootstrap"]["state"]["state_volume_id"],
        "registry_id": pin["registry_id"],
        "authority_key_id": pin["authority_key_id"],
        "consumer": CONSUMER,
        "service_id": intent["service_id"],
        "certificate_id": policy["certificate_id"],
        "hostnames": policy["hostnames"],
        "policy_sha256": policy["policy_sha256"],
        "challenge": challenge,
        "dns_mode": dns_mode,
        "dns_zone": dns_zone,
        "credential_id": credential_id,
        "credential_revision": credential_revision,
        "contact_email": policy["contact_email"],
        "acme_directory": policy["acme_directory"],
    }
    signed_fields = (
        "consumer", "certificate_id", "hostnames", "challenge", "dns_mode",
        "dns_zone", "credential_id", "credential_revision", "contact_email",
        "acme_directory",
    )
    require(all(assignment[key] == binding[key] for key in signed_fields),
            "certificate-owner-binding",
            "signed assignment differs from independently installed local binding")
    return binding


def _owner_candidate(authority, binding):
    assignment = authority["envelope"]["assignment"]
    return {
        "schema": OWNER_SCHEMA,
        "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": binding["host_id"],
        "installation_id": binding["installation_id"],
        "operation_id": authority["operation_id"],
        "revision": authority["revision"],
        "status": assignment["status"],
        "approved_at": assignment["approved_at"],
        "expires_at": assignment["expires_at"],
        "revoked_at": assignment["revoked_at"],
        "certificate_id": binding["certificate_id"],
        "service_id": binding["service_id"],
        "hostnames": list(binding["hostnames"]),
        "policy_sha256": binding["policy_sha256"],
        "challenge": binding["challenge"],
        "dns_mode": binding["dns_mode"],
        "dns_zone": binding["dns_zone"],
        "credential_id": binding["credential_id"],
        "credential_revision": binding["credential_revision"],
    }


def _delivery_policy(path):
    from zog.host_deploy import certificate_delivery

    value = certificate_delivery.read_policy(path)
    return value, _digest(value)


def _host_deploy_validate(authority, pin, binding, owner, *, now, previous=None):
    from zog.host_deploy import certificate_hostname_authority as owner_mod
    from zog.host_deploy import certificate_managed_authority as managed

    owner_mod.validate(owner)
    if previous is not None:
        owner_mod.compare_revision(previous, owner)

    assignment = authority["envelope"]["assignment"]
    if assignment["status"] == "approved" and assignment["expires_at"] > now:
        # Public derivation is stricter than structural validation and proves the
        # current approved path maps exactly to the consumer receipt.
        derived = managed.derive_managed_owner_authority(
            authority, pin, binding, now=now, previous=previous
        )
        require(derived == owner, "certificate-owner-binding",
                "host-deploy managed derivation disagrees with installer receipt")
    else:
        # Revocation/expiry still has to advance the second monotonic ledger so
        # an older approval can never be resurrected.  host-deploy intentionally
        # refuses such receipts for delivery, while structural owner validation
        # plus compare_revision preserves the terminal history here.
        managed._pin(pin)
        managed._valid_binding(binding)
    return owner


def _ledger_entry(authority, owner):
    return {
        "revision": authority["revision"],
        "operation_id": authority["operation_id"],
        "assignment_sha256": authority["assignment_sha256"],
        "owner_authority_sha256": _digest(owner),
        "status": owner["status"],
    }


def _new_ledger(context, authority, binding, owner, delivery_digest,
                issuer, controller, intent):
    entry = _ledger_entry(authority, owner)
    return {
        "schema": LEDGER_SCHEMA,
        "installation_id": context.bundle["bootstrap"]["installation_id"],
        "state_volume_id": context.bundle["bootstrap"]["state"]["state_volume_id"],
        "registry_id": binding["registry_id"],
        "authority_key_id": binding["authority_key_id"],
        "service_id": binding["service_id"],
        "certificate_id": binding["certificate_id"],
        "binding_sha256": _digest(binding),
        "delivery_policy_sha256": delivery_digest,
        "issuer": {
            "storage_id": issuer["storage_id"],
            "grant_id": issuer["grant_id"],
            "uid": issuer["issuer_uid"],
            "gid": issuer["issuer_gid"],
            "software_view": issuer["software_view"],
            "certificate_data_path": issuer["certificate_data_path"],
            "controller_record_sha256": controller["record_sha256"],
        },
        "local_intent_sha256": _digest(intent),
        "revision": entry["revision"],
        "operation_id": entry["operation_id"],
        "assignment_sha256": entry["assignment_sha256"],
        "owner_authority_sha256": entry["owner_authority_sha256"],
        "status": entry["status"],
        "operations": [entry],
    }


def _validate_ledger(value):
    required = {
        "schema", "installation_id", "state_volume_id", "registry_id",
        "authority_key_id", "service_id", "certificate_id", "binding_sha256",
        "delivery_policy_sha256", "issuer", "local_intent_sha256", "revision",
        "operation_id", "assignment_sha256", "owner_authority_sha256",
        "status", "operations",
    }
    require(type(value) is dict and set(value) == required
            and value["schema"] == LEDGER_SCHEMA,
            "certificate-owner-ledger", "unsupported owner ledger")
    for key in ("installation_id", "state_volume_id", "operation_id"):
        _validate_uuid(value[key], "invalid ledger " + key)
    for key in ("authority_key_id", "binding_sha256",
                "delivery_policy_sha256", "local_intent_sha256",
                "assignment_sha256", "owner_authority_sha256"):
        require(type(value[key]) is str and _HEX.fullmatch(value[key]),
                "certificate-owner-ledger", "invalid ledger digest")
    for key in ("registry_id", "service_id", "certificate_id"):
        require(type(value[key]) is str and 1 <= len(value[key]) <= 64,
                "certificate-owner-ledger", "invalid ledger identity")
    require(type(value["revision"]) is int and 1 <= value["revision"] < 2**53
            and value["status"] in ("approved", "revoked"),
            "certificate-owner-ledger", "invalid ledger revision/status")
    issuer = value["issuer"]
    require(type(issuer) is dict and set(issuer) == {
                "storage_id", "grant_id", "uid", "gid", "software_view",
                "certificate_data_path", "controller_record_sha256",
            }
            and type(issuer["storage_id"]) is str
            and _OPAQUE32.fullmatch(issuer["storage_id"])
            and type(issuer["grant_id"]) is str
            and _OPAQUE32.fullmatch(issuer["grant_id"])
            and type(issuer["uid"]) is int and issuer["uid"] >= 1000
            and type(issuer["gid"]) is int and issuer["gid"] >= 1000
            and type(issuer["software_view"]) is str
            and _SHA.fullmatch(issuer["software_view"])
            and type(issuer["certificate_data_path"]) is str
            and issuer["certificate_data_path"].startswith("/")
            and type(issuer["controller_record_sha256"]) is str
            and _HEX.fullmatch(issuer["controller_record_sha256"]),
            "certificate-owner-ledger", "invalid issuer binding")
    operations = value["operations"]
    require(type(operations) is list and 1 <= len(operations) <= _MAX_OPERATIONS,
            "certificate-owner-ledger", "invalid owner operation history")
    seen = set()
    current = None
    for row in operations:
        require(type(row) is dict and set(row) == {
                    "revision", "operation_id", "assignment_sha256",
                    "owner_authority_sha256", "status",
                }
                and type(row["revision"]) is int
                and 1 <= row["revision"] < 2**53
                and type(row["operation_id"]) is str
                and _UUID.fullmatch(row["operation_id"])
                and type(row["assignment_sha256"]) is str
                and _HEX.fullmatch(row["assignment_sha256"])
                and type(row["owner_authority_sha256"]) is str
                and _HEX.fullmatch(row["owner_authority_sha256"])
                and row["status"] in ("approved", "revoked"),
                "certificate-owner-ledger", "invalid owner history entry")
        require(row["operation_id"] not in seen,
                "certificate-owner-ledger", "replayed owner operation")
        seen.add(row["operation_id"])
        if row["operation_id"] == value["operation_id"]:
            current = row
    require(current is not None
            and current["revision"] == value["revision"]
            and current["assignment_sha256"] == value["assignment_sha256"]
            and current["owner_authority_sha256"]
            == value["owner_authority_sha256"]
            and current["status"] == value["status"],
            "certificate-owner-ledger", "current owner history entry mismatch")
    return value


def _advance_ledger(previous, proposed):
    _validate_ledger(proposed)
    if previous is None:
        return proposed, True
    _validate_ledger(previous)
    stable = (
        "installation_id", "state_volume_id", "registry_id", "authority_key_id",
        "service_id", "certificate_id", "binding_sha256",
        "delivery_policy_sha256", "issuer", "local_intent_sha256",
    )
    require(all(previous[key] == proposed[key] for key in stable),
            "certificate-owner-ledger",
            "local authority/issuer binding drift requires explicit migration")
    require(proposed["revision"] >= previous["revision"],
            "certificate-owner-ledger", "stale owner revision")
    if proposed["revision"] == previous["revision"]:
        require(proposed["operation_id"] == previous["operation_id"]
                and proposed["assignment_sha256"] == previous["assignment_sha256"]
                and proposed["owner_authority_sha256"]
                == previous["owner_authority_sha256"]
                and proposed["status"] == previous["status"],
                "certificate-owner-ledger",
                "same owner revision changed contents")
        return previous, False
    require(proposed["operation_id"] not in {
                row["operation_id"] for row in previous["operations"]
            },
            "certificate-owner-ledger", "owner operation replay")
    require(not (previous["status"] == "revoked"
                 and proposed["status"] != "revoked"),
            "certificate-owner-ledger", "revocation is terminal")
    require(len(previous["operations"]) < _MAX_OPERATIONS,
            "certificate-owner-ledger", "owner operation history full")
    result = dict(proposed)
    result["operations"] = list(previous["operations"]) + [{
        "revision": proposed["revision"],
        "operation_id": proposed["operation_id"],
        "assignment_sha256": proposed["assignment_sha256"],
        "owner_authority_sha256": proposed["owner_authority_sha256"],
        "status": proposed["status"],
    }]
    return _validate_ledger(result), True


def _replace_file(fd, name, data, mode=0o600):
    require(type(data) is bytes and 0 < len(data) <= 65536,
            "certificate-owner-publication", "invalid publication size")
    pending = ".next." + name
    try:
        os.unlink(pending, dir_fd=fd)
    except FileNotFoundError:
        pass
    handle = os.open(
        pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=fd,
    )
    try:
        os.fchmod(handle, mode)
        view = memoryview(data)
        while view:
            written = os.write(handle, view)
            require(written > 0, "certificate-owner-publication", "short write")
            view = view[written:]
        os.fsync(handle)
    finally:
        os.close(handle)
    os.fsync(fd)
    os.replace(pending, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def _read_json(fd, name, *, required=False):
    try:
        handle = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
        )
    except FileNotFoundError:
        if required:
            require(False, "certificate-owner-ledger", "required owner record missing")
        return None
    try:
        info = os.fstat(handle)
        require(stat.S_ISREG(info.st_mode)
                and info.st_uid == 0 and info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_size <= 65536,
                "certificate-owner-ledger", "unsafe owner record")
        data = bytearray()
        while len(data) <= 65536:
            part = os.read(handle, min(8192, 65537 - len(data)))
            if not part:
                break
            data.extend(part)
    finally:
        os.close(handle)
    require(len(data) <= 65536,
            "certificate-owner-ledger", "owner record too large")
    return decode(bytes(data))


def _validate_transaction(value):
    required = {
        "schema", "revision", "operation_id", "assignment_sha256",
        "owner_authority_sha256", "binding_sha256",
        "delivery_policy_sha256", "issuer_sha256",
    }
    require(type(value) is dict and set(value) == required
            and value["schema"]
            == "zog-host-install-certificate-owner-transaction-v1"
            and type(value["revision"]) is int
            and 1 <= value["revision"] < 2**53
            and type(value["operation_id"]) is str
            and _UUID.fullmatch(value["operation_id"]),
            "certificate-owner-ledger", "invalid pending owner transaction")
    for key in (
        "assignment_sha256", "owner_authority_sha256", "binding_sha256",
        "delivery_policy_sha256", "issuer_sha256",
    ):
        require(type(value[key]) is str and _HEX.fullmatch(value[key]),
                "certificate-owner-ledger",
                "invalid pending owner transaction digest")
    return value


def _transaction_for(ledger):
    return {
        "schema": "zog-host-install-certificate-owner-transaction-v1",
        "revision": ledger["revision"],
        "operation_id": ledger["operation_id"],
        "assignment_sha256": ledger["assignment_sha256"],
        "owner_authority_sha256": ledger["owner_authority_sha256"],
        "binding_sha256": ledger["binding_sha256"],
        "delivery_policy_sha256": ledger["delivery_policy_sha256"],
        "issuer_sha256": _digest(ledger["issuer"]),
    }


def _transaction_matches_ledger(transaction, ledger):
    transaction = _validate_transaction(transaction)
    return transaction == _transaction_for(ledger)


def _owner_directory(context, *, create=True):
    host_install = os.open(
        "host-install", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=context.fd,
    )
    try:
        metadata(host_install, 0, 0, 0o755)
        if create:
            owner = ensure_directory(
                host_install, "certificate-owner-authority", 0, 0, 0o700
            )
        else:
            owner = os.open(
                "certificate-owner-authority",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=host_install,
            )
            metadata(owner, 0, 0, 0o700)
            require(os.fstat(owner).st_dev == os.fstat(context.fd).st_dev,
                    "nested-mount", "certificate-owner-authority")
    finally:
        os.close(host_install)
    return owner


def _install_binding(binding):
    etc = directory("/etc/zog")
    child = None
    try:
        metadata(etc, 0, 0, 0o755)
        child = ensure_directory(etc, "host-deploy", 0, 0, 0o755)
        with lock(child, "certificate-managed-binding.lock"):
            publish(
                child, "certificate-managed-binding.json",
                canonical(binding), 0o600,
            )
    finally:
        if child is not None:
            os.close(child)
        os.close(etc)


def _candidate_ledger(context, authority, binding, owner, delivery_digest,
                      issuer, controller, intent):
    return _new_ledger(
        context, authority, binding, owner, delivery_digest,
        issuer, controller, intent,
    )


def reconcile_live(*, controller_project, root_control_socket,
                   expected_software_view, delivery_policy,
                   python_executable="/usr/bin/python3",
                   host_deploy_distribution="host-deploy",
                   checkpoint=lambda _: None):
    """Install binding + second owner ledger/receipt; never execute delivery."""
    require(os.geteuid() == 0, "root-required",
            "certificate owner reconciliation requires root")
    host_deploy = attest_installed_host_deploy(
        python_executable=python_executable,
        distribution_name=host_deploy_distribution,
    )
    controller = attest_installed_controller(
        python_executable=python_executable,
    )
    issuer = attest_prepared(
        controller_project=controller_project,
        root_control_socket=root_control_socket,
        expected_software_view=expected_software_view,
    )
    authorization, policy = _issuer_policy()
    intent = _installed_intent()
    pin = _installed_pin()
    delivery, delivery_digest = _delivery_policy(delivery_policy)

    with inspect_live() as context:
        context.recheck()
        authority = _root_authority(context, pin)
        binding = _binding(
            context, authority, pin, intent, policy, delivery, issuer
        )
        owner = _owner_candidate(authority, binding)
        now = int(time.time())

        # Verify the exact reviewed host-deploy semantics before publishing any
        # new consumer binding or second owner receipt.
        _host_deploy_validate(
            authority, pin, binding, owner, now=now, previous=None
        )
        _install_binding(binding)
        context.recheck()

        owner_fd = _owner_directory(context)
        try:
            with lock(owner_fd, LOCK_NAME):
                previous_ledger = _read_json(owner_fd, LEDGER_NAME)
                previous_owner = _read_json(owner_fd, OWNER_NAME)
                pending = _read_json(owner_fd, TRANSACTION_NAME)
                if pending is not None:
                    _validate_transaction(pending)
                if previous_ledger is not None:
                    _validate_ledger(previous_ledger)
                    require(previous_owner is not None,
                            "certificate-owner-ledger",
                            "durable ledger has no owner receipt")
                    owner_matches_ledger = (
                        _digest(previous_owner)
                        == previous_ledger["owner_authority_sha256"]
                    )
                    if not owner_matches_ledger:
                        require(
                            pending is not None
                            and _transaction_matches_ledger(
                                pending, previous_ledger
                            ),
                            "certificate-owner-ledger",
                            "torn owner publication lacks matching transaction",
                        )
                    _host_deploy_validate(
                        authority, pin, binding, owner, now=now,
                        previous=previous_owner,
                    )
                else:
                    require(previous_owner is None and pending is None,
                            "certificate-owner-ledger",
                            "owner state exists without durable ledger")

                proposed = _candidate_ledger(
                    context, authority, binding, owner, delivery_digest,
                    issuer, controller, intent,
                )
                ledger, changed = _advance_ledger(previous_ledger, proposed)
                transaction = _transaction_for(ledger)
                _replace_file(
                    owner_fd, TRANSACTION_NAME, canonical(transaction)
                )
                checkpoint("intent")

                if changed:
                    _replace_file(owner_fd, LEDGER_NAME, canonical(ledger))
                checkpoint("ledger")
                _replace_file(owner_fd, OWNER_NAME, canonical(owner))
                checkpoint("authority")

                # The producer's root checkpoint can legitimately advance while
                # this installer transaction is running.  Never report ready
                # until the exact revision/operation/digest is observed again.
                current = _root_authority(context, pin)
                require(
                    current["revision"] == authority["revision"]
                    and current["operation_id"] == authority["operation_id"]
                    and current["assignment_sha256"]
                    == authority["assignment_sha256"],
                    "certificate-owner-authority",
                    "root authority advanced during owner publication; reconcile again",
                )
                context.recheck()
                os.unlink(TRANSACTION_NAME, dir_fd=owner_fd)
                os.fsync(owner_fd)
                checkpoint("complete")
        finally:
            os.close(owner_fd)

        return {
            "schema": "zog-host-install-certificate-owner-reconcile-v1",
            "status": (
                "owner-authority-ready"
                if owner["status"] == "approved" and owner["expires_at"] > now
                else "owner-authority-blocked"
            ),
            "host_id": binding["host_id"],
            "installation_id": binding["installation_id"],
            "state_volume_id": binding["state_volume_id"],
            "registry_id": binding["registry_id"],
            "authority_key_id": binding["authority_key_id"],
            "revision": authority["revision"],
            "operation_id": authority["operation_id"],
            "assignment_sha256": authority["assignment_sha256"],
            "binding_path": BINDING_PATH,
            "binding_sha256": _digest(binding),
            "owner_authority_path": OWNER_PATH,
            "owner_authority_sha256": _digest(owner),
            "delivery_policy_sha256": delivery_digest,
            "issuer": ledger["issuer"],
            "host_deploy_source_commit": HOST_DEPLOY_COMMIT,
            "host_deploy_record_sha256":
                host_deploy["distribution"]["record_sha256"],
            "production_activation_authorized": False,
            "certificate_issued": False,
            "dns_modified": False,
            "nginx_modified": False,
        }


def inspect_live_owner():
    """Read-only summary of the second owner ledger/receipt and local binding."""
    require(os.geteuid() == 0, "root-required",
            "certificate owner inspection requires root")
    with inspect_live() as context:
        binding_fd = directory("/etc/zog/host-deploy")
        try:
            binding = decode(
                read_at(
                    binding_fd, "certificate-managed-binding.json",
                    0, 0, 0o600,
                )
            )
        finally:
            os.close(binding_fd)
        owner_fd = _owner_directory(context, create=False)
        try:
            ledger = _validate_ledger(
                _read_json(owner_fd, LEDGER_NAME, required=True)
            )
            owner = _read_json(owner_fd, OWNER_NAME, required=True)
            transaction = _read_json(owner_fd, TRANSACTION_NAME)
            if transaction is not None:
                _validate_transaction(transaction)
        finally:
            os.close(owner_fd)
        require(_digest(binding) == ledger["binding_sha256"]
                and _digest(owner) == ledger["owner_authority_sha256"],
                "certificate-owner-ledger",
                "installed owner records disagree with ledger")
        context.recheck()
        return {
            "schema": "zog-host-install-certificate-owner-inspection-v1",
            "status": "recovery-required" if transaction is not None else "retained",
            "installation_id": ledger["installation_id"],
            "state_volume_id": ledger["state_volume_id"],
            "registry_id": ledger["registry_id"],
            "authority_key_id": ledger["authority_key_id"],
            "service_id": ledger["service_id"],
            "certificate_id": ledger["certificate_id"],
            "revision": ledger["revision"],
            "operation_id": ledger["operation_id"],
            "assignment_sha256": ledger["assignment_sha256"],
            "status_authority": ledger["status"],
            "binding_path": BINDING_PATH,
            "binding_sha256": ledger["binding_sha256"],
            "owner_authority_path": OWNER_PATH,
            "owner_authority_sha256": ledger["owner_authority_sha256"],
            "delivery_policy_sha256": ledger["delivery_policy_sha256"],
            "local_intent_sha256": ledger["local_intent_sha256"],
            "issuer": ledger["issuer"],
            "pending_transaction": transaction,
            "production_activation_authorized": False,
        }
