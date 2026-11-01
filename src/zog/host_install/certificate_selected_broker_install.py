"""Source-only protected selected-issuer broker installation and revocation plans.

This is not an installer and never writes /etc, STATE, a broker socket or
credentials. The protected native owner must independently authenticate and
read the root records, source/RECORD, approved UID policy and disk identity.
A timer JSON or caller-provided digest cannot approve its own projection.
"""
from __future__ import annotations

import hashlib
import json
import re

from .state_contract import StateError, canonical, require

PROJECTION_SCHEMA = "zog-host-deploy-selected-issuer-broker-authority-v1"
APPROVAL_SCHEMA = "zog-host-install-selected-broker-operator-approval-v1"
RECEIPT_SCHEMA = "zog-host-install-selected-broker-install-receipt-v1"
REVOCATION_SCHEMA = "zog-host-deploy-selected-issuer-broker-revocation-v1"
REVOCATION_APPROVAL_SCHEMA = "zog-host-install-selected-broker-revocation-approval-v1"
PROJECTION_PATH = "/etc/zog/host-deploy/certificate-issuer-broker-authority.json"
REVOCATION_PATH = "/etc/zog/host-deploy/certificate-issuer-broker-revoked.json"
HOST_DEPLOY_REVIEWED_COMMIT = "9797f2f90c4c639c141bc1f98adb86e0549e657a"
HOST_DEPLOY_PROJECTION_BLOB = "8a8e1bea553f790ed50039fa1673b8165179c73c"
BOX_CONTROL_REVIEWED_COMMIT = "9111606eef306292d70fd4d941eeb73f48b33ff1"
PRIVATE_BINDING_SCHEMA = "zog-host-deploy-managed-certificate-consumer-binding-v1"
OWNER_LEDGER_SCHEMA = "zog-host-install-certificate-owner-ledger-v1"
OWNER_SCHEMA = "zog-host-deploy-certificate-owner-authority-v1"

PROJECTION_FIELDS = frozenset((
    "schema", "host_id", "installation_id", "state_volume_id",
    "certificate_id", "hostnames", "policy_sha256", "host_policy_digest",
    "issuer_lifecycle_socket", "controller_uid", "caller_uid", "issuer_uid",
    "issuer_gid", "storage_id", "grant_id", "box_control_revision",
    "consumer_binding_sha256",
))
# The independent approver explicitly selects the controller/caller UID and
# socket as well as all original issuer, policy, and service identities.
APPROVAL_FIELDS = PROJECTION_FIELDS | frozenset((
    "owner_revision", "owner_operation_id", "owner_authority_sha256",
    "root_owner_ledger_sha256", "host_deploy_source_commit",
))
REVOCATION_APPROVAL_FIELDS = frozenset((
    "schema", "projection_sha256", "install_receipt_sha256",
    "root_owner_ledger_sha256", "revoked_revision", "revoked_operation_id",
    "host_id", "installation_id", "state_volume_id", "certificate_id",
))
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_OPAQUE = re.compile(r"[0-9a-f]{32}\Z")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _valid(condition, why):
    require(condition, "selected-broker-authority", why)


def _strict(value, fields, schema):
    _valid(type(value) is dict and set(value) == fields
           and value.get("schema") == schema, "schema-or-field-mismatch")
    return value


def _canonical_bytes(data):
    _valid(type(data) is bytes and 0 < len(data) <= 8192,
           "root-record-size-invalid")
    def no_duplicates(pairs):
        out = {}
        for k, v in pairs:
            _valid(k not in out, "duplicate-root-field")
            out[k] = v
        return out
    try:
        value = json.loads(data, object_pairs_hook=no_duplicates,
                           parse_constant=lambda _: _valid(False, "nonfinite-json"))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise StateError("selected-broker-authority", "invalid-root-json") from exc
    _valid(type(value) is dict and canonical(value) == data,
           "noncanonical-root-record")
    return value


def _digest_checked(raw, independently_expected_sha):
    _valid(type(independently_expected_sha) is str
           and _HEX.fullmatch(independently_expected_sha) is not None,
           "independent-approval-required")
    _valid(_sha(raw) == independently_expected_sha,
           "independent-approval-mismatch")


def _projection_checked(row):
    _strict(row, PROJECTION_FIELDS, PROJECTION_SCHEMA)
    for key in ("host_id", "installation_id", "state_volume_id"):
        _valid(type(row[key]) is str and _UUID.fullmatch(row[key]) is not None,
               "invalid-installation-identity")
    for key in ("certificate_id",):
        _valid(type(row[key]) is str and _ID.fullmatch(row[key]) is not None,
               "invalid-certificate-id")
    _valid(type(row["hostnames"]) is list
           and 0 < len(row["hostnames"]) <= 32
           and all(type(n) is str and 1 <= len(n) <= 253 for n in row["hostnames"])
           and len(set(row["hostnames"])) == len(row["hostnames"]),
           "invalid-hostnames")
    for key in ("policy_sha256",):
        _valid(type(row[key]) is str and _HEX.fullmatch(row[key]) is not None,
               "invalid-policy")
    for key in ("consumer_binding_sha256", "host_policy_digest"):
        _valid(type(row[key]) is str and row[key].startswith("sha256:")
               and _HEX.fullmatch(row[key][7:]) is not None,
               "invalid-root-digest")
    for key in ("controller_uid", "caller_uid", "issuer_uid", "issuer_gid"):
        _valid(type(row[key]) is int and 1000 <= row[key] < 2**31,
               "invalid-selected-identity")
    _valid(len({row["controller_uid"], row["caller_uid"],
                row["issuer_uid"]}) == 3,
           "selected-role-identity-collision")
    for key in ("storage_id", "grant_id"):
        _valid(type(row[key]) is str and _OPAQUE.fullmatch(row[key]) is not None,
               "invalid-issuer-grant-storage")
    _valid(row["box_control_revision"] == BOX_CONTROL_REVIEWED_COMMIT,
           "unreviewed-broker-client")
    _valid(type(row["issuer_lifecycle_socket"]) is str
           and row["issuer_lifecycle_socket"].startswith("/run/")
           and ".." not in row["issuer_lifecycle_socket"].split("/")
           and len(row["issuer_lifecycle_socket"]) <= 107,
           "unapproved-socket")
    return row


def projection_plan(*, approval_bytes, expected_approval_sha256,
                    private_binding_bytes, owner, root_owner_ledger,
                    host_policy_digest, now):
    """Compute a protected-owner plan, never write/install/activate it.

    All root records are independently authenticated by the *caller*.
    The approval digest must be fixed out-of-band by the protected owner.
    """
    _valid(type(now) is int and now > 0, "invalid-time")
    _digest_checked(approval_bytes, expected_approval_sha256)
    approval = _strict(_canonical_bytes(approval_bytes), APPROVAL_FIELDS,
                       APPROVAL_SCHEMA)
    _valid(approval["host_deploy_source_commit"] == HOST_DEPLOY_REVIEWED_COMMIT,
           "unreviewed-host-deploy-source")
    candidate = {k: approval[k] for k in PROJECTION_FIELDS}
    candidate["schema"] = PROJECTION_SCHEMA
    _projection_checked(candidate)
    binding = _canonical_bytes(private_binding_bytes)
    _valid(binding.get("schema") == PRIVATE_BINDING_SCHEMA,
           "private-binding-schema-mismatch")
    _valid(candidate["consumer_binding_sha256"]
           == "sha256:" + _sha(private_binding_bytes),
           "private-binding-digest-mismatch")
    _valid(candidate["host_policy_digest"] == host_policy_digest,
           "root-host-policy-digest-mismatch")
    for field in ("host_id", "installation_id", "state_volume_id",
                  "certificate_id", "hostnames", "policy_sha256"):
        _valid(binding.get(field) == candidate[field],
               "private-binding-identity-mismatch")
    _valid(binding.get("consumer") == "host-nginx-https",
           "invalid-local-consumer")
    _valid(type(owner) is dict and owner.get("schema") == OWNER_SCHEMA
           and owner.get("status") == "approved"
           and type(owner.get("expires_at")) is int
           and owner["expires_at"] > now,
           "owner-not-current-approved")
    for field in ("host_id", "installation_id", "certificate_id",
                  "hostnames", "policy_sha256"):
        _valid(owner.get(field) == candidate[field],
               "root-owner-identity-mismatch")
    ledger = root_owner_ledger
    _valid(type(ledger) is dict and ledger.get("schema") == OWNER_LEDGER_SCHEMA
           and ledger.get("status") == "approved"
           and type(ledger.get("revision")) is int
           and 1 <= ledger["revision"] < 2**53
           and ledger.get("revision") == owner.get("revision")
           and ledger.get("operation_id") == owner.get("operation_id")
           and ledger.get("owner_authority_sha256") == _sha(canonical(owner))
           and ledger.get("binding_sha256") == _sha(private_binding_bytes)
           and ledger.get("installation_id") == candidate["installation_id"]
           and ledger.get("state_volume_id") == candidate["state_volume_id"]
           and ledger.get("certificate_id") == candidate["certificate_id"],
           "root-ledger-owner-mismatch")
    issuer = ledger.get("issuer")
    _valid(type(issuer) is dict
           and issuer.get("storage_id") == candidate["storage_id"]
           and issuer.get("grant_id") == candidate["grant_id"]
           and issuer.get("uid") == candidate["issuer_uid"]
           and issuer.get("gid") == candidate["issuer_gid"],
           "root-approved-issuer-mismatch")
    _valid(approval["owner_revision"] == ledger["revision"]
           and approval["owner_operation_id"] == ledger["operation_id"]
           and approval["owner_authority_sha256"] == _sha(canonical(owner))
           and approval["root_owner_ledger_sha256"] == _sha(canonical(ledger)),
           "operator-owner-checkpoint-mismatch")
    blob = canonical(candidate)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": "source-plan-only",
        "projection_sha256": _sha(blob),
        "approval_sha256": _sha(approval_bytes),
        "binding_sha256": _sha(private_binding_bytes),
        "owner_revision": ledger["revision"],
        "owner_operation_id": ledger["operation_id"],
        "host_id": candidate["host_id"],
        "installation_id": candidate["installation_id"],
        "state_volume_id": candidate["state_volume_id"],
        "certificate_id": candidate["certificate_id"],
        "root_owner_ledger_sha256": _sha(canonical(ledger)),
        "native_installation_verified": False,
        "activation_authorized": False,
    }
    return {"path": PROJECTION_PATH, "mode": 0o444, "uid": 0, "gid": 0,
            "no_replacement": True, "projection": candidate,
            "projection_bytes": blob, "receipt": receipt,
            "native_installation_authorized": False}


def no_replacement_check(existing, expected, *, revocation_present=False):
    """Never heal an ambiguous/mismatched installed authority."""
    _valid(not revocation_present, "revocation-tombstone-present")
    _valid(existing is None or (type(existing) is bytes and existing == expected),
           "installed-projection-conflict")
    return "new-only" if existing is None else "same-byte-idempotent"


def revocation_plan(*, projection_bytes, install_receipt,
                    revoked_owner, revoked_ledger,
                    approval_bytes, expected_approval_sha256):
    """Prepare an irreversible one-shot denial marker, no file mutation."""
    _digest_checked(approval_bytes, expected_approval_sha256)
    approved = _strict(_canonical_bytes(approval_bytes),
                       REVOCATION_APPROVAL_FIELDS, REVOCATION_APPROVAL_SCHEMA)
    projection = _projection_checked(_strict(
        _canonical_bytes(projection_bytes), PROJECTION_FIELDS, PROJECTION_SCHEMA
    ))
    _valid(type(install_receipt) is dict
           and install_receipt.get("schema") == RECEIPT_SCHEMA
           and install_receipt.get("projection_sha256") == _sha(projection_bytes)
           and install_receipt.get("native_installation_verified") is False,
           "original-install-receipt-mismatch")
    _valid(type(revoked_owner) is dict
           and revoked_owner.get("schema") == OWNER_SCHEMA
           and revoked_owner.get("status") == "revoked",
           "root-owner-not-revoked")
    _valid(type(revoked_ledger) is dict
           and revoked_ledger.get("schema") == OWNER_LEDGER_SCHEMA
           and revoked_ledger.get("status") == "revoked"
           and revoked_ledger.get("owner_authority_sha256")
                 == _sha(canonical(revoked_owner))
           and revoked_ledger.get("revision") == revoked_owner.get("revision")
           and revoked_ledger.get("operation_id")
                 == revoked_owner.get("operation_id")
           and type(revoked_ledger.get("revision")) is int
           and revoked_ledger["revision"] > install_receipt["owner_revision"]
           and revoked_ledger.get("binding_sha256")
                 == install_receipt["binding_sha256"],
           "revocation-checkpoint-invalid")
    _valid(revoked_owner.get("host_id") == projection["host_id"]
           and revoked_owner.get("installation_id") == projection["installation_id"]
           and revoked_owner.get("certificate_id") == projection["certificate_id"]
           and revoked_ledger.get("installation_id") == projection["installation_id"]
           and revoked_ledger.get("state_volume_id") == projection["state_volume_id"],
           "revocation-identity-mismatch")
    _valid(approved["projection_sha256"] == _sha(projection_bytes)
           and approved["install_receipt_sha256"] == _sha(canonical(install_receipt))
           and approved["root_owner_ledger_sha256"]
                 == _sha(canonical(revoked_ledger))
           and approved["revoked_revision"] == revoked_ledger["revision"]
           and approved["revoked_operation_id"] == revoked_ledger["operation_id"]
           and all(approved[x] == projection[x] for x in
                   ("host_id", "installation_id", "state_volume_id",
                    "certificate_id")),
           "revocation-operator-approval-mismatch")
    tombstone = {
        "schema": REVOCATION_SCHEMA,
        "projection_sha256": _sha(projection_bytes),
        "root_owner_ledger_sha256": _sha(canonical(revoked_ledger)),
        "revoked_revision": revoked_ledger["revision"],
        "revoked_operation_id": revoked_ledger["operation_id"],
        "operator_approval_sha256": _sha(approval_bytes),
    }
    return {"path": REVOCATION_PATH, "mode": 0o444, "uid": 0, "gid": 0,
            "no_replacement": True, "irreversible": True,
            "tombstone_bytes": canonical(tombstone),
            "native_installation_authorized": False}
