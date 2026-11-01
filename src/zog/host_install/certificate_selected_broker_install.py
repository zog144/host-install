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
COMMIT_SCHEMA = "zog-host-install-selected-broker-install-commit-v1"
REVOCATION_APPROVAL_SCHEMA = "zog-host-install-selected-broker-revocation-approval-v1"
PROJECTION_PATH = "/etc/zog/host-deploy/certificate-issuer-broker-authority.json"
REVOCATION_PATH = "/etc/zog/host-deploy/certificate-issuer-broker-revoked.json"
HOST_DEPLOY_REVIEWED_COMMIT = "e1e0ec43b3aa3b56d4627ff8ed8d24eb2495871a"
HOST_DEPLOY_PROJECTION_BLOB = "c16c55f37495177974349100451d624f39cb9718"
BOX_CONTROL_REVIEWED_COMMIT = "baca7f815974dbf685950c0c7e78f693dd0a96e2"
ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT = "32ec525903834d3a707e5aace408cf4dbee32d83"
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
           and install_receipt.get("native_installation_verified") is True
           and install_receipt.get("status") == "installed",
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



# Native-only publication primitives. These expose no CLI, HTTP route,
# unattended systemd service or automatic source-authentication shortcut.
# The root owner must supply original evidence from a separately trusted
# and installed native reader; dicts supplied by a request are not authority.
import os
import stat
from contextlib import contextmanager

from .state_io import lock, publish, raw, ensure_directory


LOCK_NAME = ".certificate-selected-broker-install.lock"
PROJECTION_NAME = PROJECTION_PATH.rsplit("/", 1)[1]
REVOCATION_NAME = REVOCATION_PATH.rsplit("/", 1)[1]
INSTALL_RECEIPT_NAME = "certificate-issuer-broker-install-receipt.json"
COMMIT_NAME = "certificate-issuer-broker-install-commit.json"


@contextmanager
def _fixed_root_parent():
    """Open the existing exact root ancestry without following symlinks."""
    _valid(os.geteuid() == 0, "root-owner-required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in ("etc", "zog", "host-deploy"):
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            _valid(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                   and info.st_gid == 0
                   and not stat.S_IMODE(info.st_mode) & 0o022,
                   "unprotected-broker-authority-ancestry")
        _valid(stat.S_IMODE(os.fstat(fd).st_mode) == 0o755,
               "timer-readable-broker-parent-required")
        yield fd
    finally:
        os.close(fd)


def _revocation_clear(fd):
    # Includes a staged-but-not-linked marker. Neither is safe to ignore.
    for name in (REVOCATION_NAME, ".pending." + REVOCATION_NAME):
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise StateError("selected-broker-authority",
                             "revocation-check-unavailable") from exc
        raise StateError("selected-broker-authority",
                         "revocation-tombstone-present")





def _installation_commit(proposal, receipt):
    """A public proof of a privately committed root 0600 installation receipt.

    Only the protected owner may create it after separately checking the
    final projection and private receipt bytes under the stable writer lock.
    """
    _valid(type(proposal) is dict and type(receipt) is dict,
           "incomplete-broker-installation")
    projection = _projection_checked(proposal["projection"])
    _valid(receipt.get("schema") == RECEIPT_SCHEMA
           and receipt.get("status") == "installed"
           and receipt.get("native_installation_verified") is True
           and receipt.get("projection_sha256") == _sha(proposal["projection_bytes"])
           and receipt.get("host_id") == projection["host_id"]
           and receipt.get("installation_id") == projection["installation_id"]
           and receipt.get("state_volume_id") == projection["state_volume_id"]
           and receipt.get("certificate_id") == projection["certificate_id"]
           and type(receipt.get("owner_revision")) is int
           and 1 <= receipt["owner_revision"] < 2**53
           and type(receipt.get("owner_operation_id")) is str
           and _UUID.fullmatch(receipt["owner_operation_id"]),
           "installed-receipt-not-committed")
    return {
        "schema": COMMIT_SCHEMA,
        "projection_sha256": _sha(proposal["projection_bytes"]),
        "install_receipt_sha256": _sha(canonical(receipt)),
        "host_id": projection["host_id"],
        "installation_id": projection["installation_id"],
        "state_volume_id": projection["state_volume_id"],
        "certificate_id": projection["certificate_id"],
        "policy_sha256": projection["policy_sha256"],
        "consumer_binding_sha256": projection["consumer_binding_sha256"],
        "box_control_revision": projection["box_control_revision"],
        "owner_revision": receipt["owner_revision"],
        "owner_operation_id": receipt["owner_operation_id"],
        "host_deploy_source_commit": HOST_DEPLOY_REVIEWED_COMMIT,
    }

def publish_verified_projection(*, trusted_original_root_reader,
                                trusted_source_attestor,
                                expected_approval_sha256):
    """Native root owner only; return protected nonsecret installed receipt.

    Both callbacks are provided by the protected installer, NOT from input
    JSON/CLI. The source attestor must check actual installed host-deploy,
    box-control and host-install wheel RECORD, plus the root-ledger/STATE
    source identity. No automatic activation follows successful publication.
    """
    _valid(os.geteuid() == 0
           and callable(trusted_original_root_reader)
           and callable(trusted_source_attestor),
           "missing-protected-native-authority")
    evidence = trusted_original_root_reader()
    _valid(type(evidence) is dict and set(evidence) == {
        "approval_bytes", "private_binding_bytes", "owner",
        "root_owner_ledger", "host_policy_digest", "now",
    }, "untrusted-root-evidence-contract")
    proposal = projection_plan(
        **evidence, expected_approval_sha256=expected_approval_sha256
    )
    _valid(trusted_source_attestor(proposal) is True,
           "installed-source-attestation-missing")
    installed_receipt = {
        **proposal["receipt"],
        "status": "installed",
        "native_installation_verified": True,
    }
    with _fixed_root_parent() as fd:
        with lock(fd, LOCK_NAME):
            # Original root-owned approval/ledger must still be the same at
            # the publication boundary. The native reader owns locking and
            # independent file provenance, not a caller-supplied JSON cache.
            _valid(trusted_original_root_reader() == evidence
                   and trusted_source_attestor(proposal) is True,
                   "root-authority-changed-before-publication")
            _revocation_clear(fd)
            # All intermediate states are non-authorizing for the timer.
            # The public 0444 COMMIT is the final durable write, only after
            # the 0600 receipt has been published and independently read back.
            # A crash after projection or receipt leaves NO public commit.
            publish(fd, PROJECTION_NAME, proposal["projection_bytes"],
                    mode=0o444, uid=0, gid=0)
            publish(fd, INSTALL_RECEIPT_NAME, canonical(installed_receipt),
                    mode=0o600, uid=0, gid=0)
            _revocation_clear(fd)
            _valid(
                raw(fd, PROJECTION_NAME, uid=0, gid=0, mode=0o444)
                    == proposal["projection_bytes"]
                and raw(fd, INSTALL_RECEIPT_NAME, uid=0, gid=0, mode=0o600)
                    == canonical(installed_receipt),
                "protected-projection-readback-mismatch",
            )
            # Reopen genuine owner evidence before making a commit visible:
            # a stale operator digest or revoked owner cannot complete it.
            _valid(trusted_original_root_reader() == evidence
                   and trusted_source_attestor(proposal) is True,
                   "root-authority-changed-before-commit")
            commit = canonical(_installation_commit(proposal, installed_receipt))
            publish(fd, COMMIT_NAME, commit, mode=0o444, uid=0, gid=0)
            _revocation_clear(fd)
            _valid(raw(fd, COMMIT_NAME, uid=0, gid=0, mode=0o444) == commit,
                   "protected-broker-commit-readback-mismatch")
        # The installer writer lock must be RELEASED before acquiring the
        # execution epoch lock. Revocation holds execution then installer;
        # acquiring them in reverse order here would deadlock on reinstall.
        # No certificate operation can launch before the root-owned fence
        # has its durable commit-bound initial ledger.
        from zog.root_control.issuer_execution_fence import (
            IssuerExecutionFence, FIXED_DIRECTORY, REVIEWED_BOX_CONTROL,
            current_boot_id,
        )
        _valid(REVIEWED_BOX_CONTROL == BOX_CONTROL_REVIEWED_COMMIT,
               "issuer-execution-source-pin-mismatch")
        execution_fd = ensure_directory(fd, FIXED_DIRECTORY, 0, 0, 0o700)
        try:
            epoch = IssuerExecutionFence(execution_fd).initialize(
                trusted_commit_sha256=_sha(commit),
                boot_id=current_boot_id())
            _valid(epoch["revoked"] is False,
                   "revoked-execution-epoch-cannot-be-reinstalled")
        finally:
            os.close(execution_fd)
        _revocation_clear(fd)
    return installed_receipt


def publish_verified_revocation(*, trusted_original_revocation_reader,
                                trusted_source_attestor,
                                expected_approval_sha256):
    """Root-only irrevocable publisher serialized with selected PID1 start."""
    from zog.root_control.issuer_execution_fence import installed_fence
    with installed_fence() as (fence, _digest):
        published = []
        def publish_original():
            published.append(_publish_verified_revocation_locked(
                trusted_original_revocation_reader=trusted_original_revocation_reader,
                trusted_source_attestor=trusted_source_attestor,
                expected_approval_sha256=expected_approval_sha256,
            ))
            return True
        fence.revoke(publish_pending_revocation=publish_original)
        _valid(len(published) == 1, "issuer-revocation-publication-unconfirmed")
        return published[0]


def _publish_verified_revocation_locked(*, trusted_original_revocation_reader,
                                       trusted_source_attestor,
                                       expected_approval_sha256):
    """Publish permanent denial marker under the same root authority lock.

    The protected native reader must independently reopen the current
    revoked owner checkpoint and original installed projection/receipt.
    A complete OR pending marker is irrevocable for this original path.
    """
    _valid(os.geteuid() == 0
           and callable(trusted_original_revocation_reader)
           and callable(trusted_source_attestor),
           "missing-protected-native-authority")
    inputs = trusted_original_revocation_reader()
    _valid(type(inputs) is dict and set(inputs) == {
        "revoked_owner", "revoked_ledger", "approval_bytes",
    }, "untrusted-revocation-evidence-contract")
    with _fixed_root_parent() as fd:
        with lock(fd, LOCK_NAME):
            _valid(trusted_original_revocation_reader() == inputs,
                   "revocation-authority-changed-before-publication")
            original_projection = raw(
                fd, PROJECTION_NAME, uid=0, gid=0, mode=0o444
            )
            original_receipt = raw(
                fd, INSTALL_RECEIPT_NAME, uid=0, gid=0, mode=0o600
            )
            _valid(original_projection is not None
                   and original_receipt is not None,
                   "no-attested-installed-projection")
            receipt = _canonical_bytes(original_receipt)
            # A half-installed projection is not a revocable installed
            # authority. The consumer already denies it; protected recovery
            # must separately reconcile it rather than invent a commit.
            proposal = {"projection": _canonical_bytes(original_projection),
                        "projection_bytes": original_projection}
            expected_commit = canonical(_installation_commit(proposal, receipt))
            _valid(raw(fd, COMMIT_NAME, uid=0, gid=0, mode=0o444)
                       == expected_commit
                   and raw(fd, ".pending." + COMMIT_NAME,
                           uid=0, gid=0, mode=0o444) is None,
                   "uncommitted-broker-installation")
            plan = revocation_plan(
                projection_bytes=original_projection,
                install_receipt=receipt,
                expected_approval_sha256=expected_approval_sha256,
                **inputs,
            )
            _valid(trusted_source_attestor(plan) is True,
                   "installed-source-attestation-missing")
            publish(fd, REVOCATION_NAME, plan["tombstone_bytes"],
                    mode=0o444, uid=0, gid=0)
            _valid(raw(fd, REVOCATION_NAME, uid=0, gid=0, mode=0o444)
                   == plan["tombstone_bytes"],
                   "protected-revocation-readback-mismatch")
    return {
        "schema": REVOCATION_SCHEMA,
        "status": "root-owned-revocation-tombstone-retained",
        "projection_sha256": _sha(original_projection),
        "tombstone_sha256": _sha(plan["tombstone_bytes"]),
        "production_activation_authorized": False,
    }
