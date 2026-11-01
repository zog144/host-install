"""Source-only broker install/revocation contract; does not touch protected paths."""
import hashlib
import json
import uuid

import pytest

from zog.host_install import certificate_selected_broker_install as broker
from zog.host_install.state_contract import StateError, canonical


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def uid(n):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"selected-broker-{n}"))


def fixture():
    binding = {
        "schema": broker.PRIVATE_BINDING_SCHEMA,
        "host_id": uid(1),
        "installation_id": uid(2),
        "state_volume_id": uid(3),
        "registry_id": "primary",
        "authority_key_id": "1" * 64,
        "consumer": "host-nginx-https",
        "service_id": "nginx",
        "certificate_id": "station-web",
        "hostnames": ["example.org"],
        "policy_sha256": "2" * 64,
        "challenge": "dns-01",
        "dns_mode": "local-cloudflare",
        "dns_zone": "example.org",
        "credential_id": "zone1",
        "credential_revision": 4,
        "contact_email": "ops@example.org",
        "acme_directory": "https://acme.example.org/directory",
    }
    owner = {
        "schema": broker.OWNER_SCHEMA, "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": uid(1), "installation_id": uid(2),
        "certificate_id": "station-web", "service_id": "nginx",
        "hostnames": ["example.org"], "policy_sha256": "2" * 64,
        "challenge": "dns-01", "dns_mode": "local-cloudflare",
        "dns_zone": "example.org", "credential_id": "zone1",
        "credential_revision": 4,
        "operation_id": uid(4), "revision": 6,
        "approved_at": 50, "expires_at": 10000,
        "revoked_at": None, "status": "approved",
    }
    raw = canonical(binding)
    issuer = {"storage_id": "a" * 32, "grant_id": "b" * 32,
              "uid": 24001, "gid": 24002, "software_view": "sha256:" + "c" * 64,
              "certificate_data_path": "/var/lib/zog-certify-manage",
              "controller_record_sha256": "d" * 64}
    ledger = {
        "schema": broker.OWNER_LEDGER_SCHEMA,
        "installation_id": uid(2), "state_volume_id": uid(3),
        "registry_id": "primary", "authority_key_id": "1" * 64,
        "service_id": "nginx", "certificate_id": "station-web",
        "binding_sha256": hashlib.sha256(raw).hexdigest(),
        "delivery_policy_sha256": "2" * 64, "issuer": issuer,
        "local_intent_sha256": "3" * 64,
        "revision": 6, "operation_id": uid(4),
        "assignment_sha256": "4" * 64,
        "owner_authority_sha256": digest(owner),
        "status": "approved", "operations": [{
            "revision": 6, "operation_id": uid(4),
            "assignment_sha256": "4" * 64,
            "owner_authority_sha256": digest(owner), "status": "approved",
        }],
    }
    candidate = {
        "schema": broker.PROJECTION_SCHEMA,
        "host_id": uid(1), "installation_id": uid(2),
        "state_volume_id": uid(3), "certificate_id": "station-web",
        "hostnames": ["example.org"], "policy_sha256": "2" * 64,
        "host_policy_digest": "sha256:" + "5" * 64,
        "issuer_lifecycle_socket": "/run/zog/certify-lifecycle.sock",
        "controller_uid": 23001, "caller_uid": 23002,
        "issuer_uid": 24001, "issuer_gid": 24002,
        "storage_id": "a" * 32, "grant_id": "b" * 32,
        "box_control_revision": broker.BOX_CONTROL_REVIEWED_COMMIT,
        "consumer_binding_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }
    approval = {
        **candidate, "schema": broker.APPROVAL_SCHEMA,
        "owner_revision": 6, "owner_operation_id": uid(4),
        "owner_authority_sha256": digest(owner),
        "root_owner_ledger_sha256": digest(ledger),
        "host_deploy_source_commit": broker.HOST_DEPLOY_REVIEWED_COMMIT,
    }
    args = {
        "approval_bytes": canonical(approval),
        "expected_approval_sha256": digest(approval),
        "private_binding_bytes": raw,
        "owner": owner, "root_owner_ledger": ledger,
        "host_policy_digest": candidate["host_policy_digest"], "now": 100,
    }
    return args


def test_current_root_approved_exact_projection_and_no_replace():
    args = fixture()
    plan = broker.projection_plan(**args)
    assert plan["path"] == broker.PROJECTION_PATH
    assert (plan["uid"], plan["gid"], plan["mode"]) == (0, 0, 0o444)
    assert plan["projection"]["controller_uid"] == 23001
    assert set(plan["projection"]) == broker.PROJECTION_FIELDS
    assert plan["projection_bytes"] == canonical(plan["projection"])
    assert plan["native_installation_authorized"] is False
    assert broker.no_replacement_check(None, plan["projection_bytes"]) == "new-only"
    assert broker.no_replacement_check(plan["projection_bytes"],
                                       plan["projection_bytes"]) == "same-byte-idempotent"
    with pytest.raises(StateError, match="installed-projection-conflict"):
        broker.no_replacement_check(b"forged", plan["projection_bytes"])
    with pytest.raises(StateError, match="revocation-tombstone-present"):
        broker.no_replacement_check(None, plan["projection_bytes"],
                                    revocation_present=True)


@pytest.mark.parametrize("field,foreign", [
    ("host_id", uid(90)), ("installation_id", uid(91)),
    ("state_volume_id", uid(92)), ("certificate_id", "other-cert"),
    ("hostnames", ["other.example.org"]), ("policy_sha256", "9"*64),
    ("controller_uid", 24001), ("caller_uid", 23001),
    ("issuer_uid", 23001), ("issuer_gid", 3),
    ("grant_id", "e"*32), ("storage_id", "f"*32),
    ("consumer_binding_sha256", "sha256:"+"f"*64),
    ("box_control_revision", "f"*40),
    ("host_deploy_source_commit", "f"*40),
    ("root_owner_ledger_sha256", "f"*64),
])
def test_independently_approved_invalid_identity_is_rejected(field, foreign):
    args = fixture()
    row = json.loads(args["approval_bytes"])
    row[field] = foreign
    args["approval_bytes"] = canonical(row)
    args["expected_approval_sha256"] = digest(row)
    with pytest.raises(StateError):
        broker.projection_plan(**args)


def test_self_asserted_root_approval_digest_and_root_ledger_drift_fail():
    args = fixture()
    args["expected_approval_sha256"] = "0"*64
    with pytest.raises(StateError, match="independent-approval-mismatch"):
        broker.projection_plan(**args)

    args = fixture()
    args["root_owner_ledger"]["revision"] += 1
    with pytest.raises(StateError):
        broker.projection_plan(**args)

    args = fixture()
    args["private_binding_bytes"] += b" "
    with pytest.raises(StateError):
        broker.projection_plan(**args)

    args = fixture()
    args["owner"]["expires_at"] = 100
    with pytest.raises(StateError):
        broker.projection_plan(**args)


def installed_and_revoked():
    args = fixture()
    install = broker.projection_plan(**args)
    installed = {
        **install["receipt"], "status": "installed",
        "native_installation_verified": True,
    }
    revoked_owner = {
        **args["owner"], "revision": 7,
        "operation_id": uid(7), "status": "revoked",
        "revoked_at": 110, "expires_at": 110,
    }
    revoked_ledger = {
        **args["root_owner_ledger"], "revision": 7,
        "operation_id": uid(7), "status": "revoked",
        "owner_authority_sha256": digest(revoked_owner),
    }
    approval = {
        "schema": broker.REVOCATION_APPROVAL_SCHEMA,
        "projection_sha256": hashlib.sha256(install["projection_bytes"]).hexdigest(),
        "install_receipt_sha256": digest(installed),
        "root_owner_ledger_sha256": digest(revoked_ledger),
        "revoked_revision": 7, "revoked_operation_id": uid(7),
        "host_id": install["projection"]["host_id"],
        "installation_id": install["projection"]["installation_id"],
        "state_volume_id": install["projection"]["state_volume_id"],
        "certificate_id": install["projection"]["certificate_id"],
    }
    return {
        "projection_bytes": install["projection_bytes"],
        "install_receipt": installed,
        "revoked_owner": revoked_owner,
        "revoked_ledger": revoked_ledger,
        "approval_bytes": canonical(approval),
        "expected_approval_sha256": digest(approval),
    }


def test_signed_owner_revocation_yields_irreversible_no_replace_tombstone():
    args = installed_and_revoked()
    result = broker.revocation_plan(**args)
    assert result["path"] == broker.REVOCATION_PATH
    assert result["irreversible"] is True
    assert (result["uid"], result["gid"], result["mode"]) == (0, 0, 0o444)
    assert json.loads(result["tombstone_bytes"])["revoked_revision"] == 7
    assert broker.no_replacement_check(result["tombstone_bytes"],
                                       result["tombstone_bytes"]) == "same-byte-idempotent"


@pytest.mark.parametrize("attack", [
    "no-native-proof", "rollback", "wrong-signed-owner", "foreign-installation",
    "wrong-revocation-approval", "wrong-projection", "same-revision",
])
def test_revocation_fails_closed_on_stale_or_forged_evidence(attack):
    args = installed_and_revoked()
    if attack == "no-native-proof":
        args["install_receipt"]["native_installation_verified"] = False
    if attack == "rollback":
        args["revoked_ledger"]["revision"] = 5
    if attack == "same-revision":
        args["revoked_ledger"]["revision"] = 6
        args["revoked_owner"]["revision"] = 6
    if attack == "wrong-signed-owner":
        args["revoked_owner"]["host_id"] = uid(99)
    if attack == "foreign-installation":
        args["revoked_ledger"]["installation_id"] = uid(99)
    if attack == "wrong-revocation-approval":
        args["expected_approval_sha256"] = "f"*64
    if attack == "wrong-projection":
        args["projection_bytes"] += b" "
    with pytest.raises(StateError):
        broker.revocation_plan(**args)


def test_no_proposal_only_revocation():
    args = installed_and_revoked()
    args["install_receipt"]["status"] = "source-plan-only"
    with pytest.raises(StateError, match="original-install-receipt-mismatch"):
        broker.revocation_plan(**args)
