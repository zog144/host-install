"""Source-only archive receiver interface model; intentionally not a runtime receiver.

No network, keys, credentials or filesystem are used here. These checks model
required *after-cryptographic-verification* ordering and fail-closed receipt
behavior; a boolean in this test model is NOT trusted production evidence.
"""
import copy
import json
from pathlib import Path

CONTRACT = json.loads((Path(__file__).resolve().parents[1] /
    "docs/host-install/archive-provider-receiver-contract-v1.json").read_text())


def destination():
    return {
        "host_id": "host-A", "host_fingerprint": "fingerprint-A",
        "installation_id": "install-A", "state_volume_id": "state-A",
        "registry_id": "registry-A", "provider_id": "upstream-A",
        "provider_origin": "https://upstream.example.invalid",
        "provider_role": "archive-mirror-provider",
        "role_revision": 4, "collections": ["sources"],
        "operations": ["fetch"], "provider_credential_id": "cred-A",
        "credential_revision": 7,
    }


def operation():
    return {
        "scope": destination(), "consumer": "archive-mirror",
        "purpose": "archive-mirror-upstream-fetch",
        "authorization_id": "auth-7", "authorization_revision": 3,
        "authorization_current": True, "authorization_expires": 1000,
        "request_id": "request-7", "delivery_id": "delivery-7",
        "nonce": "nonce-7", "bytes_digest": "opaque-test-digest-7",
        "action": "deliver", "previous_delivery_id": None,
        "signatures_verified_by_owner": True, "https_authenticated_by_owner": True,
        "source_approved_by_owner": True,
    }


class Hold(ValueError):
    pass


def transition(ledger, candidate, *, expected, now=100, fail_at=None):
    """Abstract ordered transition, never an implementation/admission API."""
    record = copy.deepcopy(ledger)
    if record["revoked"]:
        raise Hold("revoked")
    if not record["enabled"]:
        raise Hold("receiver not selected")
    if (candidate["consumer"] != CONTRACT["consumer"] or
            candidate["purpose"] != CONTRACT["purpose"] or
            candidate["scope"] != expected or
            candidate["scope"]["provider_role"] != CONTRACT["provider_role"] or
            candidate["scope"]["operations"] != CONTRACT["operations"]):
        raise Hold("destination/purpose mismatch")
    if not all(candidate[k] is True for k in (
            "authorization_current", "signatures_verified_by_owner",
            "https_authenticated_by_owner", "source_approved_by_owner")):
        raise Hold("unverified")
    if candidate["authorization_expires"] <= now:
        raise Hold("expired")
    if candidate["scope"]["credential_revision"] < record["credential_revision"]:
        raise Hold("rollback")
    claim = {k: candidate[k] for k in ("authorization_id",
        "authorization_revision","request_id","delivery_id","nonce",
        "bytes_digest","action","previous_delivery_id")}
    previous = record["claims"].get(candidate["request_id"])
    if previous is not None:
        if previous != claim or record["receipt"] is None:
            raise Hold("conflicting or pending replay")
        if record["receipt"]["delivery_id"] != candidate["delivery_id"]:
            raise Hold("receipt conflict")
        return record, "identical-retry-requires-native-byte-and-approval-recheck"
    if candidate["nonce"] in record["nonces"]:
        raise Hold("nonce replay")
    if record["receipt"] is not None:
        if (candidate["action"] != "renew" or
                candidate["previous_delivery_id"] !=
                record["receipt"]["delivery_id"] or
                candidate["scope"]["credential_revision"] <=
                record["credential_revision"]):
            raise Hold("rotation chain mismatch")
    elif candidate["action"] != "deliver":
        raise Hold("initial delivery action mismatch")
    # Persist verified request and delivery claims before any local installation.
    record["claims"][candidate["request_id"]] = claim
    record["nonces"].add(candidate["nonce"])
    if fail_at == "claim":
        return record, "interrupted-before-install"
    record["installed_delivery"] = candidate["delivery_id"]
    if fail_at == "install":
        return record, "interrupted-before-receipt"
    record["credential_revision"] = candidate["scope"]["credential_revision"]
    record["receipt"] = {"delivery_id": candidate["delivery_id"],
        "authorization_id": candidate["authorization_id"],
        "request_id": candidate["request_id"], "status": "installed"}
    return record, "acknowledged-after-durable-receipt"


def revoke(ledger, *, verified, destination_matches, fail_at=None):
    if not verified or not destination_matches:
        raise Hold("invalid revocation")
    record = copy.deepcopy(ledger)
    # Durable common tombstone precedes application-local revocation.
    record["revoked"] = True
    if fail_at == "tombstone":
        return record, "interrupted-application-revocation-pending"
    record["application_revoked"] = True
    record["revocation_receipt"] = {"status": "revoked"}
    return record, "acknowledged-after-revocation-receipt"


def fresh():
    return {"enabled": False, "revoked": False, "application_revoked": False,
            "claims": {}, "nonces": set(), "credential_revision": 0,
            "receipt": None, "revocation_receipt": None, "installed_delivery": None,
            "archive_catalogue": "retained", "archive_objects": "retained",
            "archive_pins": "retained"}


def test_contract_is_purpose_scoped_disabled_and_not_native():
    assert CONTRACT["enabled_by_default"] is False
    assert CONTRACT["production_activation_authorized"] is False
    assert CONTRACT["native_https_accepted"] is False
    assert CONTRACT["native_acceptance"] is None
    assert "cloudflare-dns-01" in CONTRACT["excluded_operations"]
    assert CONTRACT["purpose"] == "archive-mirror-upstream-fetch"
    assert CONTRACT["delivery_order"].index("persist_delivery_claim") < (
        CONTRACT["delivery_order"].index("install_verified"))
    assert CONTRACT["delivery_order"].index("persist_verified_secret_free_receipt") < (
        CONTRACT["delivery_order"].index("acknowledge"))
    assert CONTRACT["revocation_order"].index("persist_common_revocation_tombstone") < (
        CONTRACT["revocation_order"].index("apply_signed_revocation"))


def test_disabled_by_default_and_selection_does_not_approve_native_receiver():
    import pytest
    with pytest.raises(Hold, match="not selected"):
        transition(fresh(), operation(), expected=destination())


def test_destination_purpose_revision_and_authorization_fail_closed():
    import pytest
    for field, bad in (
        ("host_id", "another-host"), ("host_fingerprint", "other-fp"),
        ("installation_id", "other-install"), ("state_volume_id", "other-state"),
        ("registry_id", "other-registry"), ("provider_id", "other-upstream"),
        ("provider_origin", "https://other.example.invalid"),
        ("role_revision", 3), ("collections", ["other"]),
        ("credential_revision", 8), ("provider_role", "issuer"),
        ("operations", ["write"]),
    ):
        changed = operation()
        changed["scope"][field] = bad
        state = fresh(); state["enabled"] = True
        with pytest.raises(Hold, match="destination/purpose mismatch"):
            transition(state, changed, expected=destination())
    for field, bad in (
        ("consumer", "certify-manage"), ("purpose", "cloudflare-dns-01"),
        ("authorization_current", False), ("signatures_verified_by_owner", False),
        ("https_authenticated_by_owner", False),
        ("source_approved_by_owner", False),
        ("authorization_expires", 100),
    ):
        changed = operation(); changed[field] = bad
        state = fresh(); state["enabled"] = True
        with pytest.raises(Hold):
            transition(state, changed, expected=destination())


def test_claim_crash_lost_ack_replay_and_conflicts():
    import pytest
    state = fresh(); state["enabled"] = True
    claimed, status = transition(state, operation(), expected=destination(),
                                  fail_at="claim")
    assert status == "interrupted-before-install"
    assert claimed["installed_delivery"] is None
    with pytest.raises(Hold, match="pending replay"):
        transition(claimed, operation(), expected=destination())
    installed, status = transition(state, operation(), expected=destination(),
                                    fail_at="install")
    assert installed["receipt"] is None
    with pytest.raises(Hold, match="pending replay"):
        transition(installed, operation(), expected=destination())
    accepted, status = transition(state, operation(), expected=destination())
    assert status == "acknowledged-after-durable-receipt"
    accepted2, status = transition(accepted, operation(), expected=destination())
    assert status.startswith("identical-retry")
    assert accepted2 == accepted
    changed = operation(); changed["bytes_digest"] = "altered"
    with pytest.raises(Hold, match="conflicting"):
        transition(accepted, changed, expected=destination())
    changed = operation(); changed["request_id"] = "other-request"
    with pytest.raises(Hold, match="nonce replay"):
        transition(accepted, changed, expected=destination())


def test_rotation_monotonic_and_signed_revocation_precedes_archive_store():
    import pytest
    state = fresh(); state["enabled"] = True
    state, _ = transition(state, operation(), expected=destination())
    rotated = operation()
    rotated.update(request_id="request-8", nonce="nonce-8",
                   delivery_id="delivery-8", bytes_digest="opaque-test-digest-8",
                   action="renew", previous_delivery_id="delivery-7")
    rotated["scope"]["credential_revision"] = 8
    expected = destination(); expected["credential_revision"] = 8
    state, result = transition(state, rotated, expected=expected)
    assert result == "acknowledged-after-durable-receipt"
    assert state["credential_revision"] == 8
    wrong = copy.deepcopy(rotated)
    wrong["request_id"] = "request-9"; wrong["nonce"] = "nonce-9"
    wrong["previous_delivery_id"] = "delivery-unknown"
    with pytest.raises(Hold, match="rotation chain"):
        transition(state, wrong, expected=expected)
    interrupted, status = revoke(state, verified=True,
                                  destination_matches=True,
                                  fail_at="tombstone")
    assert interrupted["revoked"] and not interrupted["application_revoked"]
    with pytest.raises(Hold, match="revoked"):
        transition(interrupted, rotated, expected=expected)
    revoked, status = revoke(interrupted, verified=True,
                             destination_matches=True)
    assert status == "acknowledged-after-revocation-receipt"
    assert revoked["application_revoked"]
    for field in ("archive_catalogue", "archive_objects", "archive_pins"):
        assert revoked[field] == "retained"
    with pytest.raises(Hold, match="invalid revocation"):
        revoke(state, verified=False, destination_matches=True)
