"""Pure host-install review of nonsecret Django commit; no password or Host key."""
import copy
import time
import uuid
import pytest

from zog.host_identify import credential_delivery as cd
from zog.host_install import station_admin_password_receipt as checked

NOW = int(time.time())


def fixture():
    binding = {
        "host_id": str(uuid.uuid4()),
        "host_fingerprint": "a"*64,
        "installation_id": str(uuid.uuid4()),
        "state_volume_id": str(uuid.uuid4()),
        "registry_id": "station-registry",
        "consumer": checked.CONSUMER,
        "purpose": checked.PURPOSE,
        "credential_id": "station-admin-73",
    }
    auth = {
        "schema": cd.AUTHORIZATION_SCHEMA, "issuer": "https://station.example.test",
        **binding, "credential_revision": 2, "authorization_id": str(uuid.uuid4()),
        "revision": 3, "status": "approved",
        "approved_at": NOW - 20, "revoked_at": None, "expires_at": NOW + 600,
    }
    request = {
        "schema": cd.REQUEST_SCHEMA, **binding,
        "credential_revision": 2, "authorization_id": auth["authorization_id"],
        "authorization_revision": 3, "request_id": str(uuid.uuid4()),
        "action": "deliver", "previous_delivery_id": None,
        "created_at": NOW - 1, "expires_at": NOW + 119,
    }
    delivery = {
        "schema": cd.DELIVERY_SCHEMA,
        "request_id": request["request_id"], "delivery_id": str(uuid.uuid4()),
        "authorization_id": auth["authorization_id"],
        "authorization_revision": 3, "credential_id": binding["credential_id"],
        "credential_revision": 2, "consumer": checked.CONSUMER,
        "purpose": checked.PURPOSE, "issued_at": NOW,
        "expires_at": NOW + 120, "secret_format": "base64",
        "secret": "c3ludGhldGlj",  # Never inspected or emitted by this module.
    }
    commit = {
        "schema": checked.COMMIT_SCHEMA,
        "state": "committed-awaiting-host-signed-receipt",
        "request_id": request["request_id"],
        "delivery_id": delivery["delivery_id"],
        "authorization_id": auth["authorization_id"],
        "credential_revision": 2, "account_id": 73,
        "installed_at": NOW + 1,
    }
    return dict(commit=commit, authorization=auth, request=request,
                delivery=delivery, expected_binding=binding,
                expected_account_id=73, now=NOW)


def test_exact_receipt_contract_is_not_native_authority():
    result = checked.inspect(**fixture())
    assert result["source_contract_matched"]
    assert result["account_id"] == 73
    assert result["host_signed_receipt_authorized"] is False
    assert result["anonymous_fd_peer_proven"] is False
    assert "secret" not in str(result) and "c3ludGhldGlj" not in str(result)


@pytest.mark.parametrize("field,value", [
    ("state", "pending"),
    ("request_id", "00000000-0000-4000-8000-000000000000"),
    ("delivery_id", "00000000-0000-4000-8000-000000000000"),
    ("authorization_id", "00000000-0000-4000-8000-000000000000"),
    ("credential_revision", 1),
    ("account_id", 74),
    ("installed_at", NOW - 1),
])
def test_stale_or_substituted_local_commit_refuses_receipt(field, value):
    example = fixture()
    example["commit"][field] = value
    with pytest.raises(checked.AdministratorReceiptContractError):
        checked.inspect(**example)


@pytest.mark.parametrize("field,value", [
    ("host_id", "00000000-0000-4000-8000-000000000000"),
    ("installation_id", "00000000-0000-4000-8000-000000000000"),
    ("state_volume_id", "00000000-0000-4000-8000-000000000000"),
    ("consumer", "certify-manage"),
    ("purpose", "issuer-cloudflare-dns01"),
    ("credential_id", "other-user"),
])
def test_wrong_destination_or_purpose_refuses_receipt(field,value):
    example = fixture()
    example["expected_binding"][field] = value
    with pytest.raises(checked.AdministratorReceiptContractError):
        checked.inspect(**example)


def test_changed_delivery_and_request_or_revoked_authority_refused():
    for section, field, value in [
        ("delivery", "request_id", str(uuid.uuid4())),
        ("delivery", "delivery_id", str(uuid.uuid4())),
        ("request", "action", "renew"),
        ("authorization", "status", "revoked"),
    ]:
        example = fixture()
        example[section][field] = value
        with pytest.raises(checked.AdministratorReceiptContractError):
            checked.inspect(**example)
