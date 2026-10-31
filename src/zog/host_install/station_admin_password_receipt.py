"""Source-only host-install ↔ Django protected admin credential receipt contract.

This adapter NEVER handles password bytes, signs a Host receipt, installs
software, or asserts native authority. It only compares a protected local
commit record to the exact canonical HTTPS request/delivery and operator
approved account selection. Real signed receipt production requires root
control's independently reviewed signer and installed-byte/FD evidence.
"""
from __future__ import annotations

import uuid

from zog.host_identify import credential_delivery as cd

CONSUMER = "station-access"
PURPOSE = "station-access-administrator-password"
COMMIT_SCHEMA = "zog-station-admin-password-protected-commit-v1"
COMMIT_FIELDS = frozenset({
    "schema", "state", "request_id", "delivery_id", "authorization_id",
    "credential_revision", "account_id", "installed_at",
})


class AdministratorReceiptContractError(ValueError):
    pass


def _deny():
    raise AdministratorReceiptContractError("protected-admin-commit-unverified") from None


def inspect(*, commit, authorization, request, delivery,
            expected_binding, expected_account_id, now):
    """Reject mismatched canonical binding or uncommitted/replayed local claims.

    Returned metadata is a *source-contract observation*, not a validated
    native producer signature, root-controlled FD transfer or permission to
    send a Host-signed receipt.
    """
    if (type(now) is not int or type(commit) is not dict
            or set(commit) != COMMIT_FIELDS
            or commit["schema"] != COMMIT_SCHEMA
            or commit["state"] != "committed-awaiting-host-signed-receipt"
            or type(expected_account_id) is not int
            or expected_account_id <= 0
            or type(commit["account_id"]) is not int
            or commit["account_id"] != expected_account_id):
        _deny()
    try:
        expected = cd.binding(expected_binding)
        if (expected["consumer"] != CONSUMER
                or expected["purpose"] != PURPOSE
                or cd.binding(authorization) != expected
                or cd.binding(request) != expected):
            _deny()
        cd.validate_authorization(
            authorization, expected_issuer=authorization["issuer"],
            expected_binding=expected, now=now)
        cd.validate_request(request, authorization, now=now)
        cd.validate_delivery(delivery, request, authorization, now=now)
        if (request["action"] != "deliver"
                or commit["request_id"] != request["request_id"]
                or commit["delivery_id"] != delivery["delivery_id"]
                or commit["authorization_id"] != authorization["authorization_id"]
                or type(commit["credential_revision"]) is not int
                or commit["credential_revision"] != authorization["credential_revision"]
                or type(commit["installed_at"]) is not int
                or commit["installed_at"] < delivery["issued_at"]
                or commit["installed_at"] > delivery["expires_at"] + cd.CLOCK_SKEW):
            _deny()
        for value in (commit["request_id"], commit["delivery_id"], commit["authorization_id"]):
            if str(uuid.UUID(value)) != value:
                _deny()
    except (ValueError, TypeError, KeyError):
        _deny()
    return {
        "schema": "zog-host-install-admin-password-commit-review-v1",
        "request_id": commit["request_id"],
        "delivery_id": commit["delivery_id"],
        "authorization_id": commit["authorization_id"],
        "credential_revision": commit["credential_revision"],
        "account_id": commit["account_id"],
        "observed_commit_time": commit["installed_at"],
        "source_contract_matched": True,
        "installed_byte_attested": False,
        "operator_pin_independently_attested": False,
        "anonymous_fd_peer_proven": False,
        "host_signed_receipt_authorized": False,
    }
