"""Root-only, source-contract adapter for protected Django password FD handoff.

No active listener, key selection, authorization grant, installed pin or Host
receipt signing is provided here. The independent installer must establish
signed authorization and operator approval before calling this module.
"""
from __future__ import annotations
import os
from zog.host_identify import credential_delivery as cd
from .station_admin_password_receipt import (
    AdministratorReceiptContractError, CONSUMER, PURPOSE, inspect)


def _deny():
    raise AdministratorReceiptContractError("protected-admin-broker-not-approved") from None


def _frame(*, authorization, request, delivery, account_id,
           expected_binding, expected_origin, now, recovery=False):
    from zog.root_control.administrator_fd import operation_frame
    if (type(account_id) is not int or account_id <= 0
            or type(now) is not int or now <= 0):
        _deny()
    try:
        binding = cd.binding(expected_binding)
        if (binding["consumer"] != CONSUMER or binding["purpose"] != PURPOSE
            or cd.binding(authorization) != binding
            or cd.binding(request) != binding):
            _deny()
        if not recovery:
            cd.validate_authorization(authorization, expected_issuer=expected_origin,
                                      expected_binding=binding, now=now)
            cd.validate_request(request, authorization, now=now)
            cd.validate_delivery(delivery, request, authorization, now=now)
            if request["action"] != "deliver":
                _deny()
        return operation_frame(
            request_id=request["request_id"], delivery_id=delivery["delivery_id"],
            authorization_id=authorization["authorization_id"],
            credential_revision=authorization["credential_revision"],
            account_id=account_id)
    except (TypeError, ValueError, KeyError):
        _deny()


def handoff(*, channel, readonly_fd, receiver_peer, authorization, request,
            delivery, account_id, expected_binding, expected_origin, now):
    """Source-only SCM_RIGHTS submission; recipient process must be non-root."""
    if os.geteuid() != 0 or getattr(receiver_peer, "uid", None) in (None, 0):
        _deny()
    frame = _frame(authorization=authorization, request=request, delivery=delivery,
                   account_id=account_id, expected_binding=expected_binding,
                   expected_origin=expected_origin, now=now)
    from zog.root_control.administrator_fd import send_secret_fd
    send_secret_fd(channel, readonly_fd, receiver=receiver_peer, frame=frame)
    return {"schema": "zog-host-install-admin-fd-submitted-v1",
            "request_id": request["request_id"],
            "host_signed_receipt_authorized": False}


def recover(*, channel, receiver_peer, authorization, request, delivery,
            account_id, expected_binding, expected_origin, now):
    """Ask Django to inspect only a historically committed original request.

    An expired request may be inspected without authorizing redelivery.
    Caller's durable receipt ledger and native authorization remain separate.
    """
    if os.geteuid() != 0 or getattr(receiver_peer, "uid", None) in (None, 0):
        _deny()
    frame = _frame(authorization=authorization, request=request, delivery=delivery,
                   account_id=account_id, expected_binding=expected_binding,
                   expected_origin=expected_origin, now=now, recovery=True)
    from zog.root_control.administrator_fd import send_recovery
    send_recovery(channel, receiver=receiver_peer, frame=frame)
    return {"schema": "zog-host-install-admin-commit-inspection-request-v1",
            "request_id": request["request_id"],
            "host_signed_receipt_authorized": False}


def inspect_recovered(*, commit, authorization, request, delivery,
                      expected_binding, expected_account_id, expected_origin, now):
    """Check the protected result; native Host signing remains forbidden."""
    if (type(now) is not int or type(commit) is not dict
            or type(commit.get("installed_at")) is not int
            or commit["installed_at"] > now):
        _deny()
    # This is a historical, post-commit comparison, NOT fresh authorization.
    # Revalidate against the original protected commit time, not the reboot
    # time after delivery/request expiry. Host receipt remains disallowed.
    return inspect(commit=commit, authorization=authorization, request=request,
                   delivery=delivery, expected_binding=expected_binding,
                   expected_account_id=expected_account_id,
                   expected_origin=expected_origin, now=commit["installed_at"])


def read_committed_reply(*, channel, receiver_peer, authorization, request,
                         delivery, account_id, expected_binding,
                         expected_origin, now):
    """Read exactly the matching Django commit on the protected Unix channel.

    Caller retains durable evidence; response loss triggers recover() and
    another read, never repeat handoff(). No Host receipt signing here.
    """
    if os.geteuid() != 0 or getattr(receiver_peer, "uid", None) in (None, 0):
        _deny()
    frame = _frame(authorization=authorization, request=request, delivery=delivery,
                   account_id=account_id, expected_binding=expected_binding,
                   expected_origin=expected_origin, now=now, recovery=True)
    from zog.root_control.administrator_fd import receive_commit
    commit = receive_commit(channel, station=receiver_peer, frame=frame)
    return inspect_recovered(commit=commit, authorization=authorization,
                             request=request, delivery=delivery,
                             expected_binding=expected_binding,
                             expected_account_id=account_id,
                             expected_origin=expected_origin, now=now)
