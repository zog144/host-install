"""Disabled source-only archive receiver -> actual archive-mirror consumer path.

Unlike the Cloudflare issuer path, this uses *only* archive-provider purpose and
consumer. Native installation must pin the real archive application identity,
authority public key, protected STATE and witness; source tests use synthetic
credentials in disposable directories. No HTTP service, secret, key or native
owner is installed by this module.
"""
from __future__ import annotations

from zog.host_identify import archive_credentials as policy
from zog.host_identify import credential_delivery as cd

from .archive_provider_receiver import OfflineArchiveReceiver, ReceiverHold


class ArchiveProviderHandoff:
    def __init__(self, *, receiver, expected_scope, authority_public_key,
                 expected_issuer, native_witness=None, enabled=False):
        if enabled is not True:
            raise ReceiverHold("archive provider handoff disabled")
        if not isinstance(receiver, OfflineArchiveReceiver) or receiver.enabled is not True:
            raise ReceiverHold("selected protected receiving owner missing")
        if authority_public_key is None or not isinstance(expected_issuer, str):
            raise ReceiverHold("protected authority pin and issuer missing")
        # This scope must be loaded from the native protected host-install
        # policy, NEVER caller-selected via delivery inputs.
        selected = policy.provider_scope(expected_scope)
        if selected["provider_role"] != policy.PROVIDER_ROLE:
            raise ReceiverHold("archive provider purpose mismatch")
        if not callable(native_witness):
            # No boolean/test-only witness silently qualifies in production.
            raise ReceiverHold("independent archive installed-byte witness required")
        self.receiver = receiver
        self.scope = expected_scope
        self.authority_public_key = authority_public_key
        self.expected_issuer = expected_issuer
        self.native_witness = native_witness

    @staticmethod
    def _consumer():
        # Native owner must select installed archive application bytes and UID.
        # Import is here to avoid enabling an unselected consumer at boot.
        from zog.archive_mirror import provider_credentials
        return provider_credentials

    def claim(self, *, signed_authorization, url, method, headers,
              body, host_public_key, now):
        """Verify signed authorization/host HTTP and consume nonce first."""
        return self.receiver.claim(
            scope=self.scope, expected_scope=self.scope,
            signed_authorization=signed_authorization,
            authority_public_key=self.authority_public_key,
            expected_issuer=self.expected_issuer,
            url=url, method=method, headers=headers, body=body,
            host_public_key=host_public_key, now=now)

    def deliver_once(self, *, signed_authorization, request,
                     signed_delivery, now):
        """Durable send-to-archive intent FIRST; one actual consumer call.

        On an exception or lost response, installation state is irreversibly
        'installing' and a second call is forbidden, even if same bytes.
        """
        auth = policy.verify_provider_authorization(
            signed_authorization, self.authority_public_key,
            expected_issuer=self.expected_issuer, scope=self.scope, now=now)
        if auth["status"] != "approved":
            raise ReceiverHold("revoked delivery")
        delivery = cd.verify_delivery(signed_delivery, self.authority_public_key,
                                      request, auth, now=now)
        policy.validate_delivery(self.scope, auth, request, delivery, now=now)
        stage = self.receiver.verify_and_record_delivery(
            scope=self.scope, expected_scope=self.scope,
            signed_authorization=signed_authorization,
            authority_public_key=self.authority_public_key,
            expected_issuer=self.expected_issuer, request=request,
            signed_delivery=signed_delivery, now=now)
        if stage != {"status": "delivered", "delivery_id": delivery["delivery_id"]}:
            raise ReceiverHold("owner delivery witness changed")
        claimed = self.receiver.begin_install_handoff(request=request, delivery=delivery)
        if claimed["status"] != "installation-uncertain":
            raise ReceiverHold("owner installation fence unavailable")
        # This is the irreversible consumer mutation, never called again by
        # this owner for the same delivery or an uncertain installation.
        result = self._consumer().install_verified(self.scope, auth, request, delivery,
                                                   now=now)
        if (not isinstance(result, dict) or result.get("status") != "installed"
                or result.get("delivery_id") != delivery["delivery_id"]
                or result.get("scope_id") != policy.provider_scope(self.scope)["scope_id"]):
            raise ReceiverHold("archive consumer result requires reconciliation")
        # No receipt created here; independent native receipt + byte witness
        # must establish installed reality before owner acknowledges.
        return {"status": "consumer-installed-receipt-pending",
                "delivery_id": delivery["delivery_id"]}

    def reconcile_receipt(self, *, receipt, request, delivery, now):
        """No new consumer install; prove actual archive bytes independently."""
        observation = self.receiver.inspect_handoff()
        if (observation["status"] != "installing"
                or observation["request_id"] != request.get("request_id")
                or observation["delivery_id"] != delivery.get("delivery_id")
                or observation["revoked"]):
            raise ReceiverHold("no matching uncertain archive installation")
        app = self._consumer().inspect(self.scope)
        selected = policy.provider_scope(self.scope)
        if (app.get("status") != "installed" or
                app.get("scope_id") != selected["scope_id"] or
                app.get("delivery_id") != delivery["delivery_id"] or
                app.get("credential_revision") != selected["credential_revision"] or
                app.get("role_revision") != selected["role_revision"]):
            raise ReceiverHold("archive installation not independently observed")
        # The injected native witness is separately protected; source-only
        # app inspection is not an installed-byte witness by itself.
        def proof(req, delivered, submitted_receipt):
            return (self.native_witness(self.scope, req, delivered,
                                        submitted_receipt, app) is True)
        return self.receiver.record_receipt(receipt=receipt, request=request,
                                            delivery=delivery, now=now,
                                            verify_installed_receipt=proof)

    def apply_revocation(self, *, signed_revocation, now):
        """Durably forbid new claims before archive-local signed tombstone."""
        result = self.receiver.hold_revoked(
            scope=self.scope, expected_scope=self.scope,
            signed_authorization=signed_revocation,
            authority_public_key=self.authority_public_key,
            expected_issuer=self.expected_issuer, now=now)
        if result["status"] != "revocation-hold-durable":
            raise ReceiverHold("revocation hold not durable")
        actual = self._consumer().apply_signed_revocation(
            self.scope, signed_revocation, self.authority_public_key,
            expected_issuer=self.expected_issuer, now=now)
        observed = self._consumer().inspect(self.scope)
        if (actual.get("status") != "revoked"
                or observed.get("status") != "blocked"
                or observed.get("reason") != "authorization-revoked"):
            raise ReceiverHold("revocation needs independent consumer reconciliation")
        return {"status": "receiver-and-archive-revoked",
                "scope_id":policy.provider_scope(self.scope)["scope_id"]}
