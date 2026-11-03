# Archive provider HTTPS receiver — disabled source handoff (2026-11-03)

Source-only companion to [archive-mirror #2](https://github.com/zog144/archive-mirror/issues/2). Proposed interface lives in `archive-provider-receiver-contract-v1.json` with synthetic state transition tests; **it is not a receiver implementation** and cannot accept HTTP, signatures or credentials. The branch is stacked on host-install PR #5 for context, **not** a selection of Cloudflare issuer semantics.

## Exact external source

- Archive provider adapter `zog144/archive-mirror` at `9df811cf9315efec4312e6a16738a23149d286a2`.
- Canonical archive binding `zog144/host-identify` at `59dbc181f54c6ac29ee5eb1f83b6f322fb73c037`.
- Historical issuer-only receiver contract host-install PR #5 at `17e3e0e6b9405a3a81dc25575ba2dadcf6bfa588`, **not approved** for archive purpose.

## Required protected owner behavior

1. Admit only an explicitly installed and operator-approved purpose `archive-mirror-upstream-fetch`, consumer `archive-mirror`, role `archive-mirror-provider`, operation `fetch`. Default disabled; no automatic fallback to the issuer/Cloudflare receiver.
2. Under an independently pinned authority key and authenticated HTTP transport, verify canonical signed authorization, origin signer, nonce, current revision, expiry, Host + HostIdentity fingerprint, installation ID, STATE volume, registry, application owner UID/GID, protected archive storage identity, provider/origin/collection scope and source revision before any credential bytes are exposed.
3. Root-control/common protected receiver owns the durable serialized request/nonce/delivery/revocation ledger. Durable claims **precede** the archive-specific `install_verified(scope,authorization,request,delivery)`; an authenticated, secret-free receipt **follows** a verified installation. A receipt may be acknowledged only after durable publication and readback. Reject conflicting duplicate request identities or changed bytes, and reverify authorization on same-byte recovery; do not assume that an identical ledger entry alone is sufficient for native replay.
4. For signed revocation, verify the independent authority signature and exact purpose/Host/installation/STATE/scope before mutating any state. Durably commit the common revocation tombstone first, then invoke `apply_signed_revocation(scope,envelope,authority_key,expected_issuer=...)`. If interrupted between steps, **deny all opens and deliveries** until idempotent application-local revocation completes. Persist a secret-free revocation receipt last.
5. Archive-mirror itself owns `0700` application-private provider directory, `0600` secret and metadata, active role/collection checks, pending installation, and nonsecret receipt. The root receiver must not gain direct archive catalogue mutation authority. Credential replacement, revoked role or lost mirror lease must never delete archive catalogue, pinned content or retained objects. Separate JWT download grants and issuer signing keys are excluded.
6. Native integration must verify actual root-control/host-install selected source, wheel RECORD, protected listener, station signer provenance, signature correctness, group ownership, identity, crash recovery, reboot retention, installed bytes and no host-library fallback. No native approval, token delivery, ACL change or service enablement results from this handoff.

## Source negative test boundary

`tests/test_archive_provider_receiver_contract.py` models purpose and destination mismatch, non-current/expired authorization, missing independent verification, lost acknowledgement, changed replay request/secret digest, nonce replay, incomplete installation, monotonic rotation, wrong predecessor, signed revocation-before-application ordering, and archive catalogue/object/pin preservation. These tests prove only **the proposed transition ordering**, not cryptographic verification or a usable HTTPS receiver.

**Status:** SOURCE_INTERFACE_DISABLED_NO_NATIVE_ADMISSION. Archive-mirror adapter remains source-complete; protected native receiver remains outstanding under archive-mirror #2.
