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

## 2026-11-03 receiving-owner source increment

`src/zog/host_install/archive_provider_receiver.py` adds an independently reviewable **offline receiving-owner core** with no HTTP listener/client, argv/env secret transport, root-control command, credential install callback, or service activation. It imports the **exact pinned canonical source** from host-identify `59dbc181f54c6ac29ee5eb1f83b6f322fb73c037`, and reuses its actual Ed25519 signed authorization, signed Host HTTP request, signed delivery, canonical binding and ledger transitions.

The owner checks exact archive provider Host/installation/STATE/registry/collection/role/credential revisions against a separately supplied expected scope; current signed authorization approval and expiry; signed Host request identity/nonce; signed one-time delivery identity and the original request; then serializes a protected **secret-free** ledger under a separately prepared 0700 directory and 0600 original lock plus durable lock-identity marker. It takes a root-directory flock then original lock flock; checks inode/path identity and marker before and after atomic, fsynced ledger replacement. It does **not** create, recover or adopt an absent lock or original marker.

Durability phases are `idle → claimed → delivered → installed`, with a monotonic `revoked` tombstone; an interrupted `claimed` or `delivered` phase remains a **HOLD** rather than automatically redelivering. A final installed receipt is only accepted after the caller's independent installed-byte/ownership witness, and no source test witness substitutes for native verification. Claiming the same request ID after terminal status is prohibited even with a fresh nonce. Signed canonical revocation advances the common ledger **before** any future native archive-mirror `apply_signed_revocation` call; the latter is intentionally not wired, so native revocation completion/acknowledgement remains a HOLD. The archive catalogue, pinned objects, download grants and issuer signing keys are never accessed.

Tests in `tests/test_archive_provider_receiver_owner.py` use ephemeral files, synthetic Ed25519 keys and the exact selected host-identify implementation; they cover wrong identity/role/revision/collection, invalid authority and changed HTTP body, missing original lock/marker, same-byte marker substitution during claim, one-time request/delivery, absent installed witness, source interruption/restart, and signed revocation. The synthetic fixture pins `http-message-signatures==2.0.1` and its `typing_extensions` dependency because newer unreviewed versions changed the pre-existing Content-Digest handling of the selected host-identify source; this is **not** an authorization to repin its production dependency.

### Native owner obligations still blocked

- Independently select and attest original root/lock/marker custody, protected mount identity and anti-rollback, exact source/wheel RECORD, archive application UID/GID and installed storage; prevent privileged external writer/rollback.
- Root-control needs an explicit, disabled-by-default **archive** receiver entrypoint and authenticated transport/grant admission. No implicit Cloudflare/issuer receiver routing.
- Verify current credential authorization/revocation with the station authority and the independently pinned original key at each significant checkpoint; the offline core accepts keys as arguments but cannot establish their provenance.
- Wire one actual archive `install_verified` via protected FD/ownership interface. Verify persisted installed-byte receipt before calling `record_receipt`; signed real revocation requires `apply_signed_revocation` and independent durable acknowledgement with fail-closed mid-revocation recovery.
- Revalidate initial lock-marker identity from trusted install evidence across reboot and reject pre-entry byte-identical substitutions; in-operation path checks alone cannot establish original native provenance.
- Prove reboot/crash, lost acknowledgement, stale approval and dual-writer attacks in a disposable Host. Leave STATE, real credentials, catalogue and production pins untouched until explicit approval.

**Disposition:** OFFLINE_SOURCE_CORE_TESTED; **native receiver/authority/purpose installation: NO-GO**. The API is not reachable from any service and requires explicit enabling even in source tests.

## 2026-11-03 exact archive-mirror cross-owner exercise (host-install PR #21)

**Reviewed source pair:** archive-mirror `9df811cf9315efec4312e6a16738a23149d286a2`, host-identify `59dbc181f54c6ac29ee5eb1f83b6f322fb73c037`; no default-branch drift. The new `src/zog/host_install/archive_provider_consumer_bridge.py` is a **disabled, test-only in-process composition**, not a privileged root-control-to-application IPC or production installer. The existing Cloudflare consumer and purpose are untouched.

Exact offline protocol sequence:

1. Separately verified authorization + signed Host request → owner `claim` writes nonce and request record.
2. Pinned signed delivery → owner `verify_and_record_delivery` writes delivery record, never secret bytes.
3. `complete_offline` independently rechecks **current** signed authorization and original owner ledger, asks the real archive-mirror consumer `inspect(scope)`, and atomically changes owner phase from `delivered` to **`installing` before** its first and only `install_verified(scope,authorization,request,delivery)` call. A crash before/during/after that call leaves `installing`; no future invocation is allowed to redeliver, even if `inspect` reports `unavailable`. An unavailable or pending outcome requires external evidence and explicit recovery authority.
4. The application-private `inspect` result must have exact scope/delivery/revision; a separate application-owned byte witness must confirm the installed secret and private ownership. An `installed` observation after an interrupted attempt is reconciled **without another installer invocation**. Rechecking signed current authority, canonical installation receipt validation and a durable owner ledger commit precede any future HTTPS acknowledgement. There is **no actual signed HTTPS acknowledgement** in this source model. If the receipt window expires, fail closed rather than fabricate an on-time acknowledgement.
5. A signed revocation changes the **common owner ledger to irrevocable deny first**, then the bridge source-exercises the *actual* archive-mirror `apply_signed_revocation`. Interrupted application revocation can be explicitly retried with the identical signed authorization, without reopening delivery. Actual archive-mirror `inspect` must report `authorization-revoked`. Application revocation is not native-acknowledged until a future independent durable witness exists.
6. Archive-mirror's private 0700/0600 paths, role/collection checks, pending marker, rotation chain and own lock remain its responsibility. The tests use synthetic secrets and temporary directories; they never route actual provider credentials through root-control or alter managed Hosts.

`tests/test_archive_provider_consumer_bridge.py` imports the **real pinned** archive-mirror `provider_credentials`, rather than a fake consumer; exercises first install, interrupted receipt, restart and evidence-only reconciliation, denied/ambiguous byte witness, wrong purpose/identity and signed revocation. It checks retained archive objects and pins, including source-test catalogue/pin rows in temporary SQLite. The executable suite checks out both exact sources and runs Python 3.12/3.13. Root-control must implement a separate protected owner-to-application handoff (e.g. authenticated Unix socket/FD), receipt attestation and independently protected source/policy/uid pins before native activation. In-process test callbacks, `enabled=True` on an ephemeral test receiver, and a successful synthetic witness must **never** be promoted as native authority.

**Source handoff:** cross-owner proof extends the previous offline core, but all live traffic, operator approval, protected keys, Host STATE, native receipts and application service activation remain NO-GO; archive-mirror issue #2 stays open.
