# Graphical current-signing-authority installation and rotation — source-only

**Candidate:** host-deploy [PR #11](https://github.com/zog144/host-deploy/pull/11), current source head `66fd5b530aa2b6a3444ca223dd95e5b7246cd771`; root-control issue #21.

This candidate does **not** install an authority on a Host. It defines the source-only transaction `graphical_current_authority.rotate_source` over two **independently opened and authenticated** descriptor roots: exactly `/etc/zog/host-deploy` (root:root 0755, containing the fixed `graphical-chain-current-owner-pin-v1.json` 0444) and separately provisioned root:root 0700 protected private epoch state. The native owner must supply authentic signed source evidence, installed-source/RECORD, actual Host/installation/boot/policy, live signer provenance, and a stable root-only writer lock. A random directory fd in a source test is not a native authority.

A separately pinned operator Ed25519 public key must verify an exact domain-separated signed approval binding the previous installed pin digest, new pin digest, Host, installation, next monotonic epoch, authorization revision and approval ID. The new source pin conforms to the existing host-deploy public schema, changes signer at rotation, retains Host/installation/lane/policy/first-generation binding, and increments epoch exactly once. The fixed current path cannot be selected by a caller; old generation paths never become authority.

The staged update creates the immutable *public denial marker* `graphical-chain-current-owner-rotation-pending-v1.json` **before** changing either private highwater or current key. The gateway's `graphics_chain_export._read_public_pin` now refuses any pending final/symlink/malformed marker before AND after reading the fixed current key. The protected owner fsyncs the private epoch highwater, atomically replaces the fixed public 0444 pin, rereads both exact bytes, and removes only the matching reservation with parent fsync. A crash at any stage leaves pending denial or a fully installed new pin; same operator-signed intent can resume without lowering epoch, and a rollback/foreign key/unknown approval stops. The native owner must additionally serialize this transition with its own installed trusted signing and live-epoch issuer so old signing cannot continue across the commit.

Source tests cover first install, exact signed rotation, same-byte retry, invalid operator key, old epoch rollback, lost private ledger, symlink/partial marker, and simulated faults after pending, private state, public rename and acknowledgement. The source coordinator accepts dirfds for synthetic testing only; no untrusted CLI, HTTP receiver, STATE provisioning, signer/private-key writer, or native activation is exposed.

**Remaining native gates:** external trusted operator-key provenance, real source/wheel/RECORD and exact directory ancestry, root-only mutual exclusion with compiler native live signing and boot epoch, power-loss durable interruption/recovery, independent old-key rejection and Host relay tests, strict revocation without reselecting old keys, and deliberate operator acceptance. Existing graphical compilation and runtime activation remain NO-GO.


## Independent monotonic checkpoint (source extension, 2026-11-01)

**Threat closed at source-contract level:** a coherent rollback of *both* the 0444 public current pin and root-private 0600 local epoch journal could escape a purely local comparison. The new `graphical_rotation_checkpoint` source module defines an independent checkpoint issuer with a **separate Ed25519 verification key**, authenticated original Host + installation binding, signed `epoch`, exact SHA-256 current public pin, authorized approval SHA-256 and an externally monotonic `sequence`. Each read must bind a fresh random challenge. Previously signed responses are not reusable for the new challenge. The external issuer MUST persist the counter in a separately administered rollback domain, provide linearizable compare-and-advance semantics, durably reject an epoch decrease or same-epoch authority replacement, and sign only the current value. A locally held signed copy is NOT sufficient. This repository does not implement or deploy that external issuer.

The source `rotate_checked_source` retains the existing fixed local writer lock and:
1. Reads a *fresh authenticated* external checkpoint before attempting rotation and compares it to the local current pin and epoch.
2. Publishes the existing public pending-denial marker before requesting the independent external compare-and-advance. An interrupted/absent response remains HOLD.
3. Requires fresh signed verification of the advanced external record before modifying the local private epoch and public key; recovery from an interrupted transaction only accepts the **same** reserved approval, key and epoch.
4. Rechecks the external authority after local publication. A concurrent external change, unavailable issuer, stale replay, foreign Host/installation or stale local epoch is denied.
5. Exposes `read_checked_source` as **source-only reader parity**: public pin with locally coherent private journal still fails if a fresh independent checkpoint is ahead or unavailable.

**Updated 2026-11-01:** The ordinary exported `rotate_source` now **mandatorily** retrieves the independently installed root 0444 checkpoint pin from the fixed `/etc/zog/host-deploy/graphical-external-checkpoint-pin-v1.json`, uses only the fixed `/run/zog/host-deploy/graphical-external-checkpoint.sock` transport, and calls `rotate_checked_source` with those implementation-owned read/CAS operations. Missing/malformed pin, transport unavailability, stale/wrong signer, old epoch, or operator/issuer key identity collision all fail before authorized local publication. The old unchecked **public facade is removed from shipped source**; pre-existing basic crash/lock tests use a helper defined only inside `tests/`. `rotate_checked_source` remains explicitly a synthetic contract harness accepting test callbacks and **must not be called as a protected native entrypoint**.

**host-deploy integration:** `graphics_chain_export.load_selected_step` now requires an independently signed online snapshot matching the exact canonical current Host pin SHA and epoch *before* export signature validation, and independently rechecks with a new nonce *after* the Host live-epoch acknowledgement. The external signer key is distinct from the Host signing key, fixed and protected, and a separate UID-pinned relay transports but cannot mint signed checkpoint evidence. Coherent rollback of local public pin and private journal is rejected against the external highwater; caller-supplied alternate signer, reader or callback is not accepted. This closes the confirmed source consumer gap, **not** the native installation gate.

The fixed pin and relay are NOT yet installed; the real independent issuer, its linearly durable ledger, CAS authorization and reboot/rotation race fencing are not established natively. Absence intentionally blocks all graphical stage selection. Protected native owner must independently pin the external key, install and authenticate the relay, ensure online availability and test its true nonrollbackable ledger before authorizing any compiler stage. Protected native owner + gateway consumer must independently pin the external service's public key, install the authenticated transport, make it a mandatory online gate at rotation AND every live signing-key acceptance, synchronize with the true Host live-epoch issuer, and test power-loss plus external availability/failover. The source callbacks are test harnesses, not independently trusted native endpoints. The consumer must not use an offline cache or substitute the operator/Host key for the external checkpoint key.

Negative tests explicitly restore both local files to an earlier coherent snapshot while leaving the synthetic external highwater advanced; attempts to read or rotate then fail. Tests also cover unavailable issuer, nonce replay, wrong checkpoint signer, Host mismatch, same-epoch different key, and interruption after external CAS or during local publication. No production signing key, STATE or external service was changed.


## Integration and secure handoff

The ordinary graphical rotation's fixed online transport accepts no endpoint,
issuer-key or reader callback from the caller. The source-level replica of the
legacy local-only rotation lives only under `tests/test_graphical_current_authority.py`
to preserve crash, fsync and stable-inode lock regression coverage. That
synthetic fixture has no native installer or gateway authority.

For native acceptance, the checkpoint issuer must be independently administered
and monotonic outside the Host local rollback domain, and the protected installer
must bind the exact user authorization, root-host current pin, source commit and
operator signer. The gateway's external read must be a real fresh online
signature, not a locally cached tuple or a response signed by the compiler Host.
No external deployment, no protected STATE, no key rotation and no compiler
submission was performed in this source pass.
