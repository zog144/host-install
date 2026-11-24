# Recovered issuer startup guard: reviewed source candidate and recoverable installation

**Date:** 2026-11-23. **Owner:** host-install Regular / PR #49. **Native status:** HOLD until independent source review and authorized inactive-window acceptance.

## Exact recovered source

The last native attempt selected the approved compiler unit but the old prestart checker refused the changed unit SHA with "persistent issuer baseline mismatch". The original unit was restored and restarted. The fresh disposable root-0:0 child did not run. Retain failed native attempt **150c2b18-1b2c-461a-9b26-dd94fb05d972**; do not replay it.

The user-supplied recovered source is tracked verbatim as `src/zog/host_install/issuer_guard_original_20261023.py`. Its 3,853 bytes match the exact previously attested live file ` /opt/zog/host-install-issuer-persistence-20261023/guard.py ` (strip surrounding display spaces): SHA-256 **990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78**. Its historical October 23 installer record remains unverified.

| Artifact | Expected installed SHA-256 | Size |
| --- | --- | ---: |
| Original guard and separate protected rollback copy | 990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78 | 3,853 |
| Reviewed successor guard.py | 313cb4d644b259ece175adea24f030d36c851c753f547288aad21359a8db686e | 10,554 |
| Co-installed compiler_issuer_persistence_binding.py | 26c286dc72d772b68dd7a942ba08a77d900b9ac844f9401bd7c642ffda729a38 | 12,607 |

The replacement preserves the existing issuer-persistence.conf bytes and original systemd 252 prestart command:

` /usr/bin/python3.12 /opt/zog/host-install-issuer-persistence-20261023/guard.py verify `

The original drop-in SHA-256 remains **364366b3b49fca2349cb6aa8c5f6f3ec59d49aa08b6273dc02fd6543ce33c6ef**.

## Security and acceptance contract

The successor retains the **exact original AST** of `h()`, `snapshot()` and `verify_mounts()`. The original code checks mounted issuer DATA UUID, inode/owner/mode, storage identity, issuer grant and software binding, generation/policy manifest hashes, all previously enumerated protected file hashes and certificate-data contents, read-only generation/source mounts and writable certificate-data mount. None are suppressed on the replacement path. The saved `baseline.json` is never updated; the old `capture` operation is disabled.

The successor additionally reads the **live** `/etc/systemd/system/zog-certbot-seed-root.service.d/issuer-persistence.conf` and requires its exact bytes, SHA-256, size, root UID/GID and permission mode to match the issuer entry in the approved selected composition. It rejects symlinks, hardlinks and writable or foreign-owned paths. Checking only the preserved and staged copies is insufficient; a live-only drift denies replacement admission.

The original unit must still pass the **whole original snapshot**. For a replacement, **only** the hash of the live `/etc/systemd/system/zog-certbot-seed-root.service` may differ. The script requires the exact protected approval bytes (new create-only `rollback/<release>/approved-selection.json`), the original rollback receipt, selected unit digest and bytes, unchanged issuer drop-in restrictions and a **unique durable selected transaction**, invoking PR #49's `verify_selected_replacement_digest()` from an exact co-installed policy file. Pending, restoring, arming, restored and aborted transactions reject a **replacement** unit. Pending/restoring reject even the original unit. A restored transaction plus original bytes permits normal original startup. The independent persistent systemd startup guard is retained.

## Work-owned native install / restore sequence

1. During a separately approved inactive maintenance window, use the reviewed Host deployment channel. Read-only verify actual old helper SHA, UID/GID (0:0), mode (0444), Python 3.12 interpreter, drop-in SHA and effective ExecStartPre, original baseline SHA, issuer STATE identity, storage/grant permissions and mounted filesystems. No credentials or certificate content in public logs.
2. Install and attest the **reviewed, pinned host-install source package**, including module origins and RECORD, under /usr/bin/python3.12. The source-only CI artifact contains `original-guard.py`, `guard.py`, `compiler_issuer_persistence_binding.py` and the source manifest; it is not an install authorization.
3. When the original service is **inactive**, invoke ` /usr/bin/python3.12 -I -B -m zog.host_install.issuer_guard_deploy stage ` via the reviewed installer. This create-only step verifies the 3,853-byte live original and baseline, retains original bytes at `/opt/zog/compiler-runtime/issuer-helper-rollback-20261123/original-guard.py` mode 0400, and stages source-pinned replacement/policy in protected files. The live prestart helper is unchanged. Existing stage or hash mismatch is HOLD.
4. Independently verify rollback copy, original baseline and staged SHA values; invoke ` /usr/bin/python3.12 -I -B -m zog.host_install.issuer_guard_deploy activate ` while inactive. The tool installs the verified policy alongside the existing helper path, atomically replaces only guard.py at its **same original pathname** with root-owned mode 0444, verifies new bytes and records activation. It neither changes the drop-in, unit nor issuer baseline.
5. Validate **original startup**, unchanged issuer STATE/mount/grant policies, the new selected-only acceptance, denied foreign units, denied incomplete transactions, denied any issuer storage change. Run selection via the existing guarded PR #49 transaction only after independent approval of the real unit/drop-ins, source and stored exact selection bytes.
6. For emergency or planned rollback, first restore the **original controller unit and drop-ins** with PR #49 protected restore, verify the original unit SHA and durable **restored** transaction, stop the service under approved maintenance, then invoke ` /usr/bin/python3.12 -I -B -m zog.host_install.issuer_guard_deploy restore `. The helper installer refuses to restore over a selected unit or incomplete transaction. It recovers the original 3,853-byte script from its separately retained root-owned copy, removes only the exactly matching new policy file, and keeps original baseline and previous rollback/operation evidence untouched.
7. Confirm original startup and boot/reboot persistence with actual systemd 252 readback and all issuer mount/permission checks. Only **host-install Work** may perform a **new bounded disposable 0:0 probe** after approval. Keep Fonts disabled; do not replay the prior failed attempt.

## Evidence, tests and remaining boundary

- `tests/test_issuer_guard_successor.py` checks source parity, original/approved-selected/restored startup, manifest and transaction tampering, baseline storage identity, foreign unit, unexpected files and interrupted state.
- `tests/test_issuer_guard_deploy.py` checks original/helper recovery bytes, create-only stage, selected unit preventing helper rollback, altered policy/guard rejection, baseline immutability and reinstallation safeguards.
- Python 3.12 and 3.13 source CI plus separate real AL2023 controller staging are required. Native systemd 252 issuer mount, cold reboot and fresh 0:0 execution have **not** been exercised by Regular.

**Do not activate** merely because CI passed. The exact helper commit, both new SHA-256 values and original rollback SHA must be independently reviewed/attested before Work's inactive-window native run.


## November 23 — native helper installation must observe fully stopped systemd unit

Independent review found that accepting `systemctl is-active --quiet` exit codes 3 or 4 does not prove an expected unit exists or has finished stopping. In particular, `activating` and `deactivating` are transitional states, and a missing unit cannot qualify for safe installation.

`issuer_guard_deploy._inactive()` now queries `systemctl --no-pager --all show --property=Id,LoadState,ActiveState,SubState,Job zog-certbot-seed-root.service` and **requires all of**:

- `Id=zog-certbot-seed-root.service` and `LoadState=loaded` (not masked, missing, invalid, or another unit);
- `ActiveState=inactive` **and** `SubState=dead` (not starting, stopping, reloading, failed, or restarting);
- `Job=` (systemd 252's absent-job representation) or explicit `Job=0` (no enqueued unit start/stop job).

A nonzero command exit, missing/duplicate/unknown property, or nonzero/malformed job fails closed. The native check runs at the beginning of **stage, activate, and restore**, and is repeated immediately before the atomic live-helper activation or rollback swap. The original issuer data, helper and policy source hashes, protected baseline and transaction remain unmodified by this correction.

These checks establish **observed manager state**, not a lock against a concurrent new unit start immediately after the query. Work must still use the approved inactive maintenance window and controlled native installation path to exclude unrelated start/stop actors; do not infer full race freedom from a one-time systemd readback.

Source tests mock systemd 252 responses for loaded/inactive/dead/no-job, `activating`, `deactivating`, absent/masked/wrong units, queued start/stop jobs, partial or duplicate property readback, and a systemctl error. Each native entrypoint is required to deny unsafe states before touching deployment files. Real systemd 252 acceptance and service readback remain Work-owned.


## November 24 — supported restored → staged helper rearm

The helper installer now supports **one narrow rearm** when its existing protected rollback directory contains a **durably `restored`** helper record. It no longer needs to delete/recreate the rollback directory or overwrite original backup files between approved maintenance windows.

The `stage` command still requires the exact loaded `zog-certbot-seed-root.service` to be `inactive/dead` with no queued systemd job on the real Host. It verifies all of the following *before* changing the record:

- The live original `guard.py` is root-owned, regular, mode 0444 and byte-identical to the recovered 3,853-byte original SHA-256; the original main unit matches the saved `baseline.json` unit digest.
- The full original issuer baseline bytes still match the baseline SHA-256 in the helper rollback record; the original baseline is not captured or rewritten.
- All three **previously staged, protected** files—`original-guard.py`, `approved-successor.py`, and `approved-binding.py`—retain the reviewed exact bytes, hashes and mode 0400; the rollback record's original/successor/policy SHA values remain correct.
- No co-installed policy file remains after restoration, and no compiler selection for this service is `arming`, `pending`, `selected`, or `restoring`.
- The existing record has `state=restored`. An already-`staged` or `active` helper, foreign record, or changed rollback evidence remains a fail-closed HOLD.

Before the transition, the **unchanged restored-state record bytes** are copied using a create-only, fsynced file `restored-before-restage-000001.json` in the same protected rollback directory (0400), with the number increasing on each completed cycle. An interrupted attempt after receipt creation but before commit can retry **only if the saved receipt equals the current protected restored record**; it does not overwrite the historical evidence. Only `record.json` is atomically advanced from `restored` to `staged`, with a monotonic `restage_count`. Existing backups, receipts, issuer baseline, original service, certificates and selected-operation records stay untouched. `activate` and `restore` retain their independent inactive-state checks and protected rollback behavior.

**Work procedure:** During the separately approved inactive maintenance window, verify the existing protected `record.json` shows `restored` and the original unit/helper/issuer protections pass; then invoke the already reviewed `issuer_guard_deploy stage` again. Do not remove the rollback directory or use a new helper identity. Read back the new `staged` state, the create-only restored-record receipt and the unchanged three protected source files before authorizing the next helper activation. Source tests include a successful stage → activate → restore → re-stage → activate → restore cycle, two distinct restage receipts, fail-closed cases for changed live original/baseline/protected source copies/receipt or an incomplete controller transaction, and a crash/retry between receipt creation and record commit. The historical failed native operation stays preserved. Real systemd 252 startup, reboot, fresh bounded `0:0` fixture and full restoration remain Work-owned.


## November 24 — reviewed old compiler retirement and protected policy revision

**Source compatibility with host-deploy PR #35 revision `9239f5ec648ab3ad4d8a1cba63f28ec8679f757d`.** The original issuer baseline and the original/selected `issuer-persistence.conf` bytes, ownership, mode, SHA-256, and the **live** drop-in readback are unchanged. The policy now permits removing original-only systemd `ExecStartPre` commands and `ReadOnlyPaths` **solely** for the exact previously recorded compiler root `/opt/zog/fonts-controller-d9dfd6c0-20261114` (and its slash-delimited descendants), requiring that root to match `selection.rollback.original_runtime` exactly. A merely similar prefix, a different original runtime, or an issuer application path such as `/opt/zog/certbot-seed-oct21` is **not** eligible for retirement. All original nonretired prestarts, all commands declared by the issuer drop-in with exact executable/argv/nonignored flags, issuer read-only paths, and **every original Requires/After backing-mount dependency** remain required after selection. Neither the issuer storage UUID/grant/ownership/certificate-data checks nor the original issuer snapshot/mount functions are altered.

**New installed policy SHA-256:** `3607f36bb40ea093433224749570de47f607dc43e965b2e7aee49e88ef953bc7`, **15,573 bytes**, at `/opt/zog/host-install-issuer-persistence-20261023/compiler_issuer_persistence_binding.py`. This replaces the *source selection*, not the historical protected policy backup. The original 3,853-byte helper SHA-256 `990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78`, unchanged successor guard SHA-256 `313cb4d644b259ece175adea24f030d36c851c753f547288aad21359a8db686e`, original `issuer-persistence.conf` SHA-256 `364366b3b49fca2349cb6aa8c5f6f3ec59d49aa08b6273dc02fd6543ce33c6ef` and the issuer `baseline.json` must remain exactly as accepted. Prior policy `26c286dc72d772b68dd7a942ba08a77d900b9ac844f9401bd7c642ffda729a38` is **historical**, not the expected new installed policy.

### Supported re-staging and policy revision

The supported `issuer_guard_deploy stage` is narrow and **requires the existing live original helper and original controller unit**, verified inactive/dead with no queued systemd job and matching their protected saved baseline, with **no co-installed policy file** and **no incomplete compiler transaction**. Existing helper `record.json` may be `restored` or `staged`; an `active` helper must first be restored through the approved rollback path. An existing `staged` record may only be re-staged when the reviewed policy SHA changes; an unchanged `staged` record remains HOLD. Every existing helper record's original and successor SHA pins and three protected source files must remain valid.

When the reviewed policy differs, `stage` does **not** overwrite `approved-binding.py` or any prior `approved-binding-<old-sha>.py`. It creates a new **root-only, mode-0400, content-addressed** `approved-binding-3607f36bb40ea093433224749570de47f607dc43e965b2e7aee49e88ef953bc7.py` (or verifies exactly matching existing bytes after an interrupted attempt). Then, before changing `record.json`, it saves the original complete state record as a separate create-only, fsynced receipt. A `restored` transition uses `restored-before-restage-00000N.json`; a `staged` policy revision uses `staged-before-policy-update-00000N.json`. The mutable record is atomically updated to `state=staged`, the new `policy_sha256` and `policy_backup_name`, retaining `previous_policy_sha256` and monotonic transition counts. Old policy copies, previous receipts, the original helper rollback and original baseline remain untouched. A crash between creation of versioned copy/receipt and record commit is retryable **only when** the existing content-addressed copy and receipt match exactly. Changed backup bytes, foreign source pin, a residual live policy, wrong original runtime, or unresolved operation remain fail-closed.

**Work action after independent review:** First attest original live helper/controller and the protected restored/staged record, old policy backup digest, original issuer drop-in and STATE/mount/grant/DAC checks in the approved inactive window. Install the newly SHA-pinned host-install package through reviewed channels and call `stage` without deleting the rollback directory. Read back *both* the original policy backup and new content-addressed version, immutable prior-record receipt, new staged `record.json` and unchanged original baseline. An old **active** helper whose historically installed policy matches its protected old `policy_sha256` may still be restored with the reviewed current installer **after the original controller is restored and inactive**: restoration checks the exact saved old policy bytes rather than imposing the new source pin, reinstates the original helper and removes only that historical installed policy. **Activation, in contrast, always requires a previously staged policy matching the new reviewed source pin.** This prevents a source update from obstructing safe rollback while prohibiting direct activation of an unstaged replacement policy. Both operations preserve the old policy backup and original receipts.

Then separately authorize `activate` to install the revised policy and the unchanged selected-only guard, verifying native policy SHA-256, systemd 252 effective issuer restrictions, original/replacement startup and reboot, a **fresh bounded 0:0 fixture**, and guarded controller/helper restoration. Keep Fonts disabled. Do not replay the retained failed operation or modify protected receipts.

**This is source CI acceptance only.** No native Host, issuer storage, service or live drop-in was changed during Regular implementation. Earlier CI helper bundles and compiler candidates with the old verifier/policy hash are not valid evidence for the newly selected combination.
