# Recovered issuer startup guard: reviewed source candidate and recoverable installation

**Date:** 2026-11-23. **Owner:** host-install Regular / PR #49. **Native status:** HOLD until independent source review and authorized inactive-window acceptance.

## Exact recovered source

The last native attempt selected the approved compiler unit but the old prestart checker refused the changed unit SHA with "persistent issuer baseline mismatch". The original unit was restored and restarted. The fresh disposable root-0:0 child did not run. Retain failed native attempt **150c2b18-1b2c-461a-9b26-dd94fb05d972**; do not replay it.

The user-supplied recovered source is tracked verbatim as `src/zog/host_install/issuer_guard_original_20261023.py`. Its 3,853 bytes match the exact previously attested live file ` /opt/zog/host-install-issuer-persistence-20261023/guard.py ` (strip surrounding display spaces): SHA-256 **990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78**. Its historical October 23 installer record remains unverified.

| Artifact | Expected installed SHA-256 | Size |
| --- | --- | ---: |
| Original guard and separate protected rollback copy | 990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78 | 3,853 |
| Reviewed successor guard.py | 1824e25c977617f610927fa4777e88e61d4fe674ab6738c3597bf222d38458b8 | 9,195 |
| Co-installed compiler_issuer_persistence_binding.py | d6e979e17b7301d49993bef44a7c66abe8d6eb92fb9c4b5fcf19b01209297b5d | 11,331 |

The replacement preserves the existing issuer-persistence.conf bytes and original systemd 252 prestart command:

` /usr/bin/python3.12 /opt/zog/host-install-issuer-persistence-20261023/guard.py verify `

The original drop-in SHA-256 remains **364366b3b49fca2349cb6aa8c5f6f3ec59d49aa08b6273dc02fd6543ce33c6ef**.

## Security and acceptance contract

The successor retains the **exact original AST** of `h()`, `snapshot()` and `verify_mounts()`. The original code checks mounted issuer DATA UUID, inode/owner/mode, storage identity, issuer grant and software binding, generation/policy manifest hashes, all previously enumerated protected file hashes and certificate-data contents, read-only generation/source mounts and writable certificate-data mount. None are suppressed on the replacement path. The saved `baseline.json` is never updated; the old `capture` operation is disabled.

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
