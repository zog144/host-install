# Task C trust broker — systemd mount-readiness corrective native handoff

2026-11-05. Source correction for [host-install PR #32](https://github.com/zog144/host-install/pull/32). The read-only trust broker is already installed in the retained environment, but **do not activate it**.

## Corrected exact source unit

`src/zog/host_install/systemd/zog-graphical-trust.service` now declares exactly these two dependencies under **[Unit]**, not [Service]:

```ini
[Unit]
RequiresMountsFor=/var/lib/zog-graphical-owner-ledger
RequiresMountsFor=/var/lib/zog-graphical-owner-authority
```

Both `RequiresMountsFor=` directives in [Service] were ignored by systemd, so the previous installed service had no effective mount-ordering guarantee. The exact corrected service bytes have SHA-256 `217e4213166a2f0268b3b0d7128a03ec59d56a74f1870cacc6203efbc4184c31`. The installer pins this value as `BROKER_SERVICE_SHA256`, still requires `selection.broker_service_sha256` and `broker_manifest.service_sha256` to match the same actual bytes, and validates both mount dependencies **exactly once under [Unit]**. The already selected original owner, root-control, host-deploy sources, source/wheel RECORD obligations, protected Python and credential separation remain unchanged. The unit/socket have no [Install] activation target.

## Host-install Work — exact installed-file correction and effective systemd test

1. Confirm the retained Host/installation/STATE identity and current selected installer source revision. Read and hash the existing installed `zog-graphical-trust.service` and socket unit, retaining a rollback copy/evidence. Ensure they correspond to the pre-correction source; avoid rewriting unrelated installed sources, credentials, signed approvals or original checkpoint authority. Do not change the original S3 account/region/bucket/prefix/scope/genesis/writer role or independently retained anchor.
2. Install **only** the corrected reviewed service unit bytes via the authorized protected installer, with correct root ownership/mode and its exact SHA-256 above; update the protected installation/manifest receipt for this **new unit hash** without claiming a new wheel RECORD or source hash for unchanged packages. Re-verify existing socket byte hash and selected separate read-only GetObject/signer credential slots. Any byte mismatch, changed inode/owner/pin or interrupted publication must HOLD.
3. Run `systemd-analyze verify` against the effective installed service and companion socket, and inspect any diagnostics. Run `systemctl daemon-reload` to load the corrected unit definition, but **do not start, enable, restart or trigger** the trust broker or its socket. Check `systemctl cat zog-graphical-trust.service` for unintended drop-ins and `systemctl show -p FragmentPath -p DropInPaths -p Requires -p After zog-graphical-trust.service`; the effective dependency graph must reference both protected mount units (compute unit names with `systemd-escape --path --suffix=mount`). If those paths are not actual mounts or generated dependencies are missing, mark native mount-readiness unaccepted; do not fabricate a PASS from static text or default mount paths.
4. Confirm both units remain disabled and inactive (`systemctl is-enabled`, `systemctl is-active`), no SSM sent, no new S3 ledger/genesis, and no changed IAM/key material. Capture before/after unit hash, `systemd-analyze verify`, effective `Requires`/`After` dependency properties, mount backing/device identity and service/socket inactivity in a native acceptance receipt. Test negative mount-readiness in an isolated disposable environment, never by unmounting retained production STATE.
5. Attribute only the **mount-readiness correction** as accepted if proven. Native original purpose approval, signed issuer provenance, signer custody, effective GetObject-only IAM, authenticated gateway peer and normal owner→SSM software route remain independently gated. Denial of SSM/STS/IMDS to a separately credentialed gateway service is optional hardening, never a requirement to prove the trusted Host administrator cannot access SSM; fixing this unit does not make Task C broker admission GO.

## Source verification

Python 3.12/3.13 exact-three-owner CI covers corrected source bytes and explicit wrong-section, missing, duplicated and old-manifest-hash regressions. This is **source verification**, not evidence that systemd on the retained installation has loaded the new unit. No native runtime was changed in Regular.
