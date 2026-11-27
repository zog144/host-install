# Compiler successor: corrected authenticated inherited-peer v2 tuple

**Source-only successor to host-install PR #49, 2026-11-27. Native HOLD.**

## Selected source revisions

- root-control PR #55: `35fc1ea8969c97a00cdb4b3c18ecb47bf1f83bbb`
- box-control PR #21: `b5903779e72ea852a125a268dcd35189339dc4ae`
- image-build Boot A PR #30: `d42703b9e4f7aedce2b9959aab855485add2795a`
- host-deploy PR #35: **new verifier head is an external prerequisite, not yet selected**. The currently retained verifier `f3903dd4468436ceda20f64d67159540418325d2` pins the OLD source tuple and must FAIL against this successor until host-deploy Regular publishes/reviews the exact matching replacement.
- source inventory SHA256s: measure with `_source_inventory` using actual GitHub Actions checkout at each exact above commit and repin all roles only after source readback. Historical source hashes on PR #49 are never relabeled as hashes for the new revision.

The source verifier requires `git status` clean, no symlinked/nonregular tracked source, a canonical list of Git tracked paths and exact tracked bytes. The actual package staging uses `git archive HEAD`; ignored/untracked files do not enter the release. Both `verify_sources` and the separately installed host-deploy `SELECTED_SOURCES` equality gate must pass **before** candidate runtime or source selection may be called acceptable.

## Installer and rollback contract retained from PR #49

The only intended service is `zog-certbot-seed-root.service`, using a separately reviewed **exact unit and four effective drop-ins**: `60-boot-a-restrictive-import`, `70-fonts-combined-runtime`, `gateway-mounts`, `issuer-persistence`. A generic test fixture named `zog-root-control.service` is not a substitute for native discovery of the real composed service. The installed initial issuer helper and previous policy snapshots, exact original runtime (including literal four legacy Python venv symlinks), full systemd effective composition and exact issuer guard/STATE/UUID/grant/mount restrictions remain preserved.

Stage three exact source revisions into a **new** isolated immutable release under `/opt/zog/compiler-runtime/versions/<release-id>`, using `venv --copies`, offline source archives, pip wheel installations, `pip check`, selected Python 3.12 imports and strict no-symlink release inventory. This stage never alters the active unit, starts systemd or authorizes a build. Preserve original runtime and full original fragment/drop-in bytes in `/opt/zog/compiler-runtime/rollback/<release-id>` before attempting reviewed selection. The old runtime must remain at its own original path. Neither original issuer helper nor previous versioned policy/evidence is overwritten.

The existing source test suite verifies default-deny startup guard; systemd 252 exact Id, loaded/masked, inactive/dead, zero queued job; exact original and successor `ExecStart`, real effective drop-in `Requires/After`, issuer `ExecStartPre` and `ReadOnlyPaths`; canonical path refusal for retired compiler exceptions; and owner, STATE, mount, storage and durability constraints. Under an exclusive approved maintenance window, the selected source/service unit may be guarded/masked only after the original verified loaded stopped state. In incomplete `pending/restoring`, exact guarded and masked recovery with original rollback remains supported; all foreign files/states HOLD.

The **only** native restore path is the supported host-install `--restore` with the same originally reviewed selection bytes+digest. It compares preserved independent installed runtime/RECORD/provenance, retired old interpreter chain, exact prior unit/drop-ins, protected policy baseline, selected issuer bindings, rollback inventory and reviewed host-deploy inspector outputs. It reinstates the original composed service while the startup guard prevents early start, checks exact systemd loaded inactive/dead and original issuer restrictions, and removes the guard only after original readback. Partial and retried selections retain content-addressed/numbered immutable transaction history. A restored source-level fixture is not evidence of actual restart or reboot.

## Review and source/disposable evidence before Work

CI on the **successor PR exact head** must verify: all three source revision+inventory digests; matching new host-deploy PR #35 verifier `SELECTED_SOURCES`; Python 3.12/3.13 issuer+installer+legacy rollback tests; Amazon Linux 2023 genuine Python 3.12 versioned `venv --copies`/pip check/imports, exact installed source module SHA-256, package candidate archive hash and strict runtime inventory. The candidate artifact is **not** an installed Host release and is marked `native_installed=false`, `execution_authorized=false`, `selection_approved=false`.

A separate exact-head **independent source review** must accept the matching installer **and** host-deploy verifier before Work can proceed. Root-control/box-control real Unix-socket integration used authenticated 0:0 peer and simulated systemd, *not* PID 1 systemd 252; Work must check installed exact source and wheel RECORD on both Gateway/compiler as relevant and attest actual `SO_PEERCRED`, child UID/GID, cgroup memory.max, job InvocationID, terminal report, journal and rollback.

### Work instructions (separate authorization required)

1. Read-only preflight: exact installed compiler daemon/client/producer SHA, installed wheel RECORDs and controller Python; verify actual `/home/certbot-build-owner/certbot-seed` owner/permissions without chown/chmod, real unit and four drop-ins/effective systemd 252 properties, old runtime/interpreter, issuer mount/STATE/UUID/grants, no queued jobs and no active protected operation. Preserve request #63 and failed R5 operation and CommandIds. Stop on any mismatch.
2. Only in a **new separately approved exclusive inactive maintenance window**: choose fresh immutable release ID; stage matching candidates; preserve complete old runtime/unit/issuer composition; submit real exact selection manifest for independent hash approval, then perform guarded selection. Reverify installed final bytes, source, current HOST/Project, issuer restrictions, no unreviewed policy, startup guard and every part of systemd composition.
3. Run separately authorized disposable bounded normal client/daemon job with authenticated existing peer 0:0 through the socket, live PID1 systemd 252 and actual child/cgroup/InvocationID observation; no arbitrary User/Group/UID/GID request selectors. Capture native results without reusing R5 or request #63.
4. Under a separately approved rollback test window, explicitly restore **the original versioned installer selection** with exactly the same approval/digest, verify original complete unit/drop-ins and old runtime tree, verify original issuer mount/startup checks and supported old-service start/reboot/terminal operation, while preserving both generations and all original/past transaction receipts. No automatic replay or SSM send is permitted.

**HOLD:** Never assume a new verifier revision or source digest; until verified, the successor's source-hash and installed verifier equality gates intentionally reject selection. No Host/systemd/issuer private state/SSM/new Fonts operation is altered by Regular.
