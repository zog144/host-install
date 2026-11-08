# Registry Host directory-backed STATE: retained identity and account migration

**2026-11-08 · host-install PR #36 · SOURCE INTEGRATION PASS, NATIVE HOLD**

This is the **selected single handoff** following the original [private Work inventory](https://github.com/zog144/know-file/blob/01ec0766d495d57a5513274c34b895f0747162d9/host-install/handoffs/host-registry-directory-state-account-migration-2026-11-08.md). It is **not** a license to modify the live registry Host. Work reported the Host unchanged, and Regular has run only GitHub Actions plus disposable filesystem tests.

## Source pins and ownership

| Component | Reviewed immutable source | Purpose |
|---|---|---|
| host-install [PR #35](https://github.com/zog144/host-install/pull/35) | `dfce38a239957b98c1d433dac94ea9fc4b0918fd` | Canonical root-directory STATE, no registrar signature |
| host-identify [PR #1](https://github.com/zog144/host-identify/pull/1) | `39972469ec01017f83dea488ca5b868d9d691062` | Retained legacy Ed25519 key loader via identity and root completion FDs |
| host-discover [PR #8](https://github.com/zog144/host-discover/pull/8) | `99965cf6d66f68c92affbedf585bf7b366f4d095` | Opt-in unchanged-beacon retained identity consumer, certificate assignment preserved |
| host-install [PR #36](https://github.com/zog144/host-install/pull/36) | this branch's exact reviewed source head | Root-only migration source candidate and negative tests |

Both companions are checked out at the exact SHAs and their retained loader and beacon tests run in host-install CI. They are **source selections**, not proof of matching installed wheels or production dependency closure. Task C v3's separate owner/broker/SSM frozen selection in PR #35 remains unchanged and disabled.

## Native read-only initial selection (must be revalidated)

The selected long-lived registry instance is `i-0da27c843d92f610c` in `us-east-1`. Work reported writable XFS root filesystem UUID `bb1da0c1-2cbf-492f-911c-93fd0083b4a4` and root PARTUUID `ee697950-63b6-4d79-ab2c-35012403cc6e`. No canonical `/state` or `/etc/zog/host-install` configuration existed in that read-only snapshot. This is **historical evidence, not a fresh admission**.

Preserve Host UUID `d934cd5e-54d3-4980-8305-3dd77b023e0d`, original Ed25519 public fingerprint `fc9eb1c215a3e5f8a610263ef30072022f76c1e30225aa1a5435aec7389a8ed3`, original registry endpoint, beacon signing/enrollment, archive credentials and destinations. The original private key remains under `/var/lib/host-discover/identity/identity.pem` until an independently authorized migration. No private-key bytes, credentials or access grants are placed in journal, source test evidence or handoff.

Legacy UID/GID mapping: host-discover `991:991`, archive-consumers `990`. Target: host-discover `970:970`, box-control `971:971`, archive-consumers `972`, host-control `973`. Source preflight denies any occupied target ID, unrecognized group/file or registry change. The canonical STATE marker is only `/state/.zog-state.json` schema 2, kind `zog-state-directory`; do not introduce earlier `.zog-state-directory.json` as a parallel identity.

## Implemented source contracts

`state_account_migration.py`: explicit non-resident `migration` bundle selection, matching original Host UUID and public fingerprint, managed control registry, real root XFS/ext4 UUID and PARTUUID observation **as input only**, exact legacy NSS mapping and mode-0600 file metadata, metadata-only plan hash and bounded, same-operation durable journal. It models each account/group/ownership/move/configuration/service step, refuses foreign or reordered transitions and simulates interrupted replay/rollback in isolated fixtures. **Production MigrationJournal remains hard held**.

`state_account_migration_consumer.py`: exact companion revision/interface and receipt schema selection. A bare caller assertion or arbitrary version is not sufficient for admission.

`state_account_migration_native.py`: source-only root-capable account command allowlist, no shell, original-inode-preserving same-filesystem `renameat2(RENAME_NOREPLACE)`, guarded UID/GID file transitions, narrow legacy config rewrite and disabled service drop-in. Actual root filesystem execution is explicitly held by `NATIVE_ACTIVATION_ENABLED=False`; no native production command is available. Test fixtures use real temporary-file ownership operations and synthetic NSS/systemd responders, not host system accounts.

`state_account_migration_observer.py`: NSS `pwd`/`grp` field checks and restricted systemd `host-discover.service` status/operation source. Historical stop/reload stages require retained transaction history; a caller boolean cannot replace the local probe. It remains uninstalled and must undergo native systemd behavior review.

`state_account_migration_storage.py` and the separate private extension to `state_provision.prepare_tree`: canonical configuration/STATE layout can be prepared in `migration` mode **only under a root-owned, opened journal showing the exact active transaction stage**, with matching bundle and backend. Original fresh-install behavior and missing/foreign marker holds remain; this path never initializes a Host key.

`state_account_migration_completion.py`: the root-only **pre-mutation original witness** captures and publishes original directory/key/binding/lock and optional registry-CA inode evidence from an opened legacy identity directory, checking strict ownership, file types, hardlinks, public binding and pinned consumer. It never opens the private key. Same-byte retries are permitted, differing witness publication is denied. A separate **post-migration** issuer requires the protected *complete* journal and exact original file inode evidence before publishing the root-owned mode-0600 `zog-retained-legacy-state-identity-completion-v1` receipt. The retained host-identify loader then opens and verifies the actual key cryptographically, matching original public fingerprint; an inode alone cannot authenticate a key. The source witness helper accepts a caller-opened descriptor: **Work must prove the descriptor really comes from the selected original legacy path, under a root-owned transaction lock, before any mutation**. Do not manufacture baseline inode evidence after moving the key.

`state_account_migration_launcher.py`: a **disabled**, root-only restart bridge checks the canonical STATE context, full protected transaction journal, matching plan and completion receipt, original identity inode and unchanged Host UUID/fingerprint, then describes how two inherited FDs are passed to host-discover running as UID/GID `970:970` with the reviewed `--existing-legacy-migration` mode. It does not transmit key contents in argv, env or journal. The systemd drop-in source has been corrected to contain actual newline-delimited directives. Both `RUNTIME_ENABLED=False` and an unresolved `@PINNED_HOST_INSTALL_PYTHON312@` placeholder prevent production service activation.

## Source verification

- [Registry account migration and pinned companion CI](https://github.com/zog144/host-install/actions/runs/42533246571): **PASS on Python 3.12 and 3.13**. Per interpreter: 165 migration/recovery tests (4 unrelated root-capable tests deselected in this first group), 60 privileged disposable-root/receipt/native-stage/relaunch/witness tests, and 35 pinned companion tests.
- [Root-directory STATE CI](https://github.com/zog144/host-install/actions/runs/42533246589): **PASS**, separately covering disposable root layout.
- Source tests cover same-directory rename preserving key inode, symlinks and hardlinks, foreign public binding, unknown identity files, changed UID/modes, incomplete journal, changed migration IDs, repeated receipt issue, no private material in public records, protected original-witness publication, and rollback/restart source models.
- A deliberately captured regression demonstrates Linux may reuse an inode after unlink+recreate: the negative test retains the original inode when substituting a key. Stronger assurance comes from the **pre-mutation protected witness plus the retained loader's public-key check**, not inode values in isolation.

## Native HOLD / missing final acceptance

1. **Installed source and environment:** Work must inspect and pin the actual Host, its root UUID/PARTUUID, original identity fingerprint, existing registry session, all file/device/account metadata and actual dependency closure. Verify installed wheel RECORD and fixed Python 3.12 paths; no guessed `/usr/bin/python3`. Source CI does not prove installed wheel bytes.
2. **Durable original witness and journal origin:** Before even stopping the service, obtain root-owned exclusive transaction access, independently open the actual original identity at the real legacy path (no symlink/hardlink/nested mount), securely reobserve its binding/public key, publish **original witness and journal before mutation**, and retain them through reboot/retry. A caller-provided `identity_fd` or source `plan` cannot authenticate itself. Actual bridge of this issuer into a live actuator has **not** been enabled or demonstrated.
3. **Root and account actuator:** The source has real command allowlists, protected file staging and NSS/systemd observers, but no approved effective native executor with complete per-syscall idempotence for the real 991→970 / 990→972 conversion, canonical initial `/state` creation, service stop/restart, and robust rollback of changed production NSS/systemd records. Test synthetic NSS proves only models. All actual executor admission switches remain false.
4. **Installed service selection:** Validate the effective original systemd service, drop-ins, `ExecStart`, `ReadWritePaths`, UID/GID, credential access, `/opt/host-discover` interpreter and pinned host-install Python 3.12. The source unit contains an intentional unresolved Python placeholder and must never be installed verbatim. Verify any service sandbox restrictions and host-discover certificate-assignment behavior. The privileged FD launcher remains disabled and is not a production service.
5. **Native recovery/acceptance:** In a separately authorized controlled transaction, verify actual same-Host /state persistence, original key inode/fingerprint, unchanged enrollment/registry endpoint, credential and destination access, fresh beacon response, repeated restart, outage behavior, controlled reboot, recovered interrupted operation and rollback evidence. Retain recovery originals until acceptance. Never re-enroll/regenerate, introduce registrar signatures, alter unrelated cloud resources, or activate protected Task C.

**Disposition:** reviewed migration consumer integration and disposable source tests PASS; original witness and completion contracts are authored and exercised; **native migration, resident protected Task C, broker, and SSM sending remain HOLD**. No real Host was modified from this chat.
