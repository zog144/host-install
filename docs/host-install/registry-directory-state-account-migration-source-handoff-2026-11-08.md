# Registry Host → canonical directory STATE: guarded account migration source

**2026-11-08 · host-install Regular · Draft PR #36 · SOURCE TEST ONLY / NATIVE HOLD**

Authoritative native read-only evidence: private [know-file migration handoff](https://github.com/zog144/know-file/blob/01ec0766d495d57a5513274c34b895f0747162d9/host-install/handoffs/host-registry-directory-state-account-migration-2026-11-08.md) and its linked [host-install index](https://github.com/zog144/know-file/blob/01ec0766d495d57a5513274c34b895f0747162d9/host-install/INDEX.md). The actual retained registry Host has **not been modified**.

## Frozen source selection and scope

- Base: host-install [PR #35](https://github.com/zog144/host-install/pull/35) at exact previously source-tested head `dfce38a239957b98c1d433dac94ea9fc4b0918fd`; its Task C v3 installer/source freeze remains separate and unchanged.
- New focused candidate: [host-install PR #36](https://github.com/zog144/host-install/pull/36), `src/zog/host_install/state_account_migration.py`, `tests/test_state_account_migration.py`, `.github/workflows/registry-state-account-migration.yml`.
- **Single canonical marker:** schema-2 `/state/.zog-state.json` with `kind=zog-state-directory`, verified root UUID/PARTUUID, and `backing_root=/`. The unpublished, earlier Work `.zog-state-directory.json` marker is **not** a second accepted authority. Never install both.
- The canonical installed configuration uses `/etc/zog/host-install/{accounts,installation,bootstrap}.json`. A migration bundle must explicitly select `installation.operation=migration`, `bootstrap.mode=migration`, a locally authorized transaction UUID, the existing Host UUID/fingerprint, and the **existing managed registry/control authority**, not silently replace enrollment with `registries=[]`.
- The legacy beacon `server` must equal the canonical control registry `origin` and must not acquire new CA material. Existing custom CA files require explicit separate source reconciliation. Only the `identity_directory` field changes in the legacy host-discover JSON; all other fields, including endpoint and credential path, remain byte-preserved through the narrow rewrite.

## Reviewed legacy → target account and path transition

The read-only native inventory selected the original host-discover account UID/GID `991:991`, supplementary `archive-consumers` GID `990`. The canonical target is host-discover `970:970`, box-control `971:971`, archive-consumers GID `972`, host-control GID `973`. The explicit staged transaction models every UID/GID and group step, plus preservation of supplementary memberships and home/shell changes.

- Identity directory: `/var/lib/host-discover/identity` → `/state/host-discover/identity`; same-filesystem rename must preserve original directory/key inode, public fingerprint, binding, key contents and modes. **Do not read, log, copy, reissue, or regenerate the existing private key** during the migration source review.
- Credentials remain under `/var/lib/host-discover/credentials`. Their files remain consumer-readable after the specific owner/group conversion. The destinations file remains `/var/lib/host-discover/beacon-destinations.json`. No credential/token bytes enter the migration journal or public source evidence.
- Canonical root-directory STATE preparation must happen only after account ownership and canonical configuration are reconciled and root backing is freshly verified. A missing, substituted, nonempty unmarked or nested-mounted `/state` remains a hard hold. Protected Task C ledger/authority mounts are **independent** and not part of this migration.
- The source outlines stopping **only** host-discover, preserving prior active/enabled status, installing a narrow systemd `[Service]` drop-in that resets/replaces `ReadWritePaths` with new identity and retained credential paths, daemon reload, and service restoration. It has not implemented a native systemd actuator.

## Source transaction semantics

`review_source_migration` checks exact canonical schema, existing Host UUID/fingerprint binding and *reported public identity witness*, root XFS/ext4 UUID/PARTUUID topology and absent /state mount, free target numeric IDs, closed legacy file metadata inventory, legacy service source and preserved registry origin. Its output is **source evidence**, not a privileged observation: independently sourced input fields are untrusted until Work reopens them on the selected Host. The source does **not** independently prove the private-key fingerprint from a caller-supplied string.

`MigrationJournal` writes a bounded, root-owned-mode `0700` directory's mode-`0600` intent journal with a durable migration ID and hash of the selected metadata-only plan before each modeled mutation. Per-stage before/after evidence, fsync, same-operation replay, pending-journal reattachment, conflicting-stage refusal, explicit reverse rollback and rollback interruption recovery are covered using a **disposable injected backend**. The tests also verify identity inode preservation via actual file renames in a temporary sandbox, reversible legacy JSON rewrite, and reversible unit drop-in creation.

**Production execution is deliberately denied** by the current constructor (`migration-consumer-hold`). There is no native `usermod`, `groupmod`, `systemctl`, `/state` creation, key mutation, move or filesystem action in PR #36. Passing simulation tests does not imply actual accounts/filesystems or services can be rolled back after a real syscall-level interruption. Native per-command execution adapters, secure on-disk installation publication, actual postcondition probes and kernel-level failure injection still require review.

## Concrete blocking dependency: identity consumer

The current [host-discover daemon](https://github.com/zog144/host-discover/blob/main/src/zog/host_discover/daemon.py) explicitly rejects an identity directory under `/state`. Legacy `host-identify.storage.load_existing_key` also deliberately refuses managed STATE paths. The managed `host-identify.initialization.load_existing_fd` instead requires a receipt from a fresh identity-initialization process; the legacy key cannot be transformed into that receipt by assertion, copied receipts or a regenerated key. Updating only the account, config and writable path would break existing beaconing.

**Consumer task:** [host-discover issue #7](https://github.com/zog144/host-discover/issues/7). Its Regular owner must add an explicitly selected *retained legacy identity migration* verification mode and a protected durable host-install acceptance/consumption contract, with unchanged existing key, Host UUID, fingerprint, control endpoint, signing, credentials, observer/session semantics and separate server approval. No automatic conversion, implicit fallback, new registrar, or key creation. Integrate that exact candidate and negative tests into host-install PR #36 before removing `migration-consumer-hold`.

## Required native acceptance, not yet attempted

1. Pin the exact reviewed host-discover/host-identify consumer source and exact host-install migration, then read back genuine selected retained Host OS/root UUID/PARTUUID, source/target IDs, all paths and every file's metadata, existing public identity binding and verified fingerprint using a reviewed noninitializing service interface.
2. Reconcile any unexpected existing files, symlinks, hardlinks, custom CA, alternate legacy service source or endpoint without allowing implicit conversion. Create and retain a root-protected, same-operation migration journal **before** the first account, service or filesystem mutation.
3. With explicit operator approval and native rollback plan, apply the precise staged account/STATE/key move/config/drop-in transition on the retained Host. Recheck same-key and same-registry identity with the approved consumer after each needed barrier; test interrupted recovery before accepting. Preserve original account/config bytes, identity inode and service enabled/active disposition until acceptance.
4. Verify the final canonical `state-inspect`, new service effective UID/GID/groups and `ReadWritePaths`, credential consumer access, authentic outbound beacons to the existing endpoint, unchanged Host UUID/fingerprint, service restart and controlled reboot persistence. Never create a fresh enrollment to bypass an identity error.
5. Keep Task C protected owner, broker, SSM send fence and associated native activation **disabled**. Ordinary directory-backed STATE on root is not an independent Task C owner-ledger or anchor.

**Disposition: source-only transaction design and disposable rollback tests. Native migration HOLD pending host-discover issue #7 and the missing privileged per-step migration adapter.** Do not treat this document as a live Host migration acceptance or authorization to alter AWS resources.
