# Root-directory STATE runtime — source integration candidate

2026-11-07. Regular implementation branch `regular/state-directory-runtime-integration-20261107`, based on host-install PR #34. **Draft, not approved for host-registry installation.**

## Provenance and limitation

Host-install Work reported an unpublished separate branch implementing `state-directory-prepare`, `state-directory-inspect`, and a marker tying `/state` to installation/STATE IDs and filesystem backing. At the start of this work its branch and source files **were not present** among GitHub branches/commits accessible to Regular. This branch is an independent opt-in runtime integration candidate, **not** a claim that those unpublished Work marker bytes have been imported or reviewed. Reconcile the exact marker format, ownership, source heads and digest algorithm with Work's branch before selecting any installation.

## Implemented source path

- `state_contract.validate`: unchanged strict schema-1 `zog-state-volume` default; explicit schema-2 `zog-state-directory` marker selects `storage_backend=root-directory` for a non-resident installation only. It binds configured installation/STATE IDs, filesystem UUID and PARTUUID, account profile and exact backing root `/`. The marker and installer_recorded marker digests as well as the bootstrap installation-record SHA are bound; an upgrade cannot switch backends without a separately reviewed migration.
- `state_inspect.load_configuration`: reconstructs and validates the correct canonical marker from the installed configuration, without accepting a caller-supplied marker as live authority.
- `state_inspect.assess_root_directory` and `_mount`: require an actual writable ext4/xfs root partition, unique matching UUID/PARTUUID and mount major/minor, and **no** `/state` mount or nested mount. `VerifiedState.recheck` still checks the retained directory descriptor and live backing before and after reads.
- `state_provision.prepare_directory_live`: uses the exact opt-in backend, caller's explicit matching STATE ID, and original durable preparation/marker/layout lock and publication path. Any nonempty unmarked directory or conflicting marker is rejected; it does not generate IDs, initialize a block device, mount, or touch any IAM/S3 scope. Legacy `state-prepare` remains restricted to volume-backed STATE.
- `cli.py`: `state-directory-prepare --state-volume-id <exact UUID>` and read-only `state-directory-inspect` use the canonical loader/inspection paths. Both require a separately selected signed configuration; neither silently converts existing ext4-volume configuration to directory-backend configuration.

## Tests and evidence

`tests/test_state_directory_runtime.py` covers unchanged volume marker validation, explicit directory schema, wrong root/device/UUID/PARTUUID, read-only/overlay/nested mounts, marker and installation-digest substitution, and disposable root-capable preparation, idempotency, nonempty unmarked directories and conflicting markers. GitHub Actions `state-directory-runtime.yml` runs Python 3.12/3.13, normal pure tests plus `sudo` root-owned disposable filesystem regression runs; no retained Host paths are touched.

## Native acceptance still required

1. Recover and inspect **Work's original unpublished directory-backend source** and compare its marker schema/byte canonicalization and exact authority boundaries against this independent candidate. Reconcile any drift in one reviewed source head; do not claim the modules were merged until this is done.
2. On the actual selected host-registry EC2 instance, authenticate AWS IID/account/region, original registered UUID/fingerprint, installation ID and existing/recovery STATE ID; inspect root partition UUID/PARTUUID, filesystem type, mountinfo and root/STATE directory inode identities. **Do not** create /state on that Host as a side effect of assessment.
3. Independently approve whether a directory on the **same root filesystem** is acceptable for host-discover identity/control STATE. It has **no independent EBS failure/rollback domain** and is not a substitute for the **two separately mounted independent Task C owner ledger and anchor** volumes. Persist the selected backend and its durability/recovery limitations in a signed installation selection; keep all graphical owner/broker and SSM gates held.
4. Provision an empty root-owned /state directory with explicit installation approval if missing; this source command requires the directory to already exist. Check no symlinks, populated unmarked tree, unexpected nested mounts, or conflicts; only then execute the prepared layout transaction on an authorized disposable or controlled native install.
5. Run actual root-capable `state-directory-prepare`, `state-directory-inspect`, `state-inspect`, `state-probe`, preparation/identity admission and recovery after reboot, with exact signed registry mapping and original key custody. Confirm host-discover/host-identify load-existing and offline/recovery behavior. Test invalid filesystem replacement, missing marker and nonempty unmarked refusal without damaging retained STATE.
6. Only after accepted native evidence should Work consider enabling ordinary host-discover operations. No trust-broker/Task C authority is activated or implicitly admitted by directory-backed /state.

**Status:** source candidate only; no runtime installation, STATE filesystem creation, new Host identity, mount, S3 checkpoint, certificate or SSM operation performed.
