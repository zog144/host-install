# Compiler-controller versioned installer — November 21, 2026

**Source-only candidate; not native admission.** This is distinct from the Task C Gateway venv and unit in host-install PR #48. The compiler controller uses the inherited-peer-v2 runtime contract in [host-deploy PR #35](https://github.com/zog144/host-deploy/pull/35). Never substitute the Gateway's unit, repository tuple, or /var/lib/zog-task-c rollback path.

## Exact selected source tuple

- root-control `58b5a94311d771bb1c5f4c3e9c6191b44d6565c9`, clean tracked tree SHA-256 `0ffddcfb39a9cc5295cc67196362e2dcb57301ed70199c502af1203e20c2d097`
- box-control `ad61fa6a4e9c3176149720868cb008e0512dbec9`, clean tracked tree SHA-256 `9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00`
- image-build `ff968a431dd2067e7d0e1f17d6e547f2779f647a`, clean tracked tree SHA-256 `e0aacfb08a8b0ef9b1883080ece7d93673906263bee30caa09a285e7a1466310`

These are **source** hashes, never substitutes for installed wheel/module/RECORD SHA-256 or full installed runtime inventory. The legacy schema-4 Fonts lane remains disabled. The candidate may not run root compilation, use caller-selected UID/GID, or create build-owner/build-worker accounts.

## Versioned source workflow

The distinct source program is `python -m zog.host_install.compiler_controller_versioned_install`. Its root-protected actions are independent:

1. **Stage:** `--stage <32–64-lowercase-hex-release>` plus the exact `--root-control-source`, `--box-control-source`, `--image-build-source`, `--python`, `--service`, `--executable`, and `--unit-template` arguments. The operator must supply the *actually reviewed* compiler unit name, installed entrypoint name and unit-template bytes; the installer does not guess these from the Gateway or historical compiler environment. The template must contain exactly one `ExecStart=/opt/zog/compiler-runtime/versions/<release>/bin/<executable>` and no `[Install]`. The installer verifies exact immutable clean source trees, creates a distinct `/opt/zog/compiler-runtime/versions/<release>/venv`, performs ordinary pip installation of all three sources and their dependencies and `pip check`, rechecks source trees, copies the actual installed entrypoint into the release-owned `bin`, places the reviewed unit under `systemd`, and checks its complete immutable file tree. It does **not** select or activate the service. An interrupted release must not be reused under the same ID.
2. **Preserve:** `--preserve <release> --service <reviewed-service> --original-runtime <real-existing-root>`. The real current unit must reference the chosen original runtime path. The installer requires the service inactive, rejects special/unreviewed-link/foreign/writable files, inventories the **entire original runtime**, copies it independently to `/opt/zog/compiler-runtime/rollback/<release>/previous-runtime`, verifies copied bytes and modes, and preserves the exact previous unit at `/opt/zog/compiler-runtime/rollback/<release>/<service-name>` with a durable custody receipt. The original runtime stays at its original location. A previously created or partial rollback directory fails closed.
3. **Independent review:** From actual staged installed bytes obtain the host-deploy `fonts-runtime-inventory` output, including complete tree and all required modules/RECORDs. Construct the exact canonical inherited-peer-v2 selection at `/var/lib/zog/compiler-runtime/selections/<release>.json`; include independently read original unit/rollback hashes. An independent reviewer must approve that file's **exact SHA-256**. Run `host-deploy fonts-runtime-inspect --phase staged` as a read-only gate. The host-install selector itself invokes that same validated host-deploy source contract before changing any unit.
4. **Select:** `--select --selection <reviewed-file> --expected-selection-sha256 <reviewed-hash>`. The root-owned selector serializes transitions under a protected lock, requires the service inactive and the previously preserved unit equal to the actually selected old unit, runs the host-deploy staged inspector, durably creates a pending transaction, and atomically replaces **only that exact systemd unit file** with the staged version. It reloads systemd, verifies inactivity, and requires the host-deploy **selected** installed-byte inspector before committing `selected`. If a check fails, it restores the original unit without auto-retrying a build. An interrupted pending transaction requires explicit restore.
5. **Restore:** `--restore` with the same independently approved selection file and digest. Check locked transaction identity, retained unit SHA-256, independent old runtime inventory, and current unit against either the selected or original bytes. Atomically reinstall the previous unit, reload systemd, confirm inactivity and retain the old state and transaction as `restored`. Never delete or replay historical operations.

## Do not deploy yet

The selected **compiler-controller service name, original runtime root, actual unit template, installed launcher**, and installed-byte/RECORD values must be independently observed from the compiler Host and reviewed; they are not inferred from a historical Task C gateway. Native Work must verify the real local root-owned installed host-deploy verifier supports the pinned PR #35 inspection contract, the complete package/RECORD closure, root/box/image producer imports, file ownership and absence of mutable links, and native systemd 252 reload/rollback behavior. Test unit selection and recovery after interruption/reboot, preserve original journal and operation records, and separately prove the actual nonroot SO_PEERCRED-bound child UID/GID, cgroup, InvocationID, argv and namespace contract. No Fonts activation, compilation, service start/restart or SSM fallback is authorized here.

The companion GitHub Actions workflow tests clean exact source tuples and disposable source rollback transitions without any AWS or Host operation. A green source workflow is not installed-controller acceptance.


## November 21: observed complete compiler service composition

Service: zog-certbot-seed-root.service. Fragment: /etc/systemd/system/zog-certbot-seed-root.service.
Observed fragment SHA-256: ee3284eb9c317092312bc632ac2eebb68c4c5d36684ad4b5e86c6dd129a2d72d.
Manager-effective ExecStart: /opt/zog/fonts-controller-d9dfd6c0-20261114/venv/bin/python -I -B /opt/zog/fonts-controller-d9dfd6c0-20261114/bootstrap.py.

Four active drop-ins in /etc/systemd/system/zog-certbot-seed-root.service.d/:
- 60-boot-a-restrictive-import.conf: f9152af9b90fd632ca5eeb280c0e592503bf04aabe8d71303b673aa5aac88bce; ExecStart reset, ReadOnlyPaths.
- 70-fonts-combined-runtime.conf: 26902a509f10bc5adcef2a86080ae6925fe02f2b424144735445293af2a9571d; ExecStart reset to old interpreter, ReadOnlyPaths.
- gateway-mounts.conf: 15d00d89d2af03ca5779ae549755afda34bbf41f2d715d4ac2b4f8670b9a6782; Requires/After.
- issuer-persistence.conf: 364366b3b49fca2349cb6aa8c5f6f3ec59d49aa08b6273dc02fd6543ce33c6ef; ExecStartPre and ReadOnlyPaths.

Both fragments and all active drop-ins are now preserved as bytes plus owner, group, mode, size and SHA-256, with the manager's loaded properties retained. The successor must explicitly stage a reviewed drop-in directory; its entire sorted set and approved effective properties are bound to host-deploy PR #35's selection. Do not silently reuse or drop original mount dependencies, issuer guards, or read-only paths. No actual successor drop-in bytes have been fabricated by this source change.

The compiler service was ACTIVE during the original observation: no staging, preservation, or selection against that running Host is authorized. Selection requires an approved inactive maintenance window, a protected pending transaction, persistent service mask, successful daemon-reload and LoadState=masked before changing the drop-in set, a reviewed final fragment plus drop-ins, readback of effective loaded properties, and durable explicit restore/recovery. The Task C Gateway remains a different service.

Historical HOLD (superseded by the later legacy-inventory correction below): the original four virtualenv symlinks previously failed the generic strict inventory. The new legacy-only inventory admits exactly these literal links; native external interpreter attestation and approved inactive maintenance remain outstanding.

Evidence requirements for native Work: independent exact selected source tuple, actual staged module/RECORD hashes, complete unit and drop-in bytes, root ownership and modes, systemd 252 effective properties, rollback interruption/reboot and nonroot peer-to-child witness. No Fonts lane activation, service start, SSM or compilation is authorized.

The independently approved composition also includes original_fragment and selected_fragment with exact canonical path, SHA-256, file size, mode, UID and GID. The installer compares the preserved original fragment receipt and staged release fragment with those fields. The host-deploy read-only inspector independently checks the original protected backup, staged file and active fragment metadata on both sides of selection. A mismatch is a HOLD; no implied chmod or chown is permitted.


## November 21 — reviewed legacy virtualenv symlink preservation

The *original* compiler runtime remains /opt/zog/fonts-controller-d9dfd6c0-20261114; this is not the new immutable selected release. A distinct `zog-compiler-legacy-rollback-inventory-v1` inventories its complete original and copied trees, including ordinary symlinks as **literal link objects**, without dereferencing or flattening. The only permitted symlink objects (relative to the original runtime root) are `venv/lib64 -> lib`, `venv/bin/python -> python3.12`, `venv/bin/python3 -> python3.12`, and `venv/bin/python3.12 -> /usr/bin/python3.12`. An additional symlink, changed literal target, escaping relative target, cycle, multiply linked regular file, special file, foreign owner or mutable ordinary file fails closed.

The inventory freezes canonical path/type/mode, file byte-size and SHA-256, symlink literal target and owner/group, a separate whole-tree digest, and the `/usr/bin/python3.12` interpreter target chain (each link's literal target, and the final regular executable's exact bytes, mode, owner/group, size and SHA-256). The separately attested external chain must remain available and byte-identical during later inspection/restore; a changed target or chain is HOLD. This external interpreter is *not* silently copied or modified. The original runtime and independently copied rollback tree must have identical literal-link inventories. The protected receipt and host-deploy's externally reviewed selection pin schema, tree digest, complete inventory digest, original runtime path and external interpreter chain. Explicit restore verifies the original and copy again and reinstalls the previously saved unit/complete drop-ins, leaving the original runtime path untouched.

This correction does **not** change `_inventory` for new staged software or host-deploy's `_retained_tree_sha256` for selected immutable software: those reject *all* symlinks. The legacy exception is deliberately limited to separate rollback custody and does not permit a symlink in the selected controller. Focused CI covers four successful copies, malicious/escaping links, changed targets, hardlink detection, cycles, interpreter-chain changes and strict selected-tree denial.

### Native acceptance HOLD remains

The existing compiler service was active during inspection. No stopping, reinstalling, selecting, restoring, or reboot testing is approved without an inactive maintenance window. Work must read the actual `/usr/bin/python3.12` byte hash and complete symlink ancestry/target chain independently and approve the final real installed inventory and selection digest; source CI contains disposable fixture hashes, not live installed hashes. Preserve all prior operations and their uncertainty, original systemd fragment and four drop-ins, actual runtime, and complete protected rollback. Successful symlink treatment addresses only the prior inventory blocker: systemd 252 drop-in selection, recovery, RECORD attestation, nonroot peer-to-child evidence and Fonts authorization are separate gates.


## November 21 — new selected runtime: link-free Python 3.12 staging

The selected immutable runtime remains strictly no-symlink. On the NEW release only, staging invokes `/usr/bin/python3.12 -m venv --copies` and inspects fresh venv-generated links before pip installation. Only `bin/python`, `bin/python3`, `bin/python3.12`, and `lib64 -> lib` patterns are recognized. Interpreter links are replaced with real executable copies of already present in-venv interpreter files; the redundant lib64 alias is removed only when lib is a real directory. Foreign, escaping, absolute or unexpected new links HOLD.

The original runtime and its four approved legacy virtualenv symlinks remain untouched. The selected runtime still undergoes its existing strict `_inventory` after real pip installation; dependency-created links are rejected, not normalized.

The pinned box-control installable project is under the checkout's nested `box-control/` directory, not its repository root. Staging now installs the exact root-control, nested box-control, and image-build source projects, runs pip check, and imports `zog.root_control`, `zog.box_control`, `zog.image_build` and `zog.image_build.remote_operations` with isolated Python.

The dedicated CI job `amazon-linux-2023-real-runtime` uses the Amazon Linux 2023 container and `/usr/bin/python3.12`; it runs real venv creation, actual dependency installation, import checks, and strict full-runtime inventory, then discards the candidate. This job does not touch the live Host or its service.

Native Work selection and restore are separately gated on the approved inactive maintenance window and independent installed-RECORD, effective fragment/drop-in, persistent mask/reboot and non-root child verification. No Fonts activation or build is authorized by this source change.

The first real AL2023 run established that normal pip wheel building writes generated metadata into the input checkout. The installer now snapshots each independently verified clean Git HEAD into a disposable tracked-source archive and installs from those temporary copies, then verifies the original source checkouts again. This retains strict clean-tree checks without deleting or ignoring generated files, and does not change the selected package or source revisions. The earlier failed CI operation is retained as diagnostic evidence.


## November 22 — normalized systemd 252 command identity integration

Host-deploy PR #35 reviewed source head `1db5ec50989fcd345bfef6bba8f20efab6cb83cb` defines the required stable-command contract. Live systemd 252 `ExecStart` and `ExecStartPre` properties include transient PID/start/stop/code/status fields; those **must not** be included in the approved immutable selection or compared after reboot.

The host-install installer now calls `zog.host_deploy.fonts_unit_composition.normalize_loaded_commands(raw_five_properties)` when reading the manager's exact loaded fragment, drop-ins and five effective properties. It saves the returned stable typed `ExecStart` and ordered `ExecStartPre` argv/path/flags in the protected receipt's `original_loaded_properties`; transient observations are retained only as `original_loaded_process_metadata` for auditing. The stable configuration is compared against the independently approved `composition.original_effective` at selection and restoration. The previous regex matching a single raw `argv[]` field has been removed; preservation now calls `verify_composed` against the original fragment and all lexically ordered original drop-ins, checking both command lists and reset/flags semantics. The retained original runtime must still occur as a whole path component in the actual original command's argv.

After reload, the host-deploy read-only inspector's `verify_loaded` compares normalized stable command identities and other manager properties. It rejects unknown command fields or changes in executable, argv, prestart commands or flags; volatile process observations are separately returned, not pinned. The installer rejects old raw-string receipts instead of silently converting them. The selected successor's stable typed command configuration must still come from independently reviewed real staging evidence, never guessed from old PID/timestamps.

The CI workflow checks host-install against exact host-deploy source head `1db5ec50989fcd345bfef6bba8f20efab6cb83cb` on Python 3.12 and 3.13, including mocked systemd 252 changing PID/timestamp acceptance and changed main/prestart argv/ignore_errors rejection. The Amazon Linux 2023 real Python 3.12 staging job remains distinct. No live service, SSM, compilation or original journal is modified by this source correction. The native maintenance-window gate and independent review remain in effect.


## November 22 — reboot-persistent startup protection for multi-file selection

**Independent review finding resolved in source:** the earlier temporary mask replaced the active main fragment but was then removed before the selected and restored transactions were independently verified and durably committed. A reboot in that interval could start a partially changed service. The corrected transaction uses two protections: the prior temporary /dev/null fragment mask while physically replacing drop-ins and the fragment, AND a separate, permanent-on-disk service drop-in named `zzzz-zog-compiler-transaction-guard.conf`. It contains a root-owned, mode-0644 `[Unit] ConditionPathExists=/opt/zog/compiler-runtime/rollback/<release>/startup-permit`. The installer **never creates** this permit and rejects a present or symlinked permit. Consequently, after the temporary mask is replaced by the final fragment, a reboot still cannot start the service while this guard is present. Before switching any files, the installer loads and confirms the guarded inactive service via systemd, then masks the main fragment; the guard remains installed throughout replacement.

For **selection**, the durable pending record comes first, then the independent guard is installed and manager-loaded. The fragment and ordered drop-ins are replaced under the temporary mask while leaving the guard file unchanged. After reloading the selected fragment, host-deploy's read-only `inspect_installed(..., phase="selected", transaction_guard=True)` verifies the exact protected guard, absence of startup permit, all original and selected byte inventories, and the manager's effective full command and drop-in set including the guard. Only after this passes is `selected` fsynced to the transaction. The guard is then removed and systemd reloaded; the ordinary unguarded selected inspection is repeated. A crash after the commit but before guard cleanup causes temporary unavailability, not an unauthorized start. A crash before commit leaves the persistent guard present.

For **restoration**, the installer durably records `restoring` before changing the unit or drop-ins, installs/validates the persistent guard, and uses the temporary mask during multi-file recovery. The original fragment and complete original drop-ins are restored, and the manager-loaded original effective properties are checked **while the persistent guard is still active**. Only then is `restored` fsynced, after which the guard is removed and the final unguarded state checked. A reboot after a restored commit but before guard removal can be reconciled by an explicit repeat restore. Unknown transitional files, changed original runtime, wrong original fragment/commands, unexpected permit, or mismatched guard continue to fail closed.

The protected original runtime and all historical operation records remain unchanged. New tests simulate process death between unmask and selected inspection, during restore after the original fragment reappears, and after the restored durable commit before guard cleanup. They also reject unexpected startup permit files. The host-deploy PR #35 guarded inspector now checks the exact deny-by-default guard bytes, mode, and loaded DropInPaths, without weakening the normal strict unguarded inspector.

**Native acceptance remains separate.** Source CI does not prove systemd 252 condition semantics on the actual compiler Host. Work must independently verify `ConditionPathExists` blocks starts across a real reboot during `pending` and `restoring`, normal selected and restored stable command identity, full unit/drop-in bytes, protected rollback state and journal. Do not activate the Fonts lane or start a compilation. Use only the separately authorized inactive maintenance window.


### Startup guard lexical-order and restore precommit requirements

The permanent guard name is `zzzz-zog-compiler-transaction-guard.conf` and must sort **after every other original or successor drop-in**. A later file could clear systemd's accumulated `ConditionPathExists` conditions, so both the installer and the independent host-deploy inspector reject any file ordered after the guard. All original and successor drop-ins remain pinned by their exact reviewed inventories; the guard is the only temporary, explicitly verified addition.

During restoration, the persistent guard must be installed, fsynced, loaded, and confirmed while the previously selected service is still complete, **before** changing the durable transaction state to `restoring`. The prior selected state is safe if interruption occurs before that transition. After `restoring` is durable, the complete original composition is restored under the fragment mask and persistent guard, verified, and only then marked `restored`. New source fault injection simulates reboot before the restoring commit, between unmask and verification, and between restored commit and guard removal. The old runtime and operation evidence are never rewritten.


## November 22 — pre-guard interruption correction

An additional independent review found a crash window **before** the persistent startup guard was installed: the old implementation durably recorded `pending` first, so reboot could start the unchanged original boot-triggered service while the transaction incorrectly claimed a startup-protected pending selection.

The corrected sequence now durably records an explicit `arming` state before writing the guard. This state means **the original fragment and drop-ins are still unchanged and may run normally after reboot**; it must not be treated as a startup-protected pending operation. The installer writes and fsyncs the deny-by-default `zzzz-zog-compiler-transaction-guard.conf`, reloads systemd, confirms the unit remains inactive and the guard is manager-loaded, and only then atomically/fsyncs `state=pending`. Subsequent masked replacement, guarded selected inspection and selected durable commit are unchanged. No operation is submitted during `arming`.

An interrupted `arming` state has a separate **explicit abort recovery** path through `--restore`. It verifies the unchanged original fragment, complete original drop-in set, retained runtime/rollback custody, selected identity and external interpreter evidence. If no guard was written, recovery may record `aborted` without demanding inactivity of an original service which booted unchanged. If a guard exists, recovery requires service inactivity, confirms the exact guard and loaded manager composition, safely removes it, then durably records `aborted`. A present guard with an active service is a HOLD; do not force-stop it. The original runtime, historical operations and existing journal are never altered. An aborted selection is not automatically replayed; reattempt requires deliberate reconciliation and a new selection decision.

Fault injection now covers both crashes (before creating the guard and after creating/loading it but before committing `pending`) and verifies their recovery paths. The existing tests of crashes after the temporary main fragment mask has been replaced and during restoration remain in place. Native acceptance must check systemd 252 behavior across these exact boundaries under an approved inactive maintenance window; source tests are not live boot proof.


## November 22 — refreshed immutable runtime candidate (source-only)

**New distinct candidate ID:** `be8d28824d3e3880f901b4c9c58af3ab`. This is derived from the exact four source-verifier revisions and is **not** the existing staged release or a selected Host generation. The read-only root-control peer-caller correction is in root-control PR #55 at `fd23fb464ebd73e7dce867b2e061dc1467f18d95` (complete clean tracked-byte inventory SHA-256 `e3a7d0fc002a43417cfc5394894d2e1e15774b55fc3d1a18ca48d7ef655cb2d1`). In particular, `authenticated_build_peer((0,0))` is now valid; partial-zero peers and caller-supplied identity overrides remain invalid. This does not create new accounts or change systemd's isolation restrictions.

The other exact companions remain:
- box-control PR #21: `ad61fa6a4e9c3176149720868cb008e0512dbec9`, pinned inventory `9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00`;
- image-build producer: `ff968a431dd2067e7d0e1f17d6e547f2779f647a`, pinned inventory `e0aacfb08a8b0ef9b1883080ece7d93673906263bee30caa09a285e7a1466310`;
- host-deploy PR #35 guarded installed-byte verifier: `8a00b0f9b55416aca11aea6a4940236690f4ab9f`.

The AL2023 acceptance job builds all three real source packages into an isolated Python 3.12 virtual environment with actual pip installation and imports, checks the authenticated root peer API in the installed interpreter, runs `pip check`, and enforces the existing no-symlink full runtime inventory. It now exports the new runtime as an **unapproved, disposable GitHub Actions artifact**, with `candidate-manifest.json` recording all exact source revisions/inventories, the actual release runtime tree hash, archive SHA-256 and size. The CI-built archive includes a **test-only unit fixture**, not a reviewed real `zog-certbot-seed-root.service` fragment and complete successor drop-ins. Never select this fixture onto the compiler Host. Work must author/review the exact real unit/drop-in composition separately and produce an independently attested Host-installed manifest/RECORD before any native selection.

All earlier staged releases, protected rollback copies, original live service and historical operations remain unchanged; this source-only candidate creates a *distinct* release ID and CI artifact without modifying the actual Host. The protected select/restore/arming/pending/guard interruption regressions remain mandatory. This candidate is not a production approval and does not authorize compilation, job replay, or Fonts activation.


## November 22 — joint PR55/PR35 pin and single matching candidate

**Supersedes the earlier source-built candidate:** `be8d28824d3e3880f901b4c9c58af3ab` remains unchanged as historical CI evidence. The **new matching, separately numbered candidate** is `3aa6ab5e221a81b3fd7962ec8d91faf9`. Neither ID authorizes native installation; this only produces a disposable release and independently verifiable hash manifest.

**Both repositories must agree on the exact root-control pin:**
- root-control PR #55: `a672f007b33f83bf70970e3a571fd443366bd93f`; clean tracked-byte SHA-256 `c9475afdc6545adc963203f1ef00f77bd5aa542e2bf6337f660a5b64d0800989`.
- box-control: `ad61fa6a4e9c3176149720868cb008e0512dbec9`; clean tracked-byte SHA-256 `9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00`.
- image-build: `ff968a431dd2067e7d0e1f17d6e547f2779f647a`; clean tracked-byte SHA-256 `e0aacfb08a8b0ef9b1883080ece7d93673906263bee30caa09a285e7a1466310`.
- host-deploy PR #35 exact matched verifier: `caa87434cf3c0556084d62642d66b47a348e26a9`.

The source-only workflow checks the three clean source checkout inventories, pins the verifier checkout by exact SHA, and additionally imports host-deploy's `SELECTED_SOURCES` from the **actual pinned verifier checkout** to compare every SHA and inventory with the installer `SOURCES`. Amazon Linux 2023's real Python 3.12 runtime-build test independently repeats the comparison against the same checked-out verifier, then builds/pip-installs the three packages, checks imports, `authenticated_build_peer((0,0))`, `pip check`, and the strict link-free installed runtime inventory. The artifact includes the new release runtime and an inventory manifest recording all four revisions, the runtime-tree SHA-256 and the archive SHA-256.

This archive still has a disposable **test-only service unit**. It is not a reviewed real compiler-controller unit/drop-in composition or a native installation receipt. A separate verified selected manifest/RECORD and systemd 252 maintenance-window acceptance are still required. The existing staged release and rollback copy, prior CI candidate, existing service and all historical operations must remain preserved.


## November 22 — systemd dependency ordering correction after native HOLD

Native attempt `48ab8b03-2558-4947-84d6-becdcebe8cc8` encountered an installer-only false rejection: the protected rollback receipt and systemd 252 loaded composition had equivalent `After` and `Requires` member lists in different enumeration orders. The complete original unit/drop-in byte, mode, ownership and SHA-256 inventories matched. Host-deploy PR #35's read-only verifier already accepted the equivalent lists, but host-install `select()` and `restore()` still compared the entire typed stable manager dictionary using raw equality.

The installer now uses the same **order-insensitive, multiplicity-preserving** `sorted(value.split())` comparison for **only** `Requires` and `After`. The `ExecStart`, ordered `ExecStartPre`, `ReadOnlyPaths` and all other selected manager properties remain exact; missing/added/duplicated dependency members fail closed. The comparison requires the exact reviewed property-key set and refuses malformed property types. It is used for both the original preservation comparison during selection and the separately checked protected receipt comparison during restoration. Neither protected rollback receipt nor approved manifest is normalized, rewritten or republished; their literal content and historical digests remain authoritative.

Source regression tests exercise reordered `After` and `Requires` passing without mutating either input, and altered command argv, prestart argv, mount restrictions, missing/extra/duplicate dependency names and malformed properties failing. The original legacy symlink custody, source tuple, immutable selected-runtime inventory, and guarded crash/reboot transaction checks remain unchanged. The native attempt ID is **diagnostic evidence only**: do not replay or alter it. Work must install/attest this reviewed successor and retry only through a separately authorized controlled inactive-window selection/restore procedure.


## November 22 — issuer persistence replacement-unit SHA admission (source contract)

The native compiler replacement was rejected by an **independent issuer-persistence `ExecStartPre` check** because that check still compared the active replacement unit's SHA-256 to the **original** issuer baseline digest. The original digest remains the correct protected rollback identity, but it is not the correct expected digest for a separately approved, selected replacement. Native restoration succeeded: retain the original controller/runtime, its protected rollback bytes and records, and the disposable launch fixture without replay.

Host-install now defines `zog-compiler-issuer-replacement-unit-binding-v1` in `compiler_issuer_persistence_binding.py`. For the actual `zog-certbot-seed-root.service` only, selection and restoration compare all of the following *without rewriting the approved selection or old preservation receipt*:

- A caller-supplied expected 64-hex digest of the **independently approved selection**, checked through the existing host-deploy `load_reviewed_selection` gate; this is not derived from an unreviewed local unit.
- The approved **replacement** `service.staged_sha256` equals `composition.selected_fragment.sha256` and is measured over the actual staged unit bytes by existing installer and verifier checks.
- The original **rollback baseline** `rollback.unit_sha256` equals `composition.original_fragment.sha256`, the immutable `preservation.json.unit_sha256`, and the original fragment receipt; its original drop-in inventory and old runtime remain unchanged.
- The original and successor `issuer-persistence.conf` have **identical literal bytes, mode, root owner and SHA-256**. Its nonempty `ExecStartPre` and `ReadOnlyPaths` checks remain in effect. The stable effective `ExecStartPre` list is identical; issuer storage read-only paths and previously required/ordered backing-mount dependencies remain present in the selected effective configuration. Exact full fragment/drop-in metadata, manager property checks, and independent denial of foreign overlays are still handled by the original host-deploy verifier.
- A separate binding record is saved in the **new** `selection-transaction.json.issuer_replacement_binding` (along with the transaction's existing reviewed selection digest, old/new unit hashes, and state). The original preservation receipt and protected rollback tree are **never modified**. Explicit recovery recomputes this record from the reviewed selection and protected files before any transition. The record flags `issuer_native_storage_rechecked=false` and `startup_authorized=false`; its presence does not itself grant service startup.

**Issuer persistence owner matching source change — still required.** The installed `ExecStartPre` issuer guard must independently read/attest the approved manifest, original baseline, protected transaction binding and actual main-unit bytes, and accept the replacement digest **only when** the approved selected transaction is durably `selected`. For the unchanged original unit, it must continue to accept **only** the original issuer baseline in the preselection/aborted/restored context. Pending or restoring transactions must remain denied by the persistent startup guard. A crash while `arming` may leave the unmodified original service bootable, as previously accepted. Never accept an arbitrary supplied digest or relax path/ownership/selected-approval checks.

The issuer owner's existing native checks of certificate-data/STATE UUID, mount backing identity, storage ownership/DAC, protected issuer grant, read-only state paths, required mounted filesystem and all source/installed-byte pins are **additional independent requirements**. The new digest binding does **not** replace any of them. The exact installed issuer guard source, its deployed path, and its read-only access to the approved selection/transaction must be independently reviewed and installed; host-install's source-only adapter cannot change the already installed guard implementation.

Source tests cover a legitimate distinct replacement hash with unchanged old baseline, immutable inputs, mismatch between selected and reviewed SHA, changed original custody, altered guard bytes/owner/permissions, changed prestart commands, removed read-only issuer paths and backing-mount dependencies, incorrect approval hash and recovery-time changed binding. CI is disposable, not native systemd 252 acceptance. Preserve the fixture for an independently approved inactive-window retry **after** both revisions are reviewed. Do not replay historical Fonts operations, edit their receipts, bypass issuer persistence or issue a direct SSM/systemd launch.


## November 23 — helper provenance, selected-only digest and verifier refresh

The native read-only systemd 252 inspection identified the existing issuer prestart command as
`/usr/bin/python3.12 /opt/zog/host-install-issuer-persistence-20261023/guard.py verify`
on `zog-certbot-seed-root.service`. The observed **helper** is root-owned `0:0`, mode `0444`,
SHA-256 `990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78`.
The observed Python interpreter has SHA-256
`f4a74be62ff195cd0c79fba74172d3faa5e92976a37c8125b535869afa9f5fc0`.
The installed `issuer-persistence.conf` is root-owned, mode `0644`, SHA-256
`364366b3b49fca2349cb6aa8c5f6f3ec59d49aa08b6273dc02fd6543ce33c6ef`.
The helper and drop-in are not RPM-owned; the interpreter is an RPM-owned AL2023 Python 3.12.
These are **observations, not source provenance or a reviewed deployment pin**.
The retained October 23 source record does not match the current installed helper SHA.
Do **not** reconstruct or overwrite this helper from its name, digest, or argv alone.
Before packaging an accepted replacement, Work must provide exact nonsecret helper bytes
and source/installation provenance, independently reconcile the older source record,
then review any source-level change of the real storage/STATE/issuer-grant checks.

Host-install's source-only `compiler_issuer_persistence_binding.verify_selected_replacement_digest`
now defines the *additional* replacement digest predicate needed by the eventual
reviewed prestart helper. It checks the approved selection/rollback binding already
created by `select()` against the protected transaction, verifies the **exact raw\napproved selection bytes** against the expected SHA-256 (rejecting duplicate JSON\nkeys and a parsed-object mismatch), and requires **durable
`state=selected`**, the original old-unit SHA, selected new-unit SHA, exact
old/selected drop-in records and the actual active unit bytes. It denies
`arming`, `pending`, `restoring`, `restored`, `aborted`, forged approval,
altered original custody, changed mounted-path restrictions and an unexpected
active unit. Its output explicitly retains `startup_authorized=false` and
`issuer_native_storage_rechecked=false`: merely passing this predicate
**must never** bypass the existing issuer-private STATE, backing-mount,
grant/ID, owner/DAC, read-only-path and prestart checks. This function is not
wired into the installed `guard.py`, and no helper has been replaced.

Host-install now pins host-deploy PR #35 exact verifier commit
`5b199ca39b04906423dea31c6d8f64443a0bf3ab` in both source
regressions and real AL2023 acceptance, replacing `df3e2cca…`. This verifier
independently requires the issuer prestart source/drop-in meaning to remain
unweakened and separately disclaims native issuer storage verification.
A **distinct disposable AL2023 source candidate**
`e7b0d8394f25466c9c2d43b519fa68e0` is built against the new verifier.
It contains a CI-only unit fixture, not an approved installed issuer helper
or real selected compiler unit. The prior candidate `16ccd90f…`, original
Host unit/runtime, issuer storage, rollback receipts, protected operation and
retained fixture remain unchanged.

**Native HOLD:** No production helper deployment should occur until its
actual installed bytes are obtained and matched to independently reviewed
source, and the reviewed *new* helper explicitly preserves all original
storage/mount/grant validations while consuming the protected selected-only
digest. Subsequent guard and helper replacement must be a separate
recoverable, inactive-window transaction with independent installed-byte,
source/RECORD, crash/reboot and rollback acceptance. Do not use the digest
predicate as an alternate service launch path or SSM bypass.
