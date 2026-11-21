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
2. **Preserve:** `--preserve <release> --service <reviewed-service> --original-runtime <real-existing-root>`. The real current unit must reference the chosen original runtime path. The installer requires the service inactive, rejects special/linked/foreign/writable files, inventories the **entire original runtime**, copies it independently to `/opt/zog/compiler-runtime/rollback/<release>/previous-runtime`, verifies copied bytes and modes, and preserves the exact previous unit at `/opt/zog/compiler-runtime/rollback/<release>/<service-name>` with a durable custody receipt. The original runtime stays at its original location. A previously created or partial rollback directory fails closed.
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

Separate unresolved preservation HOLD: venv/lib64 -> lib; venv/bin/python -> python3.12; venv/bin/python3.12 -> /usr/bin/python3.12; venv/bin/python3 -> python3.12. The strict full-runtime inventory still rejects these four symlinks. No symlink rewrite, flatten, exemption or Host command is implied. Native reviewer must explicitly resolve this hold before any install.

Evidence requirements for native Work: independent exact selected source tuple, actual staged module/RECORD hashes, complete unit and drop-in bytes, root ownership and modes, systemd 252 effective properties, rollback interruption/reboot and nonroot peer-to-child witness. No Fonts lane activation, service start, SSM or compilation is authorized.

The independently approved composition also includes original_fragment and selected_fragment with exact canonical path, SHA-256, file size, mode, UID and GID. The installer compares the preserved original fragment receipt and staged release fragment with those fields. The host-deploy read-only inspector independently checks the original protected backup, staged file and active fragment metadata on both sides of selection. A mismatch is a HOLD; no implied chmod or chown is permitted.
