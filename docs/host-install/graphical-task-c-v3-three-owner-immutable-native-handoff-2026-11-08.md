# Task C v3 — immutable three-owner disabled installation source freeze

**2026-11-08 · source freeze only · NATIVE HOLD**

Candidate: host-install [PR #35](https://github.com/zog144/host-install/pull/35), inclusive of host-install [PR #34](https://github.com/zog144/host-install/pull/34). The selected v3 installer is in `src/zog/host_install/graphical_task_c_v3_install_freeze.py`. This file defines a **disabled source selection**; it is not an install command, positive native acceptance, or runtime grant. The root-control and host-deploy PRs remain draft and are not promoted to production.

## Exact source/repository selection

| Owner | Immutable source revision | Selection |
|---|---|---|
| root-control [PR #47](https://github.com/zog144/root-control/pull/47) | `935e2764c227b0d8036015d9d11e7419b3afd5e0` | v3 trust authority, installation scope/commit/checkpoint, live backend observation, protected owner |
| host-deploy [PR #30](https://github.com/zog144/host-deploy/pull/30) | `95ff98327ed9730774fdaa5d6f588ac8c63b8ad6` | v3 trust/history/gateway observer, daemon, disabled broker selection |
| host-install [PR #35](https://github.com/zog144/host-install/pull/35) | `aaccfdb2852532a9667682938937afe768dbc821` | **STATE source snapshot** with registrar-free standalone configuration and corrected live protected mount readback; all selected `STATE_SOURCES` have the same bytes at this revision and the final PR head |
| host-install PR #35 | `979026069cec8d5d19fd9cc1c8a9a66050b1ea0e` | **Three-owner freeze + tests + workflows source checkpoint** before this handoff document; subsequent documentation-only commit does not change selected Python or unit bytes |

The selected immutable whole-file group hashes, `sha256:` prefixed, are:

| Group | SHA-256 |
|---|---|
| Nine selected root-control v3 Python modules | `4a6e51c6244c2d6a3fc243f1200b76193e5b6436dfdd0ba165cfe6a4e430c861` |
| Five selected host-deploy broker Python modules | `a15bd2212e17f5906636b33c51b8875a467038aede07467ae9b542c64e594080` |
| Five selected host-install STATE/mount admission Python modules | `42b3f048a859efd6ba8b582b5986dff18382fbe42abcd159e40ab7206359c15b` |
| Installed candidate owner service unit | `c6dc325892e0b9371834dda94213e1854336d6e5c6ed8ebe5058e60f4b244ed5` |
| Installed candidate owner socket unit | `873e67a61be9ed329a0e5aa07f94c46cf3cfb7c793c3d4239580501564f327e3` |
| Installed candidate broker service unit | `217e4213166a2f0268b3b0d7128a03ec59d56a74f1870cacc6203efbc4184c31` |
| Installed candidate broker socket unit | `56bbdba9af32c85fc157da654af4f6b7916896930893d506217de400c0e2c84d` |

The group-hash format is `SHA256(name || NUL || source_bytes || NUL)` in sorted module-name order. Exact module sets are checked against root-control's `ROOT_V3_SOURCES`, host-deploy's `SOURCES` and host-install's `STATE_SOURCES` at source review. The **host-install** disabled broker service in `src/zog/host_install/systemd` is the selected unit, not host-deploy's `deploy/graphical-trust-broker` source template, whose `ExecStart` and runtime Python path differ. The template remains source-only; never install both.

## Actual uninstalled wheel RECORD evidence

[Final preceding three-owner CI run #42494609295](https://github.com/zog144/host-install/actions/runs/42494609295) built component wheels separately on Python 3.12 and 3.13, using exact pinned Git checkouts, and verified all selected modules inside each wheel against the actual source bytes and its own PEP 427 `*.dist-info/RECORD`. The **RECORD** SHA-256 was identical across both lanes:

| Wheel distribution | PEP 427 RECORD SHA-256 (raw hex) |
|---|---|
| `root-control` | `3951f166a6ada045a80ee303aa9613b511356c61354344de2ec077e5af1b55fb` |
| `host-deploy` | `e30a644eca1c2e7b3c9b95ec6fb4919daa9d8cd13ac56e9c99596a255b7b7d1c` |
| `host-install` | `eb17e12ce0f7944ac9bf99e3de70340571ca9e050dc513e550f65115cfceeb89` |

Whole-wheel ZIP hashes **differ between the two runner builds** (wheel archive metadata), so do not treat them as a reproducible or accepted native wheel pin. In the actual installed environment, Work must select exact wheel files, pin their individually captured file digests, verify installed `RECORD` contents/hashes **against all installed files** and ensure each selected module's installed byte digest matches the above group selection. This source run does not prove an installed Python environment or distro-specific dependencies.

## Source CI result

[Exact three-owner freeze #42494609295](https://github.com/zog144/host-install/actions/runs/42494609295): **136 source tests PASS + 1 fresh wheel verification PASS per Python 3.12 and 3.13 lane**; one wheel-only test is deliberately skipped during the pre-wheel pass and then explicitly run after wheel builds.

Tests include: local registrar-free versus legacy signed registry identity, XFS/ext4 root-directory versus mounted-volume STATE, source/module substitution, cross-backend downgrade, synthetic tampered marker and inode, operator approval/retained signed installer commit substitution, distinct reader/writer/SSM roles, exact service and socket bytes, required `RequiresMountsFor` in systemd `[Unit]` rather than `[Service]`, broker prohibition on owner SSM/PutObject credentials, missing or altered wheel RECORD entries, missing independent protected mount, and source-only native observer denial.

Also run and retain exact-head PASS evidence from:
- `.github/workflows/state-directory-runtime.yml`: root-capable temporary-directory STATE preparation; never the real registry Host
- `.github/workflows/graphical-registry-storage-installation.yml`: existing signed storage approval and independent S3 checkpoint/mount plan source checks
- the pinned root-control and host-deploy native-backend observer source checks included in three-owner CI

## Identity and authorization boundary

**Ordinary local installation, boot and recovery require NO registrar or Command Center.** For an explicitly standalone non-resident installation, `bootstrap.registries=[]` and `control_authority=null`; `/state` can be an appropriately selected and retained directory on the Host root filesystem. Host identity is locally generated and retained, never minted by a registrar.

For **optional Task C remote protected operations**, the operator-signed *storage establishment* approval and separate operator-approved *operation claim/send/revocation* remain mandatory. The Task C **local installation selection** (`zog-task-c-local-installation-selection-v1`) is explicitly not a signed registry enrollment or a fallback from failed managed signature verification; it contains the exact canonical host-install installation UUID and STATE UUID and cannot grant SSM. Legacy registry-signed selection is a separate, explicit mode, not a boot requirement.

Root-control `graphical_task_c_backend_observation.require_live_backend_bound_identity` is the selected protected, root-capable per-invocation readback of canonical `host-install.state_inspect`. It does not accept a gateway JSON claim, registrar signature, observer signing key or `native_accepted` flag. This handoff validates its *source*, not that a privileged native instance has successfully executed the observer against genuine enrolled Host identity. Work must independently prove custody of the existing Host's Ed25519 key/fingerprint and original enrollment, without deriving opaque H64 values from UUIDs.

## Privilege and backing storage boundaries

- Two distinct protected mounted filesystems: `/var/lib/zog-graphical-owner-ledger` and `/var/lib/zog-graphical-owner-authority`; each separate from its peer **and** the actual STATE/root filesystem, with independent UUID/PARTUUID, source, mount identity, ownership and retention verification. Root-directory STATE does **not** count as either mount. Fake directories, same-device bind mounts and borrowed historical STATE are disallowed.
- Disabled owner service `zog-graphical-owner.service` has dedicated protected session credentials for owner SSM and checkpoint write, plus root-owned IPC. Disabled broker `zog-graphical-trust.service` has **GetObject-only** checkpoint credential and separate broker signing credential. Unit-source checks forbid broker access to owner SSM/checkpoint PUT source and prohibit gateway privilege promotion.
- Both services require both protected mounts in systemd **[Unit]**, and their sockets are disabled, private Unix streams with no `[Install]` section. Only Work can independently establish which IAM policies and Unix-socket peer isolation are actually effective.
- Preserve and independently verify original history or approved new-installation genesis, independent external monotonic anchor, approved retention disposition, irreversible per-operation claim, revoked scopes, retry/lost-ACK and reboot recovery, and single-attempt protected SSM send fence. Do not reset an original or substitute a fresh scope to escape the old history.
- In all source results, `native_state_accepted=false`, `native_mounts_accepted=false`, `native_wheel_record_accepted=false`, `native_credential_accepted=false`, `owner_active=false`, `broker_active=false` and `ssm_authorized=false`. Passing source tests does not change these flags.

## Exact Work-only native follow-on

1. Independently authenticate selected real registry Host instance/account/region and root filesystem, non-resident installation/STATE UUIDs, real local Ed25519 fingerprint and correct retained identity. Last recorded native preflight found an XFS root but no installed host-install config or `/state`; reconcile unpublished original directory marker bytes with PR35 before creating `/state`. Native directory setup requires explicit local install approval, not an extra registrar or online command center.
2. Independently authenticate the approved prospective **Task C storage establishment** and operator key, separate protected ledger and authority disks/mounts, actual S3 account/bucket/prefix roles and externally retained anchor. Never borrow compiler-host /state or silently provision with synthetic IDs. Reuse approved native facts; if evidence is missing, report one exact deficiency.
3. Verify the **installed** three wheels, full RECORD contents, owned Python interpreters, systemd services and sockets against the selected source/unit bytes, including whole-wheel hashes newly attested in the native environment; never fall back to unpinned `/usr/bin/python3` when the native Host has an incompatible version.
4. Prove genuine fresh per-operation local backend observation and owner/broker identity, actual peer-authenticated Unix IPC, broker GetObject-only and owner checkpoint-writer/SSM IAM separation, direct gateway SSM denial, anchor/reboot/rollback and exact one-send fence tests.
5. Only after independent approval and native PASS may Work propose activation. This source handoff itself does not approve mounting, generating a signer, creating S3 genesis, changing IAM, enabling sockets, invoking SSM, or submitting Fonts.

**Disposition: source freeze candidate PASS; native installation HOLD.** This is the one selected handoff for the current root-control #47 + host-deploy #30 + host-install #35 v3 path. Superseded registrar-signed STATE mapping handoffs are not authoritative.
