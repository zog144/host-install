# STATE interface implementation, pass 2

Historical pass-2 boundary: see [pass 3 provisioning](state-provisioning.md) for
implemented record writing, preparation and initialization coordination.

This pass implements read-only preconditions, strict records, a pure lifecycle
policy and an explicitly requested storage probe. It does not install services,
create accounts, mount or format disks, generate keys, publish initialization
receipts, authenticate station sessions, or clear recovery holds. Existing disk
fixture and image-build behavior is retained.

The recovered historical proposal is in `state-contract-v1.md`. The executable
v1 record schema is `zog.host_install/state_contract.py`; complete synthetic examples
are in `examples/state-contract-v1/`. The older proposal's excerpts were partial,
with placeholder digests. They are not valid executable v1 records.

## Commands and APIs

| Entry point | Effect and result |
| --- | --- |
| `host-install state-validate BUNDLE` | Offline, bounded JSON parsing and cross-record validation; returns `offline-records-valid`. Does not inspect mounts or authorize anything. |
| `host-install state-inspect` | Read-only inspection of canonical live configuration and `/state`; returns `read-only-preconditions-verified`, never general readiness. |
| `host-install state-probe` | Explicit 4096-byte storage probe as effective UID/GID 970. Repeats live inspection, writes only in the already provisioned health directory, and rechecks the mount. |
| `state_inspect.inspect_live()` | Context manager retaining an open STATE directory descriptor; caller must close it. Does not load identity material. |
| `state_gate.decide(bundle, evidence)` | Pure policy for trusted adapters; returns an identity action, diagnostic code and control decision. It performs no IO or authentication. |

CLI failures return JSON on stderr and exit 2. STATE errors include a stable
`code`; diagnostic `error` text is for operators. Mount failures include
`state-not-mounted`, `wrong-mount`, `state-read-only`, `host-root-device`,
`nested-mount`, `volume-ambiguous-or-missing`, `wrong-volume`, `mount-changed`.
File/account failures include `required-path-missing`, `unsafe-path`,
`ownership-mode`, `hardlink`, `marker-mismatch`, `account-mismatch`, and
`state-access-denied`. Probe IO failures use `storage-probe-failed`.

A detached bundle or inspection report must never become a bearer capability.
The live commands do not accept a caller-selected mount, account, observation
file or authorization JSON. `assess_mount()` and `decide()` are library boundaries
for trusted code and synthetic tests, not exposed authorization endpoints.

## Paths, accounts and permissions

Canonical live records are `/etc/zog/host-install/{bootstrap,installation,accounts}.json`,
root:root 0444 with root-owned ancestors not writable by group/other. The volume
marker is `/state/.zog-state.json`, root:root 0444. The record loader reconstructs
the expected marker from bootstrap fields, validates its digest and compares it
with the actual marker only after establishing the STATE mount.

The account profile reserves host-discover UID/GID 970, box-control UID/GID 971,
archive-consumers GID 972 and host-control GID 973. Both users have a home under
`/state/<name>` and `/usr/sbin/nologin`. Host-discover's supplementary groups are
972 and 973; box-control's is 972. The checker rejects numeric collisions and
unexpected groups. Account creation, locked passwords, capability/sudo policy and
shadow-file composition remain installation integration responsibilities; this
pass checks NSS identity/home/shell/group mappings, not those additional policies.

Mounted `/state` is root:root 0755. `/state/host-discover` and its `identity`,
`trust`, `control`, `registries`, and new `health` directories are UID/GID 970,
0700. Identity may be absent during explicitly authorized initialization. The
other directories must have been provisioned on verified STATE. `health` contains
no authoritative state and is excluded from backup. No persistent directory is
created by inspection or the probe. Identity-file permissions and durable
receipts remain host-identify's responsibility; the inspector does not open keys.

Host-discover signs through host-identify as UID 970. Archive credentials belong
under `/run/host-discover/archive`, UID 970/GID 972, directory 0750 and files 0640.
Private key files must remain 0600 below the private identity directory. The
proposed controller socket remains `/run/box-control/host-discover.sock`, UID
971/GID 973, 0660, with peer-UID checks and a narrow allowlist. That gateway is
not implemented in this repository.

## Record validation and publication

All records are closed schemas: duplicate/unknown fields, unknown schema/features,
non-integer numeric values, mismatched digests, noncanonical UUIDs, unsupported
accounts, unsafe paths, insecure registry origins and ambiguous control roles
are rejected. Limits are 64 KiB per record and 32 registries. Digests are SHA-256
of sorted, compact, ASCII-escaped UTF-8 JSON without floats; they are integrity
references, not signatures.

The installation record adds `root_partuuid`, `accounts_sha256`, `marker_sha256`
and exact `state_schemas` for identity/trust/control/controller to the earlier
excerpt. This pass supports only schema 1 for each component. A foreign boot
bundle references an installer provenance record UUID and digest; provenance
content is not fetched or authenticated by this pass. Optional CA files have
fixed paths `/etc/zog/host-install/ca/<registry_id>.pem`, root:root 0444, with
raw-byte SHA-256 verification. Exactly one registry has the control role.

A future offline installer writer must publish all referenced files durably to
an inactive slot, fsync files and directories, and publish bootstrap last as the
commit record before selecting the slot. There is no record-writing command in
this pass. Never update the active configuration piecemeal. Per-slot artifact,
generation, root PARTUUID, selected slot, record ID and provenance may change;
installation/STATE/account/control-authority changes need explicit transitions.
The validator checks one coherent set, not the authorization for a transition
between two generations.

Installer expectations and runtime observations remain separate. `state-inspect`
reports mount ID, device, mount flags and boot ID separately. These records make
no Secure Boot, measured-boot or remote-attestation claim.

## Inspection, startup and storage failure

The Linux collector reads `/proc/self/mountinfo`, `/proc/sys/kernel/random/boot_id`
and `lsblk` topology. It requires one exact `/state` mount, ext4 rooted at `/`,
matching unique PARTUUID and filesystem UUID on one partition/device, writable
mount and superblock flags, and a different device from the running root. It
rejects nested mounts, symlink path components, incorrect owners/modes, hardlinked
records and read-only `statvfs`. The marker and component directories are examined
only after the mount check. The retained descriptor's device/inode and current
mount observation are checked again before successful return.

UUIDs and a volume marker are local bindings, not clone-resistant authentication.
The checker trusts the kernel, root-controlled configuration and topology tools.
It does not defend against a malicious root or an already compromised service
account. Collectors are invoked in the caller's mount namespace; a privileged
preparation report cannot replace the service's own check.

The explicit probe creates one unpredictable exclusive file in `health`, writes
at most 4096 bytes, fsyncs it, renames it, fsyncs the directory, removes it and
fsyncs the directory again. Short writes are completed. Any failed step fails the
probe; cleanup is best effort and never turns failure into success. Interrupted
probes may leave `.probe-*` files; remove them only during quiescent maintenance.
Do not run concurrent cleanup while a probe is active. A successful probe says
nothing about future IO or physical power-loss guarantees.

The service integrator must require STATE and a successful privileged preparation
unit, order after the mount, and bind service lifetime to it. Repeat inspection
and the probe in the service sandbox before using identity/control state. No
unconditional `StateDirectory=` or tmpfiles creation for identity. Mount loss or
any later write/fsync failure must latch a storage fault, stop command dispatch,
normal signing and credential renewal, and close the control session. This pass
does not install unit files, monitor mounts, persist that fault latch or authorize
its reset. Those adapters require the owning service's lifecycle implementation.

## Lifecycle evidence contract

Only trusted adapters may populate `decide()` evidence:

- `mount_verified` and `accounts_verified`: current successful local checks in
  this process/namespace, not a saved report.
- `storage_probe`: the current probe result, overridden to `failed` by any latched
  storage fault; never reuse a result from another process.
- `identity`: host-identify's validated receipt/key state, candidate count,
  initialization transaction ID and match against expected UUID/fingerprint.
  `complete` means both publication and authorization-consumption receipts agree.
- `authorization`: a privileged coordinator's verified, unexpired, unconsumed
  transaction, bound to current boot/installation/volume/initialization ID. A
  bootstrap fresh flag or caller-supplied boolean cannot establish this fact.
- `schemas`: actual component schema versions read by their owners before writes.
- `recovery_hold`: the protected recovery state; never default it to false after
  a failed read. `station`: an authenticated current-process session checked by
  host-discover against the designated pinned authority and independent station
  trust/checkpoint history, or an explicit unavailable/stale/cached result.

The pure function rejects unsupported schemas and inconsistent candidates, allows
completed identity reuse even with an old fresh configuration, permits absent
identity initialization only with a matching current transaction, and resumes
only a prepared identity for that same transaction. It never creates a key or
consumes authorization. `initialize-once` and `resume-prepared` are advisory
instructions to host-identify/coordinator, which must still enforce atomic
no-replacement publication and durable receipts.

Migration/recovery modes, recovery holds and stale trust/checkpoints yield
`recovery-only`. Cached sessions, unavailable stations and observation registries
never enable control. Recoveries require a named expected identity in bootstrap.
A complete STATE snapshot rollback cannot be detected locally; every daemon
start needs independently maintained station history. Simultaneous host/station
rollback or cloned keys still require external recovery/reapproval.

## Responsibility and next integration boundary

Host-install owns records, inspection, fixed account validation and this policy.
The next provisioning stage must add coherent offline record publication,
verified-volume ownership setup and protected initialization/recovery transaction
handling. Host-identify owns explicit load-existing/initialize-once/resume APIs,
key-file checks and schema-safe persistence. Host-discover owns evidence adapters,
session freshness, trust/replay journals and service fault handling. Box-control
owns the restricted gateway and reconciliation of uncertain operations.

Do not enable first-boot identity creation until those adapters are implemented
and tested together. Older slots must block on unsupported newer state schemas;
there is no automatic downgrade or journal reset.

## Reproduction and acceptance scope

Run the offline fixture with:

```sh
python3 -m zog.host_install state-validate examples/state-contract-v1/bundle.json
```

Run the complete suite with the pinned image-build dependency:

```sh
HOST_INSTALL_FIXTURES=/path/to/image-build/examples/host-install/fixtures \
PYTHONPATH=/path/to/image-build/src:src \
python3 -m unittest discover -s tests -v
```

The 19 scenarios in `scenarios.json` are synthetic, including all UUIDs, digests,
station evidence and authorization facts. The tests additionally cover strict
records, descriptor/path safety, read-only behavior, ordering, account/identity
policy, and probe EIO/ENOSPC/EROFS/short-write failures. The successful inspection
fixture uses real temporary files but synthetic mount collection and ownership
translation because this Work container maps only UID 0. No real STATE mount,
UID 970 execution, mount disappearance, hardware power loss, station recovery or
boot acceptance is claimed. All writes in testing are disposable regular files.
