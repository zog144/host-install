# STATE provisioning and identity coordinator — pass 3

This pass adds offline configuration publication, verified STATE directory
preparation, independent root-owned identity authorization/consumption, a UID 970
key worker and startup templates. It does not enable host-discover transport,
create cloud resources, format physical disks, install accounts or select a boot
slot. See `aws-state-acceptance.md` for the next disposable-host acceptance scope.

## Reviewed integration inputs

| Program | Exact reviewed unstable commit | Outcome |
| --- | --- | --- |
| host-install baseline | `79567cf93a0c012c64936834f6bd90c67a5f68e6` | Published v1 record schema retained |
| host-identify | `b504d610cfc2cd905685cfc4634e9101d479121a` | Real `initialization.prepare` and `load_existing` integrated |
| host-discover | `ce29dbf92934e1fddd7e1acb49255b238b42deb7` | Handoff reviewed; preliminary validator differs; managed transport remains blocked |
| image-build | `bb783285d888526e3c0d4976196294302c9070d6` | All six real exporter integration tests pass against current fixtures |

Dependencies are external pinned repositories, not vendored copies. Production
key-worker execution requires host-install and host-identify installed in the
same root-controlled Python environment. host-identify requires Python 3.12+.
The coordinator uses its own Python executable, drops to UID/GID 970 with groups
972/973, closes inherited descriptors and supplies a minimal environment without
PYTHONPATH. No shell or root-side private-key parsing is involved.

## Operator and installer commands

| Command | Purpose |
| --- | --- |
| `state-stage BUNDLE --output NEW_OVERLAY [--previous-bundle OLD_BUNDLE] [--ca-directory DIR]` | Write an offline configuration overlay from validated records; never modify live `/etc` or select a slot |
| `state-prepare --initialize-volume VOLUME_UUID` | Explicitly initialize metadata/layout on an empty, correctly mounted fresh STATE filesystem |
| `state-prepare` | Resume authorized preparation or verify an already completed layout; no identity creation |
| `state-authorize --initialization-id AUTHORIZATION_UUID` | Explicitly create the protected fresh identity transaction; never run automatically at boot |
| `state-initialize` | Resume/consume an existing authorization, or verify an already consumed identity; never approve enrollment |

All four mutating commands require root. The existing `state-probe` command
requires UID/GID 970. Synthetic bundles are not production authorization inputs.
Construct actual UUIDs/artifact expectations from the reviewed installation plan;
never install the example UUIDs unchanged.

## Offline publication

`state-stage` creates a root-owned 0700 output directory containing a resumable
`overlay-intent.json` and `etc/zog/host-install/`. The latter contains root-owned
0444 account, installation, optional CA and bootstrap files. Bootstrap is
published last, after its referenced files are durable. The overlay intent binds
the complete input bundle and optional previous bundle by canonical digest.

Files use exclusive staging, fsync, atomic no-replacement hard-link publication,
removal of the recognized temporary link, and parent-directory fsync. Repeating
with the same bytes re-establishes barriers. Partial/corrupt/conflicting bytes
are not overwritten. Directory staging uses Linux renameat2 with RENAME_NOREPLACE;
unsupported platforms fail rather than use a replacing fallback.

For upgrades/reinstalls, previous records are mandatory. Installation identity,
STATE bindings, initialization identity, registry configuration and control
authority must remain equal; revision and installation-record ID must advance.
An explicit authority/CA transition, migration or recovery needs a separate
operation and is rejected by this writer. A new overlay is produced for each
slot update. Copying it to an inactive slot, atomically selecting that slot and
validating boot contents remain outside this pass.

## Verified preparation and ownership

`open_volume` validates fixed NSS accounts and the actual mounted device before
any write. It performs the same PARTUUID/filesystem UUID, ext4, mount boundary,
root-device exclusion, nested-mount, read-only and descriptor checks as pass 2.
The CLI has no alternate mount-path or fixture-observation option.

On a fresh volume, explicit `--initialize-volume` must match bootstrap and the
filesystem must contain no application data (only empty, root-owned lost+found
and recognized interrupted preparation metadata are allowed). A root-owned
`.zog-preparation.json` intent is published before `.zog-state.json`. A matching
marker alone does not authorize creating a new layout.

Preparation creates installer metadata directories, private host-discover and
box-control homes and host-discover's trust/control/registries/health directories.
It leaves identity creation to the authorized coordinator. Existing directory
ownership/modes are verified, never repaired recursively. Writable service owners
are established here, after image-build's reusable all-root-v1 export boundary.

The final `.zog-prepared.json` is a durable layout-completion record. Subsequent
preparation validates existing directories and refuses to recreate missing ones.
A missing trust/control directory must not silently become an empty replacement
journal. Each state owner must additionally reject missing/corrupt files inside
those directories; directory validation cannot establish journal completeness.

Both preparation records are root:root 0444 at the STATE root, bound to the volume
marker digest. Installation records accumulate under
`/state/host-install/installations/<record_id>.json`, root:root 0444. Fresh layout
creation may resume only before completion and before any identity authorization
or consumption exists. Existing identity/control contents are never erased.

Accounts remain composition inputs supplied by image-build or the disposable-host
operator: UID/GID 970 and 971, groups 972/973, non-login shells, locked passwords,
no sudo/capabilities. The checker verifies UID/GID/home/shell/group mappings and
collisions; locked shadow and privilege-policy checks still need the deployment
preflight. No silent numeric reallocation is allowed.

## Root-owned identity operation

`/state/host-install/operations` is root:root 0700. It contains:

| File | Mode | Meaning |
| --- | --- | --- |
| `.host-install.lock` | 0600 | Persistent serialization inode; never unlink |
| `identity-authorization.json` | 0600 | Immutable fresh authorization binding installation, volume, path, account profile and authorization UUID |
| `identity-consumed.json` | 0600 | Immutable independent consumption of the exact public host-identify receipt |
| `recovery-hold.json` | 0600 | Protected failure hold; never cleared automatically |

Authorization is a root-only explicit action, separate from a fresh bootstrap
flag and from boot services. It refuses adopting orphan identity material or
changing an existing transaction. Repeating authorization does not remove or
reset consumption. There is one initialization transaction for this installation;
migration/adoption is not provided by this fresh initializer.

Under the operation lock, the coordinator checks completed layout, recovery
holds and the matching authorization. It creates the empty identity directory
only for that authorized fresh transaction. The service-account worker rechecks
STATE in its own process, performs the storage probe and calls host-identify.
The worker's public receipt is validated and durably consumed by root. A second
load-existing call validates the independently consumed receipt before success.
A consumed transaction always takes load-existing; a missing key never falls
through to prepare.

host-identify's authorization digest uses compact sorted JSON **with a final
newline**. host-install's published record digests retain compact sorted JSON
**without a final newline**. The coordinator explicitly implements this distinction;
real-library tests exercise it. No private bytes are stored in root receipts or
returned by the worker.

Process interruption after durable key publication resumes that same transaction
and key. Interruption during consumption resumes the recognized staged/link state.
Corrupt/partial metadata is refused. A host-identify transaction missing its
prepared key requires recovery, not another generation attempt. Observed worker,
IO, mount or validation failures during coordination create a recovery hold when
storage permits and propagate failure. No automatic hold-clear command exists.
If storage prevents writing the hold, incomplete consumption and subsequent
strict checks still prevent a false successful admission; external station history
remains necessary to detect restoration of an entire older STATE snapshot.

## Readable consumption projection

Successful live initialization publishes
`/run/host-install/identity-consumed.json`, root:root 0444 below a root:root 0755
directory. This contains public receipt metadata only, bound to the current boot
ID, bootstrap digest and marker digest. It declares both control and transport
false. The durable authoritative record remains in root-private operations.

The coordinator removes an old projection before a new run; failure withdraws
it where storage permits. It is transient and excluded from backups. A consumer
must verify ownership/path safety, exact schema, current boot/configuration/mount
bindings, and receipt/key agreement after successful ordered startup. It is not
authentication for a station session, a fresh-init capability or remote attestation.
No host-discover code consumes it yet; its next pass must implement that boundary.

## Startup templates and remaining gates

`examples/systemd` supplies a STATE mount template, root preparation and identity
oneshots, and an explicitly inactive host-discover drop-in example. They require
and order after the mount, bind lifetime to it, use Restart=no, and contain no
state-authorize command or unconditional identity-directory creation.

Render the PARTUUID and review executable paths before installing templates on
the disposable test host. The key-worker environment must be installed for UID
970 to import it. Syntax checks passed using systemd-analyze in a synthetic root;
no service was executed here. Service ordering, mount disappearance, actual UID
970 access and reboot behavior require the disposable-host tests.

Host-discover's live admission, storage-fault lifecycle,
station session/checkpoint protocol and restricted box-control gateway each
require their own verified consumer capability and acceptance before
transport or remote control can be enabled. The independent root receipt
does not replace those requirements. The installer-owned wire and field
contract is the [local STATE admission protocol](state-admission.md) and
the [STATE interface](state-interface.md). The consuming program
maintains its own `docs/host-discover/MANAGED-STATE.md` and
`docs/host-discover/SESSION-RECOVERY.md` contracts; those belong to
host-discover and become sibling chapters only in a reviewed aggregate
source export, not in this component's private checkout.

For a consumer, concrete admission requires a current-boot protected
observation bound to the same installation, STATE device/configuration
and root authorization/consumption evidence; independent verification
of the existing host identity; schema and protected-record compatibility
from the actual owning producers (not installer expectations copied
into runtime); and fail-closed behavior for absent, conflicting, corrupt
or storage-fault evidence. A successful observation alone authorizes
neither station enrollment nor archive signing, session renewal, DNS,
gateway operations or remote control. The older pass-3 handoff is
historical private development evidence, **not** a public schema
dependency or proof that every integration gate has passed.
