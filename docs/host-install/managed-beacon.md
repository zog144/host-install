# Explicit managed-beacon composition

> **Current selection:** host-discover 0.4.11 at `9e741d9a86bb2fd466ac46b252be0b78528eeff7`, reviewed against host-install 0.14.3 and retained by later 0.14.x compatibility CI. See [the 2026-10-24 successor contract](host-discover-compatibility-2026-10-24.md). Historical companion notes below describe earlier acceptance and must not override the current immutable pin.

This optional profile enrolls and sends session-bound heartbeats through verified
HTTPS using the existing host identity. Remote commands, archive delivery and
box-control dispatch remain disabled. The selected consumer is host-discover
0.4.11 with host-identify 0.3.4. No station approval, authority export or
certificate operation is implied by staging or restarting this profile.

## Provisioning

Complete normal STATE preparation, explicit identity authorization and identity
consumption first. Install all Python packages in a root-controlled Python 3.12+
environment. Review actual executable paths and the canonical fixed accounts.
Then run once, explicitly as root:

```
host-install beacon-prepare --state-volume-id <bootstrap STATE UUID>
```

This calls host-discover's supervisor preparation primitive. Host-install records
`beacon-intent.json` and `beacon-prepared.json` in
`/state/host-install/operations`, root:root 0600, serialized by
`beacon-provision.lock` (0600; never unlink). These records bind installation,
STATE UUID and consumed fingerprint, not a slot or configuration revision.
Interrupted initial provisioning may resume with identical bindings before any
consumer journal exists. Initial preparation refuses existing control state.
After completion, retries only verify the ledger; they never recreate it or reset
an operated ledger. A completed receipt with a missing/corrupt ledger is recovery
required. Do not bypass this wrapper with direct supervisor preparation to repair
an installation. No boot or upgrade service invokes either preparation command.

The supervisor owns `/state/host-discover-supervisor` root:root 0700, containing
`ledger.json` and `lock`, root:root 0600. This directory is reserved for that
component and excluded from reusable images. Existing STATE preparation tolerates
this separate component and does not initialize it. UID970 owns its identity and
`control/managed.json`; it cannot read or reset the root ledger.

## Offline service profile

```
host-install beacon-stage --discover-source <reviewed host-discover source> \
  --producer-source <matching host-install source> --output <new overlay> \
  --executable-directory /opt/zog/venv/bin
```

The staging command requires the reviewed consumer template byte hashes; changed
templates need interface review. Producer source is a trusted composition input
and must match the installed producer. No consumer source is vendored. Output
contains `profile.json` (immutable intent with file hashes), and seven units under
`etc/systemd/system`. Success means all files were durably published; the mere
presence of profile.json does not mean a previously interrupted stage completed.
Same-byte retries resume, different inputs refuse. Staging neither enables units
nor writes STATE. Render/install the STATE mount separately with the verified
PARTUUID. Install the staged units only after a successful stage operation.

The current profile additionally verifies all 17 reviewed top-level host-discover
runtime modules and records their Git blobs/SHA-256 values in `profile.json`.
Before activating a retained installation, attest the actual installed component
wheel with `host-install beacon-attest-installed --distribution host-discover`
using the same protected Python interpreter that will run the beacon. The command
checks exact module bytes against the selected wheel `RECORD`; it does not write
STATE or authorize station approval. Use `--distribution zog` only for an
explicit aggregate-wheel composition.

Explicitly stop and disable `host-discover.service` and
`host-discover-managed.service`; ensure no manually launched legacy writer uses
this identity. Install the units, reload systemd, and enable/start only
`host-discover-beacon.service`. Its Conflicts/After dependencies stop either
known competing service before beacon starts. Configure only one profile as
wanted at boot; do not add Wants for both. Systemd cannot police arbitrary
manually launched processes. The beacon retains the account contract's existing
supplementary groups; this does not enable archive/control features.

The composed sockets use Accept=no. `host-install-admission.service` and
`host-discover-supervisor.service` consume their systemd-passed listener using
`state-admission-listen` and `serve-listen`. Beacon Requires/After both services,
so shutdown leaves both processes available until the beacon has durably finished.
Each connection retains the original peer/schema/STATE checks and a 20-second
request deadline. Invalid requests close only that connection. No automatic
restart or reset is added. Backlog is eight; requests are handled serially.

The earlier Accept=yes composition failed live reboot: shutdown prevented a new
admission handler from starting during beacon finish and left its run active.
Do not deploy the raw per-connection templates as the managed-beacon profile.
They remain inputs for the explicit composer and legacy diagnostic examples.
The composer renders seven units, replacing the two @ templates with persistent
service units. When upgrading from that earlier profile, stop beacon cleanly,
stop both sockets, install the complete new unit set, daemon-reload, then start
beacon. Preserve STATE. Any run already stranded by the old shutdown defect needs
the normal inspected, explicit root retry; no update clears it automatically.

Both sockets start after normal identity bootstrap with DefaultDependencies=no,
explicit sysinit/STATE/identity ordering and shutdown conflicts. Beacon requires
both sockets and stops before them. All bind to STATE. Restart=no is intentional.
Supervisor socket is root:970 0660; peer credentials restrict requests to UID970.
A missing, wrong, unavailable or read-only STATE blocks admission. Do not use
ordinary directory existence as evidence. Socket observations are checks, not
leases; already sent requests cannot be retracted after a concurrent fault.

## Upgrade, rollback and recovery

Ordinary upgrades/reinstalls preserve all component state and provisioning
receipts. Stage fresh units with reviewed package versions; do not run initial
supervisor preparation as an upgrade step. A repeated beacon-prepare after
completion verifies bindings and ledger without changing journal, revision or
trust. Rollback software must understand actual stored schemas or refuse startup.
Do not replace newer state with empty older schemas.

For backup, stop beacon cleanly and take one consistent snapshot containing host
identity/receipt, installer operations/records, consumer journal and supervisor
ledger. Preserve numerical ownership and modes. Exclude /run sockets/projections
and temporary credentials. An old STATE restore requires explicit recovery with
station history reconciliation; whole-volume rollback is not locally defeated.
This pass implements no restore/adoption or torn-write repair operation.

After an abnormal exit or network/storage fault: stop beacon, investigate, then
run `host-discover-supervisor inspect`. An authorized root operator may request
retry using the observed revision and run UUID:

```
host-discover-supervisor reset --revision <N> --run-id <UUID> --reason '<reason>'
```

This preserves key, pins, journal digest and station checkpoints. It rejects stale
observations and a cooperating running consumer. It does not repair missing or
corrupt journals/ledgers, clear installer holds, delete pending files, or reset
station history. Never put reset in ExecStartPre, a timer, or a restart loop.
Clean stops permit restart/reboot with the same identity and a fresh station
session. Missing ledger or journal, schema mismatch and unresolved faults block.

## Responsibilities and verification

Host-install owns verified mount/account/installation inputs, identity transaction
coordination and explicit profile provisioning. Host-identify owns key persistence
and signing primitives. Host-discover owns enrollment, TLS/session checks, journal,
supervisor protocol and reset. Station-access owns fingerprint approval and
independent session history. Box-control has no reachable role in this profile.

`tests/test_beacon_profile.py` uses real durable files and the real supervisor
with synthetic mount/identity observations. It covers provisioning retries,
interruption, upgrade preservation, missing/corrupt state refusal, offline staging
and the complete generated boot graph with a negative cycle control. Consumer
suites cover clean finish, active-run blocking, CAS reset, and network failures.
Live acceptance requires separately retained, revision-bound results; those private records are not part of this public source manual and must not be inferred from a successful fixture run.

## Graceful stop and admission helpers (0.4.3)

The composed beacon uses `KillMode=mixed` and `TimeoutStopSec=90s`. SIGTERM goes
to the main beacon so its handler can finish a current local admission check and
durably finish the supervised run. Short-lived `lsblk` children must not receive
the initial signal: default control-group termination can kill a check during
shutdown and strand an otherwise healthy run. If the main process does not finish
in time, systemd still kills the entire cgroup; that abnormal stop intentionally
retains active-run protection. No automatic reset or prepare is added.

Stage this revision into a new overlay and install its complete unit set. Preserve
STATE. A run already stranded by the previous stop behavior requires inspection
and an explicit supervisor CAS retry, not deletion of its ledger or journal.
Host-discover 0.4.4 pins this producer version; its network retry implementation is
unchanged from 0.4.3.
