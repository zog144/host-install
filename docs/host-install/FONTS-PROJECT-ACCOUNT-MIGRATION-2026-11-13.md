# First Fonts — dedicated-account removal and Project storage migration

November 13, 2026 · host-install Regular source implementation · Native copy **not performed**

## Findings: ownership assumptions did not originate in the selected Task C installer

The existing host-install `task_c_local_install.py` installs the trusted
Host gateway from ordinary Python repositories. Its selected systemd unit
uses the already established root context, and the installer has no
`certbot-build-owner`, `certbot-build-worker`, `useradd`, `groupadd`,
or alternative controller UID selection. Do **not** create or rename a
dedicated build account to satisfy historical compiler lane source.

The **October 21 nonroot compiler identity design** instead introduced
a separate controller owner and execution worker, and a Project beneath
the controller owner's passwd home. Traced source dependencies:

- host-deploy `gateway/compiler_execution_identity.py`: explicit
  `controller_uid`, `controller_gid`, `build_uid`, `build_gid`,
  `controller_home`; dedicated nonroot home requirement; kernel identity
  switching via `subprocess.run(user=..., group=..., extra_groups=())`,
  along with a fabricated HOME/USER/LOGNAME environment.
- host-deploy `image_build_lanes.py`: historical lane specification
  `execution_user_id`/`execution_group_id` and Project path;
  `_controller(spec)` emits both IDs. These old records must remain
  readable as history, but MUST NOT authorize identity switching.
- host-deploy `fonts_lane_profile.py` and `fonts_lane_runtime.py`:
  retained first Fonts source digest
  `sha256:c7ab129937330fab5f74ae37b16a0b3e8de35cf87cef1fdda33d18bbcf1779f2`,
  old Project path, passwd home equality and chown of created directories.
  Those checks must be explicitly revised for the NEW controller.
- root-control `build.py` and controller socket validation:
  previously selected build User/Group and `SO_PEERCRED` controller
  UID policies; box-control Project-home policy. These require their
  respective owners' source amendments; host-install must not bypass
  runtime privilege/DAC checks to compensate.
- host-deploy `docs/host-deploy/NONROOT-COMPILER-EXECUTION-BINDING-2026-10-21.md`
  and root-control `docs/root-control/NONROOT-COMPILER-CONTROLLER-IDENTITY-2026-10-21.md`
  describe explicit creation/selection of new dedicated identities as a
  *native prerequisite*. These instructions are superseded for the
  webhook/compiler installation path.

**Important distinction:** the selected host-install repository contains
no implementation of the **specific historical account creation** (names
and numeric IDs). Its creation on the compiler Host appears to have been
performed by the old operator/installation procedure; its exact command,
time and remaining Certbot ownership must be checked on the live Host.
Do not claim no other software depends on these accounts merely because
the Task C installer does not. The old project must not be re-parented by
making `/home/certbot-build-owner` traversable to unrelated processes.

## New fixed application storage

Source Project (never deleted by this migration):

`/home/certbot-build-owner/gateway-first-fonts-runtime`

New compiler application data location:

`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`

The new directory is private (0700) beneath application-owned
`/var/lib/zog/image-build/projects` (0700) on **existing local storage**.
It is not a login home, alternate dedicated account, separate EBS volume,
new STATE authority, or a gateway path on a different Host. The existing
project name and artifact/provenance tree are retained unchanged.

`host-install-fonts-project-migrate` exposes `--inspect`, `--stage`,
`--commit`, `--verify` and `--verify-access`. The first four stages
require access to the historical private home; stage/commit on the live
Host require the **existing root administrative process**. No UID/GID
value is configurable and no `chown`, sudo-run-as, `subprocess(user=...)`,
getpwuid, `$USER` or `$HOME` selection exists in this helper.

The migration **copies**, not moves or deletes, all regular content with
SHA-256 inventories, timestamps and modes (and standard copied metadata),
preserving internal relative symlinks and in-tree hardlinks. All copied
files and directory entries are fsynced before atomic no-replace publication. Unexpected external hardlinks, escaping or
absolute symlinks, special devices, set-id files, changed source bytes,
a pre-existing destination or incomplete pending copy are explicit HOLDs.
A HOLD leaves source and any partial stage intact for an administrator's
evidence/recovery inspection. Stage uses a protected sibling
`.gateway-first-fonts-runtime.pending`; commit verifies the exact source
and staged contents before publishing the new Project and fsyncing its
directory. `--verify` checks the published copy again. No service is
started, and no speculative SSM retry is involved.

**Ownership:** because the live migration runs in the Host's already
provided root administrative context, every copied inode is created with
that process's *actual kernel effective UID/GID* (expected root:root
for the selected native administrator; the tool reports measured numbers
instead of selecting them). The destination's root is mode 0700 and the
source owner/group are reported separately from the destination's full
ownership histogram. No hard-coded `24201` or `24202` controls the
new tree. `--verify-access` is run directly from the corrected running
controller/worker process context (without switching identity) and reports
its actual effective UID/GID and read/write/traverse permissions. It
does not enter the inaccessible private legacy home. If the corrected
controller does **not** have access, **HOLD**, resolve process ownership
and ordinary app data permissions through its own service owner; do not
relax the old home or manufacture another account.

The copied `controller.json` and retained lane specification intentionally
still name the old Project and numeric IDs; those **are archival
provenance, NOT active execution configuration**. The host-deploy and
root-control/box-control owners must produce a reviewed new controller
selection and explicit old-to-new Project migration record, retaining
original operation identity, source pin, compiler receipt and
`kind=image`. Recomputing or overwriting the approved old specification
digest silently is prohibited. Account/identity behavior must be corrected
before restarting or compiling under this new path.

## Native Work sequence (compiler Host; no build)

Do this only after the controller owners establish the corrected
inherited-process-identity selection and native Work verifies that the
original compiler is quiesced. Recheck approved source SHA and package
installation rather than relying on a moving Git branch. The first
part can be performed as read-only inspection before new controller
selection; the copy requires a separately approved maintenance action.

```sh
set -euo pipefail
# Existing standard repository/Python installation, no new user or login home.
sudo install -d -m 0755 /opt/zog /opt/zog/image-build-maintenance
sudo git clone https://github.com/zog144/host-install.git /opt/zog/image-build-maintenance/host-install
# Reviewed immutable host-install migration source; Work still must
# inspect the installed Git commit/package bytes before privileged use.
sudo git -C /opt/zog/image-build-maintenance/host-install checkout --detach 8d9463813c39ae9ad7538beae0afec778ca8da25
# Stage the privileged tool only in a root-owned application directory;
# never execute a root installer out of a writable /tmp path.
sudo python3.12 -m venv /opt/zog/image-build-maintenance/venv
sudo /opt/zog/image-build-maintenance/venv/bin/python -m pip install --no-cache-dir /opt/zog/image-build-maintenance/host-install

MIGRATE=/opt/zog/image-build-maintenance/venv/bin/host-install-fonts-project-migrate
umask 077
sudo "$MIGRATE" --inspect
# Execute only after source/controller selection and filesystem backup review:
# sudo "$MIGRATE" --stage
# sudo "$MIGRATE" --commit
# sudo "$MIGRATE" --verify
```

Work must record the observed source and target tree SHA-256, file counts,
byte counts, original ownership histogram, new full ownership histogram,
selected effective UID/GID, private-directory modes and native access
checks. Work must separately confirm the new service's actual effective
credentials by a direct process-side `--verify-access` invocation; do
not run that check through a privileged substitute process and claim
nonroot controller access.

No account deletion is authorized here. **Before any future account
removal** examine *both* named passwd/group entries, any current
processes/units, any remaining certificates and Certbot install/renewal
workflows, all service unit/drop-ins, compiler packages/workspaces,
systemd credential sources and file ownership. A read-only starting set:

```sh
getent passwd certbot-build-owner || true
getent passwd certbot-build-worker || true
getent group certbot-build-owner || true
getent group certbot-build-worker || true
ps -eo pid,euid,egid,args | grep -E 'certbot|gateway-first-fonts|image-build|root-control|box-control' || true
systemctl list-units --all --type=service | grep -E 'certbot|build|controller|compiler' || true
sudo grep -RInE 'certbot-build-(owner|worker)|24201|24202' \
  /etc/systemd/system /etc/zog /opt/zog 2>/dev/null || true
# Inventory files on relevant existing volumes, not /proc or network mounts:
sudo find /home /var/lib /etc/letsencrypt /var/lib/letsencrypt \
  -xdev \( -user certbot-build-owner -o -user certbot-build-worker \) \
  -print 2>/dev/null || true
```

Read-only checks for Certbot ownership, renewals, account databases and
active processes must be **native observations**, not source assumptions.
If either identity has unrelated users or owns required service state,
account removal remains held until an owner-specific, tested migration
has completed. Avoid any automatic `userdel`, `groupdel`, `chown -R`
of the original private home, or deletion of files solely because they
carry one of the historical UIDs.

### Source verification and status

`.github/workflows/fonts-project-migration.yml` exercises copied
artifacts, source/data digests, hardlinks/symlinks, existing destination,
partial stage, changed source, unsafe external links and FIFO objects
against disposable filesystems on Python 3.12/3.13. This is a source
test, not a successful native compiler migration or proof of account
removal. Legacy accounts and Host state remain unchanged.
