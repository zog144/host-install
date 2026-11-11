# Task C ordinary local installation — native staging handoff (2026-11-11)

## Decision and scope

The November 11 trusted-Host decision supersedes the **selected** v3/v4
signed-storage/S3 establishment gates. The Host root administrator, installed
services and existing local Host identity are trusted; adversarial whole-Host
rollback and malicious filesystem modification are not the present threat.
Ordinary application installation must not require operator Ed25519 approval
keys, installer-signed commits, registrar/Command Center signatures, S3
account/bucket/prefix/genesis/Object Lock/retention, high-water or external
anchor, distinct reader/writer IAM sessions, additional EBS devices, separate
mounts, or special package-signing approvals.

Do not edit/repurpose historical v3/v4 evidence as though it were a valid new
local installation. They are not selected by this procedure. Normal Python
wheel/source installation, host-install local STATE inspection, ordinary
root ownership/file modes, systemd services and Unix peer authentication
remain the relevant installation facilities. A successful *software stage*
does **not** authorize a Task C operation or any AWS SSM send.

## Source path and exact installed interface

- Installer: `zog.host_install.task_c_local_install`
- Console script: `host-install-task-c`, with mutually exclusive
  `--plan` (read-only), `--stage` (install, but no activation) and
  `--inspect-state` (optional read-only use of host-install's real live
  `state_inspect.inspect_live()` descriptor after canonical STATE exists).
  Missing /state does **not** block ordinary software staging.
- Python software: ordinary `pip install` of checked-out host-install,
  root-control and host-deploy repositories into **one** venv,
  `/opt/zog/task-c/venv`. Its normal `pip check` must pass.
- Local application data: `/var/lib/zog/task-c/owner`,
  `/var/lib/zog/task-c/trust`, and `/etc/zog/task-c`, root-owned
  mode 0700 on the existing root filesystem. They are **directories**, not
  EBS volumes or independent anti-rollback authorities.
- Disabled systemd units: `zog-task-c-owner.service/socket` and
  `zog-task-c-trust.service/socket`; both sockets initially root-owned
  mode 0600, Unix IPC only. Neither service/socket has an `[Install]`
  section. Root-controlled IPC rights may later be delegated through
  ordinary users/groups after peer authentication is accepted.
- Selected owner module: `zog.root_control.task_c_local_service`.
- Selected trust module: `zog.host_deploy.gateway.task_c_local_trust_daemon`.
  **These modules are required integration inputs from their owners** and
  are not interchangeable with historical S3-backed
  `graphical_task_c_service` and `graphics_owner_trust_daemon`.
- No `LoadCredential` pointing at S3 or special AWS reader/writer roles.
  The eventual SSM owner must use existing Host AWS capabilities and local
  OS authorization with a fixed, checked SSM target/document. The owner,
  not this installer, is responsible for a durable local single-attempt
  send claim, revocation, no resend after uncertain SendCommand outcome,
  and independently reviewing the original command outcome.

This source path does not import the historical
`graphical_task_c_v3_install_freeze`,
`graphical_task_c_v4_root_backed_install` or
`graphical_protected_storage_admission` verifier. The obsolete v3/v4
requirements are **not native admission blockers for this selected local
installer**. They can remain as clearly unselected historical compatibility
references until their owners retire them.

## Work native staging — exact executable procedure, no SSM

The repository SHAs must be explicitly checked against the latest approved
three-owner source selections **before running**. Below are the reviewed
branches; use detached checkouts of the approved immutable commit, not an
unreviewed moving branch. The precise root-control and host-deploy runtime
revision is deliberately not frozen until those owners supply their new
local modules. Run these steps on the **existing** `host-registry` only
after that source integration passes.

```sh
set -euo pipefail
SRC=/opt/zog/task-c/sources
sudo install -d -m 0755 /opt/zog /opt/zog/task-c "$SRC"

# Existing GitHub repository installation workflow; no registrar, S3, EBS,
# signing service or separate source-artifact approval procedure.
sudo git clone https://github.com/zog144/host-install.git "$SRC/host-install"
sudo git clone https://github.com/zog144/root-control.git "$SRC/root-control"
sudo git clone https://github.com/zog144/host-deploy.git "$SRC/host-deploy"

# Replace these moving refs with exact accepted SHAs in the Work record.
sudo git -C "$SRC/host-install" checkout regular/state-directory-runtime-integration-20261107
sudo git -C "$SRC/root-control" checkout regular/task-c-v3-checkpoint-consumer-20261107
sudo git -C "$SRC/host-deploy" checkout regular/task-c-v3-checkpoint-consumer-20261107

# These two presence tests intentionally HOLD while the old S3 runtime is
# the only implementation; they are not storage/signer admission tests.
sudo test -f "$SRC/root-control/src/zog/root_control/task_c_local_service.py"
sudo test -f "$SRC/host-deploy/src/zog/host_deploy/gateway/task_c_local_trust_daemon.py"

# This Python 3.12 executable was previously observed in the retained
# candidate environment; Work must recheck its root custody and SHA-256.
PYTHON=/opt/host-discover/candidates/retained-legacy-3fd8bd0-3d94f34-20261109/venv/bin/python3.12
sudo test -x "$PYTHON"
sudo "$PYTHON" -m venv /opt/zog/task-c/installer-venv
sudo /opt/zog/task-c/installer-venv/bin/python -m pip install --no-cache-dir "$SRC/host-install"

INSTALLER=/opt/zog/task-c/installer-venv/bin/host-install-task-c

# Read-only plan. No installed STATE or Command Center enrollment is
# necessary to inspect source paths or stage disabled software.
sudo "$INSTALLER" --plan \
  --root-control-source "$SRC/root-control" \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

# Root-backed Python + disabled unit staging. No systemctl start/enable;
# no SSM, S3, signing, AWS IAM mutation or mount operations.
sudo "$INSTALLER" --stage \
  --root-control-source "$SRC/root-control" \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

sudo /opt/zog/task-c/venv/bin/python -m pip check

# OPTIONAL only once canonical /state is available; not required for stage.
# sudo "$INSTALLER" --inspect-state

sudo systemctl cat zog-task-c-owner.service zog-task-c-owner.socket
sudo systemctl cat zog-task-c-trust.service zog-task-c-trust.socket
sudo systemctl is-active zog-task-c-owner.service || true
sudo systemctl is-active zog-task-c-owner.socket || true
sudo systemctl is-active zog-task-c-trust.service || true
sudo systemctl is-active zog-task-c-trust.socket || true
```

The native review must record the **actual detached HEADs**, regular wheel/
installed source versions and files, import paths, local Python interpreter,
existing Host/STATE identity, root-owned directories, socket permissions and
systemd unit bytes. `pip check` is a normal dependency-consistency check;
a failing dependency must be installed from its ordinary repository/wheel
source, not bypassed by inventing a signed artifact or S3 gate.

For an already staged checkout, omit the `git clone` steps; verify the
existing source paths, package version and recorded commit SHAs before
running the installer. Do not overwrite a live v3/v4 owner unit or start
another SSM processor as part of staging.

## Non-activation acceptance

- `host-install-task-c --stage` reports
  `software-and-disabled-units-staged`, `native_runtime_started=false`,
  `ssm_authorized=false`.
- Python imports resolve exactly to the simplified local owner and trust
  modules. Missing modules are a **source-integration HOLD**, not a reason
  to supply S3 keys, extra disks, or signed storage approval.
- No `WantedBy`, `[Install]`, `systemctl enable/start`, SSM call,
  signing service, new enrollment or storage command occurs in the installer.
- `--inspect-state` uses host-install's own live, rechecked STATE
  descriptor/marker/account/topology reader, not an installation signature;
  it reports local installation/STATE IDs without granting control.
- A future operation must still check actual Host identity/STATE with
  host-install's live descriptor inspector and ordinary OS peer credentials,
  approve the specific operation, durably claim it locally before sending,
  deny replay or uncertain resubmission, and support read-only outcome
  reconciliation. Those are **root-control/host-deploy runtime duties**.
- If an existing running v3/v4 service is found, Work must not replace,
  stop or activate it silently. Coordinate a separately authorized service
  cutover after the simplified runtime is accepted.

## Source proof and remaining ownership

The focused source workflow is `.github/workflows/task-c-local-install.yml`.
It tests the ordinary source plan, package command, local directory
provisioning, disabled systemd bytes, no S3 or signing dependencies,
unprivileged/foreign-plan denial and interrupted runtime selection, and checks
the four unit templates in a built host-install wheel on Python 3.12/3.13.
This is source evidence, **not** a claim that the current registry Host has
been modified.

root-control PR #47 must provide the actual new local SSM owner; host-deploy
PR #30 must provide the matching local trust daemon. Their sources must not
re-enable historical S3 or signed storage establishment requirements through
runtime imports. No native activation or SSM SendCommand is authorized here.
