# Trusted-Host Task C — ordinary installation handoff (2026-11-11)

## Selected architecture

The existing `host-registry` administrator, root filesystem and locally
installed services are trusted. The selected Task C runtime is the **existing
host-deploy gateway**, with a durable local send-once record and fixed SSM
operation selection. There is **no additional owner daemon, trust/history
broker, socket service, S3 authority or signed installer**. Historical
v3/v4 owner/broker/S3 modules remain *unselected* compatibility source only.

Do not require operator-signed storage establishment, signed installation
commits, a new registered Host key/registrar, S3 genesis/scope/anchor/Object
Lock/high-water/retention, S3 IAM roles, extra EBS, separate mounts or
separate filesystems. The trusted Host can keep normal software and its local
journal under the existing root volume. There is **no automatic remote
execution authority** merely from installing a Python package.

## Exact selected source interfaces

- Installer: `zog.host_install.task_c_local_install`, executable
  `host-install-task-c --plan|--stage|--inspect-state`.
- Normal component source repositories: host-install, root-control,
  host-deploy. One ordinary venv `/opt/zog/task-c/venv`; ordinary
  source wheel installation (without resolving unavailable unrelated
  component-development distributions), standard runtime dependencies and
  exact installed-module import verification.
- Active runtime **after separately authorized activation**:
  `/opt/zog/task-c/venv/bin/host-deploy-gateway --state-directory
  /var/lib/host-deploy-gateway run` (standard host-deploy entry point).
- Selected root-control local journal interface:
  `zog.root_control.task_c_trusted_host` (source present, not a second
  owner daemon); gateway functions:
  `zog.host_deploy.gateway.generic_pipeline`,
  `zog.host_deploy.gateway.trusted_host_submission`,
  `zog.host_deploy.gateway.graphics_operation_send_intent`.
  The gateway's local send-intent directory is under the same
  `/var/lib/host-deploy-gateway` application root.
- Application state: `/var/lib/host-deploy-gateway`, root-owned,
  mode 0700 on the existing root-backed filesystem.
- One **disabled** systemd unit:
  `/etc/systemd/system/zog-task-c-gateway.service`, fixed root user,
  `StateDirectory=host-deploy-gateway`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/host-deploy-gateway`. No `[Install]`,
  `WantedBy`, listener socket, checkpoint credential, signer or mount unit.
- `--inspect-state` optionally reads the actual installed host-install
  `state_inspect.inspect_live()` context and rechecks its canonical
  installation/STATE UUIDs, marker, account and backing topology. This
  is read-only and **not needed to stage** the disabled software while
  the retained registry Host's /state migration is unfinished.

The standard gateway uses its existing Host AWS instance-role capabilities,
not newly established S3 reader/writer roles. Request provenance, approved
task/source, selected compiler target and exact server-generated SSM script
are checked by host-deploy before a durable local send intent is written.
The filesystem record prevents normal retry/restart duplicate sends, including
after an uncertain SSM acknowledgement; it does **not** claim to defeat
malicious administrator rollback. The source owner is responsible for
operation authorization/revocation and fixed SSM target validation.

## Work installation — exact commands; no activation/SSM

The following is a native **staging** procedure, not an instruction to
enable or start the gateway. Work should pin all repository checkouts to
approved immutable commits, verify package provenance and normal installed
files, and adjust the pinned source SHAs if newer source integration is
accepted. Examples below use the three-owner source selections observed
during this handoff. Do not confuse the installed Host's 0.14.9 legacy
host-install environment with this newly packaged installer.

```sh
set -euo pipefail
SRC=/opt/zog/task-c/sources
sudo install -d -m 0755 /opt/zog /opt/zog/task-c "$SRC"

sudo git clone https://github.com/zog144/host-install.git "$SRC/host-install"
sudo git clone https://github.com/zog144/root-control.git "$SRC/root-control"
sudo git clone https://github.com/zog144/host-deploy.git "$SRC/host-deploy"

# Review/record these exact candidate heads before staging.
sudo git -C "$SRC/host-install" checkout --detach 3178ff445849630e05ab9a1ab4f04acc5893dfd2
sudo git -C "$SRC/root-control" checkout --detach 6a545931a79e3f700dbf769b8a87fe33f9a6e620
sudo git -C "$SRC/host-deploy" checkout --detach e25feb749d091e698cd01ad0bc7079250709978f

# Use the already observed retained candidate's Python 3.12 executable,
# subject to Work's ordinary root ownership, executable and hash inspection.
PYTHON=/opt/host-discover/candidates/retained-legacy-3fd8bd0-3d94f34-20261109/venv/bin/python3.12
sudo test -x "$PYTHON"
sudo "$PYTHON" -m venv /opt/zog/task-c/installer-venv
sudo /opt/zog/task-c/installer-venv/bin/python -m pip install --no-cache-dir "$SRC/host-install"
INSTALLER=/opt/zog/task-c/installer-venv/bin/host-install-task-c

sudo "$INSTALLER" --plan \
  --root-control-source "$SRC/root-control" \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

# Installs normal repositories in a single venv and a disabled unit.
# No S3, signer, EBS, mount, systemctl enable/start or AWS SSM call.
sudo "$INSTALLER" --stage \
  --root-control-source "$SRC/root-control" \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

sudo /opt/zog/task-c/venv/bin/python -I -c 'import zog.host_deploy.gateway.generic_pipeline; import zog.host_deploy.gateway.trusted_host_submission; import zog.host_deploy.gateway.graphics_operation_send_intent; import zog.root_control.task_c_trusted_host'
sudo systemctl cat zog-task-c-gateway.service
sudo systemctl is-active zog-task-c-gateway.service || true
sudo systemctl is-enabled zog-task-c-gateway.service || true

# Optional ONLY after canonical /state exists and host-install has prepared it:
# sudo "$INSTALLER" --inspect-state
```

For an existing source checkout, omit `git clone` and record the actual
detached HEADs. Work must verify the standard Python runtime dependencies, selected module
imports, Python entrypoint, systemd ownership/mode, local state directory
and installed wheel/RECORD metadata. Root-control component-development
metadata refers to internal `box-control`/`image-build` distributions
not independently published on PyPI; this Task C staging installs the
three source wheels with `pip --no-deps` after normal boto3/cryptography/
dbus-next dependencies. A blanket `pip check` would reject those unrelated
internal pins and is **not** a Task C native admission requirement. A missing
actual Task C module or import remains a real installation failure.

Never modify an existing active gateway or enable the new service during
this Regular installation source task. If a deployed gateway is already
running, inspect its InvocationID and service configuration before any future
operator-authorized cutover. No Task C command or original SSM send is run
by the staging command.

## Source and native exit criteria

- `--plan` reports no S3, signed approval, separate volume or SSM authority.
- `--stage` produces status `software-and-disabled-units-staged`,
  `native_runtime_started=false`, `ssm_authorized=false`.
- The selected source modules import from the installed venv. Ordinary
  runtime dependencies and wheel metadata are verified; unrelated internal
  development-distribution pins are not treated as an extra install gate.
- The single systemd gateway unit is ordinary, disabled, root-owned and
  has no S3/approval signer/mount/listener dependencies.
- `--inspect-state`, where available, reads the live canonical Host/STATE
  evidence directly, without signed mapping or registrar.
- Native operation acceptance remains distinct: exact local SSM target,
  request approval/revocation, one durable pre-send intent, lost-ack no retry,
  result inspection and systemd restart behavior must be verified by
  root-control/host-deploy Work before turning on the actual gateway.

Focused source tests:
`.github/workflows/task-c-local-install.yml`, Python 3.12 and 3.13.
The wheel build verifies the included service template. Old signed-v3/v4
workflows remain historical source checks, not admission prerequisites of
this selected installer.

**No live Host installation, IAM, S3, SSM or systemd activation was
performed by host-install Regular.**
