# Task C — ordinary trusted-Host installation and native staging handoff

**Decision:** November 11, 2026. **Native result:** source-tested only; do not activate
or send SSM in this Regular task.

## Selected installation, not the historical v3/v4 design

The existing `host-registry` administrator, root filesystem, service account
and AWS instance role are in the trust boundary. The Task C gateway uses
its existing host-deploy local durable send-once journal; it does **not**
need another SSM owner, trust/history broker, socket service, operator key,
signed storage approval, installer signing key, S3 checkpoint/anchor/genesis,
retention/Object Lock, highwater witness, independent IAM reader/writer
roles, new EBS volume, partition, mount or filesystem.

The selected installation stages **one** disabled systemd unit,
`zog-task-c-gateway.service`, using the normal
`host-deploy-gateway` process. The application owns
`/var/lib/host-deploy-gateway` (root, mode 0700) on existing root storage.
No separately protected storage authority is created. The old v3/v4
source contracts are retained only for historical compatibility; the selected
installer never imports or invokes them.

### Exact source/installation interfaces

- `host-install-task-c --plan`: read-only local source plan.
- `host-install-task-c --stage`: normal Python source/wheel install of
  **host-install and host-deploy**, `pip check`, installed module imports,
  0700 local state directory and disabled 0644 unit file, then a normal
  `systemctl daemon-reload`. It does **not** enable/start/restart the
  service, open a socket, contact AWS or send SSM.
- `host-install-task-c --inspect-state`: *optional* read-only call to
  host-install's `state_inspect.inspect_live()`. It rechecks the existing
  canonical installation/STATE marker, accounts, root-backed filesystem
  and IDs without a registrar or signing key. The retained registry Host
  can stage software while /state migration is still unfinished.
- Installed venv: `/opt/zog/task-c/venv`.
- Selected systemd ExecStart:
  `/opt/zog/task-c/venv/bin/host-deploy-gateway --state-directory
  /var/lib/host-deploy-gateway run`.
- Selected runtime modules:
  `zog.host_deploy.gateway.generic_pipeline`,
  `zog.host_deploy.gateway.trusted_host_submission`,
  `zog.host_deploy.gateway.graphics_operation_send_intent`.

The independent root-control `zog.root_control.task_c_trusted_host`
local-journal source is reviewed separately under PR #47 but **is not
required for this selected existing gateway process**. Root-control's
other Host services can be installed through their usual Zog/Python
procedures independently; installing that optional module must not
become another Task C authority or deployment gate.

The host-deploy gateway validates original request provenance, fixed
selected compiler Host and exact server-generated SSM command before
writing a local fsynced one-attempt send-intent record. A lost SendCommand
acknowledgment means an uncertain outcome, never permission to resend.
This protects ordinary process retries/reboot, not malicious root rollback.
Operation authorization, cancellation and result reconciliation remain
runtime and native Work acceptance responsibilities, not installation-signing
ceremonies.

## Work-only native staging procedure (not activation)

These are executable commands for the existing `host-registry`. Work must
first confirm the true original running gateway/unit/InvocationID, actual
Host instance role and candidate Python, and review the selected immutable
repository heads. The commands below pin the actual source versions under
test, not an unreviewed mutable branch.

```sh
set -euo pipefail
SRC=/opt/zog/task-c/sources
sudo install -d -m 0755 /opt/zog /opt/zog/task-c "$SRC"
sudo git clone https://github.com/zog144/host-install.git "$SRC/host-install"
sudo git clone https://github.com/zog144/host-deploy.git "$SRC/host-deploy"

sudo git -C "$SRC/host-install" checkout --detach bbe725f82ca2ba76902e9b91c7d6ca910c1ef819
sudo git -C "$SRC/host-deploy" checkout --detach a28df09b070d81ae3369ade969302f52d0a2d749

# Existing candidate Python 3.12; re-verify executable, owner and SHA256.
PYTHON=/opt/host-discover/candidates/retained-legacy-3fd8bd0-3d94f34-20261109/venv/bin/python3.12
sudo test -x "$PYTHON"
sudo "$PYTHON" -m venv /opt/zog/task-c/installer-venv
sudo /opt/zog/task-c/installer-venv/bin/python -m pip install --no-cache-dir "$SRC/host-install"
INSTALLER=/opt/zog/task-c/installer-venv/bin/host-install-task-c

sudo "$INSTALLER" --plan \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

# Normal package install and one disabled unit only; no SSM execution.
sudo "$INSTALLER" --stage \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

sudo /opt/zog/task-c/venv/bin/python -m pip check
sudo /opt/zog/task-c/venv/bin/python -I -c 'import zog.host_deploy.gateway.generic_pipeline; import zog.host_deploy.gateway.trusted_host_submission; import zog.host_deploy.gateway.graphics_operation_send_intent'
sudo systemctl cat zog-task-c-gateway.service
sudo systemctl is-active zog-task-c-gateway.service || true
sudo systemctl is-enabled zog-task-c-gateway.service || true

# Only after canonical /state exists, read-only optional inspection:
# sudo "$INSTALLER" --inspect-state
```

If those checkouts already exist, verify their detached HEAD and use them
instead of cloning. Use the existing standard Python/package installation
workflow, not a new signed artifact bundle or AWS credential establishment.
The selected `host-install` and `host-deploy` component dependencies
resolve normally from PyPI; the unrelated `root-control` development
dependency on separately unpublished `box-control` is **not** a
prerequisite to installing the active host-deploy gateway.

No activation is permitted as part of these commands. Do not replace or
stop the existing live gateway. If the new service is later to be adopted,
Work must separately reconcile original systemd service state and Command
Center access, verify installed runtime and local claim/revocation/no-retry
behavior, and obtain authorization before enabling any SSM operation.

## Source tests and final boundaries

`.github/workflows/task-c-local-install.yml` tests Python 3.12 and 3.13
unit staging, entrypoint, wheel RECORD/unit inclusion, permission and
nonactivation contracts, and now additionally **installs the real
host-install + host-deploy repositories into a disposable venv/root**.
It neither touches the selected Host nor invokes systemctl start/enable
or AWS SSM. `--inspect-state` does not create an identity or authorization.
A passing source test is not native Host or service acceptance.

**The new path requires no S3, signer, additional storage, new Host enrollment
or external anti-rollback service. No live Host resources were changed by
host-install Regular.**
