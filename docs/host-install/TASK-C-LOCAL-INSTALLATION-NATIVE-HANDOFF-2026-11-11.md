# Task C — trusted-Host direct SSM and ordinary local installation

2026-11-11 · **Selected source contract, native activation HOLD**

## Current design

The existing trusted `host-registry` administrator, local root filesystem and installed applications form the Task C trust boundary. New S3 genesis/operation checkpoints/anchors/Object Lock, adversarial Host rollback protection, operator-signed storage and per-operation approvals, installer signing keys, separate broker signatures, extra EBS devices and a second SSM principal are **not required**.

Task C has **one selected submission path**: the existing `host-deploy-gateway` process on the trusted Host. The historical signed-v3/v4 owner, checkpoint and trust broker modules may remain in old draft source, but are not selected for installation or Task C native admission. No second owner, broker, trust daemon or socket needs to run.

`zog.host_deploy.gateway.generic_pipeline` validates the original admitted request and prepared dispatch, frozen compiler catalogue/source, exact stage and remote request, original GitHub provenance and current compiler target. `trusted_host_submission.selected_command` derives the fixed server-generated image-build shell script. The caller cannot choose an arbitrary document, SSM instance, shell payload or credential. `runner.Host.submit_command` sends one `AWS-RunShellScript` request through the existing Host AWS role with SDK `total_max_attempts=1`.

Under the per-request gateway lock, the stage journal and exclusive `graphics_operation_send_intent` file are fsynced **before** the SendCommand attempt. A known CommandId is retained in a separate fsynced receipt and can be inspected without another send. On lost acknowledgement, restart, ordinary duplicate, incomplete local intent or crash, the operation is treated as uncertain and not automatically resubmitted. This protects against ordinary retries and failures, not malicious rollback of the trusted Host administrator.

## Actual installation inputs

The direct Task C runtime requires **two component repositories**, `host-install` and `host-deploy`. Root-control PR #47 also contains a source-tested `task_c_trusted_host` journal demonstration, but **it is not selected or installed as a runtime dependency**; the gateway already has the persistent journal it needs. Do not reintroduce root-control's unrelated component-development `box-control` and `image-build` dependency pins merely for this installation.

The normal `host-install-task-c` CLI accepts `--plan`, `--stage`, or optional read-only `--inspect-state`. For plan/stage, supply `--host-deploy-source`, `--host-install-source` and `--python`. The installer uses a normal local venv `/opt/zog/task-c/venv`; ordinary `pip install` resolves the selected host-deploy dependencies and an unconditional `pip check` verifies the installed distribution set. It verifies the actual installed gateway module imports before staging the unit.

The only staged systemd unit is **`zog-task-c-gateway.service`**, disabled by default and without an `[Install]` section. It runs the existing `host-deploy-gateway` entrypoint as root, using the existing root-backed `/var/lib/host-deploy-gateway` directory (0700). No new volume, external authority, S3 credential, trust service, owner socket or separate journal directory is staged.

## Native staging outline — Work only

Use the **accepted detached Git commit IDs**, not moving branches. The selected reviewed candidate sources are in [host-install PR #35](https://github.com/zog144/host-install/pull/35) and [host-deploy PR #30](https://github.com/zog144/host-deploy/pull/30). Work must record the actual checkout revision in its evidence; older examples are not permanent production pins. Do not overwrite a currently running gateway.

```sh
set -euo pipefail
SRC=/opt/zog/task-c/sources
sudo install -d -m 0755 /opt/zog /opt/zog/task-c "$SRC"

# Skip cloning if these reviewed source checkouts are already present.
sudo git clone https://github.com/zog144/host-install.git "$SRC/host-install"
sudo git clone https://github.com/zog144/host-deploy.git "$SRC/host-deploy"
# Immutable source selections that passed the current exact-head CI; Work
# must re-check installed bytes and ensure these commits remain approved.
sudo git -C "$SRC/host-install" checkout --detach 0b52eb50073477a1de8504009004eb27d2caa54b
sudo git -C "$SRC/host-deploy" checkout --detach a28df09b070d81ae3369ade969302f52d0a2d749
sudo git -C "$SRC/host-install" rev-parse HEAD
sudo git -C "$SRC/host-deploy" rev-parse HEAD

# Work must verify this retained Python selection is still installed and usable.
PYTHON=/opt/host-discover/candidates/retained-legacy-3fd8bd0-3d94f34-20261109/venv/bin/python3.12
sudo test -x "$PYTHON"
sudo "$PYTHON" -m venv /opt/zog/task-c/installer-venv
sudo /opt/zog/task-c/installer-venv/bin/python -m pip install --no-cache-dir "$SRC/host-install"
INSTALLER=/opt/zog/task-c/installer-venv/bin/host-install-task-c

sudo "$INSTALLER" --plan \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

# Software and one disabled unit only; no SendCommand, activation or AWS mutation.
sudo "$INSTALLER" --stage \
  --host-deploy-source "$SRC/host-deploy" \
  --host-install-source "$SRC/host-install" \
  --python "$PYTHON"

sudo /opt/zog/task-c/venv/bin/python -m pip check
sudo /opt/zog/task-c/venv/bin/python -I -c \
  'import zog.host_deploy.gateway.generic_pipeline; import zog.host_deploy.gateway.trusted_host_submission; import zog.host_deploy.gateway.graphics_operation_send_intent'
sudo systemctl cat zog-task-c-gateway.service
sudo systemctl is-active zog-task-c-gateway.service || true

# Only after canonical /state exists, optionally inspect the actual Host identity:
# sudo "$INSTALLER" --inspect-state
```

This is a **source-to-Work handoff**, not an instruction to run these commands in Regular. The installer never starts/enables the unit. Its success is not a permission to issue an SSM command.

## Native acceptance and retained journal custody

Work must reconcile the current registry gateway's service identity first. The old service may use `DynamicUser`, whereas the new disabled unit uses root. Preserve every existing SQS request, original operation ID, `generic-operation-send-intents` file, CommandId sidecar and recovery record. Never start two competing gateway instances, reset journals or silently replace an active service.

Verify the installed application, root directory ownership, selected Host IAM permissions, actual compiler instance/account/region, server-generated `AWS-RunShellScript` constraints, task catalogue source and original GitHub authorization. The gateway's queue consumer does not automatically submit a Fonts build simply by starting: the selected reviewed generic advance operation must be invoked separately.

Native acceptance must cover successful CommandId capture, read-only inspection, ordinary duplicate and lost-ack denial, cancellation and reboot behavior, and the retained compiler resource admission for the first Fonts operation. **No Task C native SSM command or first Fonts job is authorized by this document.**

## Source evidence

- [host-deploy PR #30](https://github.com/zog144/host-deploy/pull/30): direct gateway, original-request validation, existing local send-intent journal and single SSM SDK attempt; Python 3.12/3.13 source tests.
- [host-install PR #35](https://github.com/zog144/host-install/pull/35): disposable normal two-repository installation, `pip check`, installed runtime imports, one disabled unit and exact cross-repository source compatibility.
- [root-control PR #47](https://github.com/zog144/root-control/pull/47): source-only local journal behavior and disposition of historical S3/signed owner modules. **Not an extra native requirement.**

**Disposition:** selected source path replaces S3 and cryptographic establishment; native installation, IAM verification and live SSM **HOLD**.
