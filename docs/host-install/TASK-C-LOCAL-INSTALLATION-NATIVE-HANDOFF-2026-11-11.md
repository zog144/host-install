# Task C trusted-Host direct SSM — one-service installation handoff

2026-11-11 · Source review candidate only · **No native SSM command or service activation**

## Selected architecture

The November 11 decision supersedes the Task C dedicated S3 and signed-establishment v3/v4 designs. The trusted `host-registry` administrator, installed gateway process and ordinary root filesystem are within the trust boundary. No independent anti-rollback service, external S3 history, operator/installer signer, external anchor, mounted disk or separate AWS reader/writer role is required for the newly selected Task C local gateway.

**Only one Task C submission service is selected:** `zog-task-c-gateway.service`, running the existing `host-deploy-gateway` command as root in its ordinary application venv, under the existing Host AWS IAM role. This intentionally does **not** install a new `task_c_local_service`, a separate trust daemon or any owner/broker sockets. Legacy experimental v3/v4 source modules may remain in repositories for historical review but are unselected and must not be installed as active Task C senders.

The selected gateway `generic_pipeline.advance` validates an admitted GitHub-request-derived image-build binding, current compiler target, frozen task/source, recipe snapshot readback and generated fixed remote script. It fsyncs the per-request stage and an **exclusive local send-intent** before one `Host.submit_command` (`AWS-RunShellScript`). It retains the returned CommandId in a separate fsynced sidecar. Missing acknowledgement, changed or partial intent, cancellation and restart never permit an automatic resend. Read-only `Host.inspect_command` reconciles known CommandIds; explicit local uncertainty remains uncertain.

The gateway storage directory is `/var/lib/host-deploy-gateway` (mode 0700, root-owned in this native selection). The existing `generic-operation-send-intents` under it is ordinary local persistent state. A second local journal or new `/var/lib/zog-task-c` volume is **not** required. This is not an independent anti-rollback promise against the trusted Host administrator. Retain existing gateway request and command files across the change.

## Selected source installer and disabled systemd unit

- Installer: `zog.host_install.task_c_local_install`, console command `host-install-task-c`.
- Inputs: ordinary checked-out host-install, host-deploy and root-control source trees, and a selected installed Python 3.12+ executable.
- Installation: normal application `/opt/zog/task-c/venv`, `pip install` from those source trees, unconditional `pip check`, and imports of the actual `generic_pipeline`, `trusted_host_submission`, `graphics_operation_send_intent` and optional root-control local journal module. No signed artifact or new operator key is generated.
- Disabled unit: `/etc/systemd/system/zog-task-c-gateway.service`. The unit selects `User=root`, `Group=root`, `StateDirectory=host-deploy-gateway`, `StateDirectoryMode=0700`, `ReadWritePaths=/var/lib/host-deploy-gateway`, `ProtectSystem=strict`, and the existing `host-deploy-gateway --state-directory ... run` entry point. There is no `[Install]` section. Installer does not start/enable the service.
- Legacy `zog-task-c-owner*` and `zog-task-c-trust*` units are **not** part of this installation. The prior source-only handoff that requested nonexistent `task_c_local_service` and `task_c_local_trust_daemon` modules is superseded by this document.

If the deployed gateway currently runs as `DynamicUser`, native Work must audit the existing request journal and retained identity, stop the old unit through normal service change control, and reconcile directory ownership **without deleting or resetting send intents or command records**. Do not run the old and new gateways concurrently. The source staging CLI does not perform the service cutover.

## Native handoff (Work only)

1. Read existing `host-registry` identity, gateway service and installed source versions. Confirm the compiler Host target and established AWS role/instance-profile permissions. No registrar or new signing keys.
2. Pin exact Git revisions, install normal packages and run `pip check`. Verify new root-owned local gateway state directories and retain the existing send-intent/history files. No additional EBS disk or S3 resource.
3. Stage disabled `zog-task-c-gateway.service` only. Do not enable it, run a second gateway, activate old owner/trust services or send SSM in this source operation.
4. After separate native approval, prove the installed gateway is the sole Task C sender, uses the selected Host AWS identity and the fixed SSM document, cannot redirect to a foreign compiler target or arbitrary document, and can inspect known commands.
5. Run bounded duplicate, crash/lost-ack, cancellation and reboot acceptance. A claim with no CommandId must remain uncertain; manual review is permitted but **no automatic retry**. Only then consider a separately authorized first Fonts submission.

**Disposition:** source-only normal installer and direct gateway mode. The old v3/v4 signed owner/broker/S3 architecture is not a prerequisite or approved runtime. Native installation/cutover remains **HOLD**.
