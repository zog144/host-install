# Task C protected root-control journal — supported installation path

November 19, 2026 · host-install Regular · source-only installation proposal

## Selected source and ordinary runtime

This change extends the existing **single Gateway** installer,
`host-install-task-c --plan|--stage`; it does not restore the historical
Task C signed-storage/S3/broker/owner-service design. The source selects:

- host-install combined Task C / first Fonts / issuer source via the reviewed
  PR branch (this proposed installer is layered on host-install PR #42);
- host-deploy [PR #51](https://github.com/zog144/host-deploy/pull/51)
  `dc8ab86897ad6652b7f9da42e587e84171c6bb64`, which provides
  the selected protected root-owner `dispatch-submit` and denies direct
  SSM fallback;
- root-control [PR #53](https://github.com/zog144/root-control/pull/53)
  `b655b0a2b2ba7abb5fddbdaadae01ef6e34bcb56`, which includes
  the combined issuer + Task C + inherited-build controller with the
  systemd 252 finite-build compatibility correction;
- box-control [PR #21](https://github.com/zog144/box-control/pull/21)
  `c886e7a90bb4ea74e771a6c5dcefaa2069539ec7`, the actual
  root-control development distribution's `box-control==0.1.0` dependency;
- image-build [PR #24](https://github.com/zog144/image-build/pull/24)
  `77a5e3c13e1c41582b3278941fb4b1f5e2f16678`, its
  `image-build==0.2.0.dev5` dependency.

The root-control selection is verified against its **exact Git HEAD** and
the `src/zog/root_control/task_c_trusted_host.py` original Git blob
`de63bac2261d639eb9f1177ef92651bbd3fcb750`.
That module defines the actual `LocalTaskCJournal`, its
`DEFAULT_DIRECTORY=/var/lib/zog-task-c/operations`, once-only
fsynced intent/CommandId, cancellation, lost-reply and replay behavior.
The installer now requires the explicit `--root-control-source`,
`--box-control-source`, and `--image-build-source` alongside the original
host-install and host-deploy sources. The selected box-control package
source is inside the Git checkout's `box-control/` subdirectory;
the other four use their checkout roots. All five component distributions
are installed **together**, using normal pip dependency resolution, into
the **same Task C Python venv** `/opt/zog/task-c/venv`. It runs ordinary `pip check`, imports all
selected Gateway modules and the real root-control module via the installed
isolated venv Python, verifies the installed journal's **same original Git
blob** and exact default directory, and refuses missing/dependency-incomplete
packages before it publishes the service. Do not use a separate Python
environment with an inaccessible `LocalTaskCJournal`, repackage the journal
into host-deploy under another name, or bypass the checked distribution.

Root-control's development `pyproject.toml` declares
`box-control==0.1.0`, `image-build==0.2.0.dev5` and
`dbus-next==0.2.3`. The installer now takes the **exact original
box-control and image-build Git checkouts** as ordinary local source
inputs and checks their reviewed HEADs and unchanged tracked files.
This resolves the previously observed real pip failure
`No matching distribution found for box-control==0.1.0` without
`--no-deps`, editing Python metadata, forging a wheel or disabling
`pip check`. [Original local installation CI #44541320071](https://github.com/zog144/host-install/actions/runs/44541320071)
passed a complete actual disposable five-repository pip installation and
`pip check` under the selected Python 3.12. Work must still compare actual
native wheel/RECORD and installer results to the reviewed candidate; tests
are not a live installed-byte acceptance. A future approved aggregate
`zog` package can replace the component-development distribution selection
only through a separate reviewed compatible installation path.

## Protected root-owned filesystem operation (before runtime)

Only the privileged installer provisions the durable journal:

```
/var/lib/zog-task-c/operations
```

Its final directory must be a **real directory**, owned `root:root`,
mode **0700**, on the trusted Host's ordinary root filesystem.
`/var/lib/zog-task-c` is root-owned and not group/world-writable
(a fresh parent is mode 0700). Existing valid directories and **all**
retained files are left byte-for-byte unchanged; an existing mode 0755,
wrong UID/GID, symlink, regular file, unsafe ancestor or foreign path
causes an error. The installation does **not** repair by `chmod`,
`chown`, following a symlink, moving files, deleting an operation or
creating a separate journal authority.

`task_c_journal_directory.ensure_operations` uses relative
`openat`-style directory-descriptor traversal with
`O_DIRECTORY|O_NOFOLLOW`; it checks actual opened `fstat` UID/GID,
directory type and permissions at every level and fsyncs the new entries.
It creates only absent trusted directory components. It does **not**
initialize `LocalTaskCJournal` during installation, and does not create
its `.lock` or any `<operation>.intent.json`. Only root-control will
open the preprovisioned journal during an independently authorized runtime
operation.

The installed static `zog-task-c-gateway.service` remains **without
an `[Install]` section**. Its existing `ProtectSystem=strict` now permits
write access to `/var/lib/host-deploy-gateway` and to this exact precreated
root-control directory, without granting access elsewhere.
The unit continues to use the current process UID **root**, not
`DynamicUser`, an alternate UID or an invented worker account. Native
staging checks `systemctl is-active --quiet` **before** modifying the
root, and again after `daemon-reload`; a running Gateway or an uncertain
service state is HOLD. There is no `systemctl start`, `enable`,
`restart`, socket activation, AWS submission, source build or SSM call.

## Executable native Work handoff — stage only after source approval

1. Confirm Gateway remains stopped and preserve its original service,
   invocation, pending requests, durable operation IDs and existing journal.
   Do not disable a running production process as a side effect of this
   installer; first arrange a reviewed maintenance window. Inspect the
   selected root-control, host-deploy and host-install exact source commits
   and their installed candidate bytes. Do not install from moving branches.
2. Confirm the same interpreter/venv and normal dependency/wheel closure
   are available; Work owns ordinary package/RECORD and installed-file
   verification, not source-only CI.
3. Use the reviewed CLI, with operator-selected exact source paths:

```sh
set -euo pipefail
HOST_INSTALL_SOURCE=/opt/zog/task-c/sources/host-install
HOST_DEPLOY_SOURCE=/opt/zog/task-c/sources/host-deploy
ROOT_CONTROL_SOURCE=/opt/zog/task-c/sources/root-control
BOX_CONTROL_SOURCE=/opt/zog/task-c/sources/box-control/box-control
IMAGE_BUILD_SOURCE=/opt/zog/task-c/sources/image-build
PYTHON=/opt/zog/task-c/installer-venv/bin/python3.12
INSTALLER=/opt/zog/task-c/installer-venv/bin/host-install-task-c

# Sources and Python must already be selected and attested.
sudo "$INSTALLER" --plan \
  --host-install-source "$HOST_INSTALL_SOURCE" \
  --host-deploy-source "$HOST_DEPLOY_SOURCE" \
  --root-control-source "$ROOT_CONTROL_SOURCE" \
  --box-control-source "$BOX_CONTROL_SOURCE" \
  --image-build-source "$IMAGE_BUILD_SOURCE" \
  --python "$PYTHON"

# Root-control journal setup is part of this one staging transaction.
# This action does not enable/start the Gateway.
sudo "$INSTALLER" --stage \
  --host-install-source "$HOST_INSTALL_SOURCE" \
  --host-deploy-source "$HOST_DEPLOY_SOURCE" \
  --root-control-source "$ROOT_CONTROL_SOURCE" \
  --box-control-source "$BOX_CONTROL_SOURCE" \
  --image-build-source "$IMAGE_BUILD_SOURCE" \
  --python "$PYTHON"

sudo stat -c '%U:%G %a %F %n' /var/lib/zog-task-c/operations
sudo /opt/zog/task-c/venv/bin/python -m pip check
sudo /opt/zog/task-c/venv/bin/python -I -c \
  'from zog.root_control.task_c_trusted_host import LocalTaskCJournal, DEFAULT_DIRECTORY; assert DEFAULT_DIRECTORY=="/var/lib/zog-task-c/operations"'
sudo systemctl cat zog-task-c-gateway.service
sudo systemctl is-active --quiet zog-task-c-gateway.service && exit 1 || :
```

The actual command must also read back the selected root-control module's
installed **Git blob, wheel RECORD entry/hash/size, actual package version,
interpreter, source commit and root ownership**. Compare against the
accepted source before recognizing staging success. Inspect existing
`/var/lib/host-deploy-gateway` separately and preserve its historical
send-intent journal, especially uncertain or dispatched operations. A new
root-control directory never grants permission to resend an old request.

4. After source and actual installed-byte review, Work may inspect
   `LocalTaskCJournal` in read-only/controlled fashion and verify root-only
   access; opening the journal itself creates a protected `.lock`, so treat
   that as a separate explicitly approved native observation. A root-owned
   owner send and Gateway activation require **their own** authorization.
   No direct `Host.submit_command` SSM fallback; no GitHub issue/SQS
   forwarding during this installation acceptance.

## Source tests and remaining boundary

`tests/test_task_c_journal_directory.py` runs as root on disposable
filesystems: fresh setup, idempotency with retained operation file,
wrong owner/GID, wrong mode, symlinked parent/leaf, foreign file,
unsafe parent and nonroot installation root. It proves no chmod/chown
adoption or journal content replacement. The original
`tests/test_task_c_local_install.py` covers the updated five-repository
source/venv plan, root staging, missing module, installed import check,
one still-disabled Gateway unit, rejected wrong selection and no SSM.
Dedicated CI also checks the **actual** root-control, box-control and
image-build Git revisions plus the original journal Git blob and instantiates the real journal only against a
disposable pre-created root.

**Status:** source-tested installation path; [protected root
journal CI #44541320104](https://github.com/zog144/host-install/actions/runs/44541320104)
passed Python 3.12 and 3.13; the original [actual normal-install
workflow #44541320071](https://github.com/zog144/host-install/actions/runs/44541320071)
passed the full venv installation, `pip check` and staging on its
disposable root. The old S3/signed-v4 CI remains an unselected historical
failure, not a Task C local-installation criterion. Native installation,
approved wheel/RECORD readback, original Host state, Gateway activation,
AWS/SSM and Fonts compilation remain separate Work gates.
