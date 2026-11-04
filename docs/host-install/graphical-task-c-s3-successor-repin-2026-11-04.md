# Task C protected stream owner S3 successor — host-install source repin (2026-11-04)

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

**Selected source, not native acceptance:** root-control draft PR #39 exact `b5ac7bddc8e2320901dd93897d43cb03441d2027`, stacked on PR #38 S3 checkpoint and PR #36 no-SDK-retry; companion host-deploy PR #26 exact `c46c6b5819b1f4496de1b860aa2785812244493e`. The latter remains a **v1 gateway**, which cannot accept the root's signed-v2 result. Its fail-closed denial is retained and explicitly tested; no silent protocol activation.

Root-control now selects operator-signed original GitHub operation mapping plus **separately issuer-signed original-event evidence**; distinct preflight and stage irrecoverable claims, external S3 genesis and append-only history, a fixed single-attempt SSM sender with read-only original GetCommandInvocation result checks, and nonce/current-identity-bound v2 signed replies. Neither an SSM claim nor `stage-succeeded` means immutable compilation output is accepted.

## This source-only installer successor

- Repins exactly the PR39 root modules and host-deploy PR26, including the selected `graphical_task_c_origin`, `graphical_task_c_runtime`, `graphical_task_c_native`, and `graphical_s3_checkpoint`. Never select the alternative SQLite or old seqpacket service.
- Replaces the previous local-file checkpoint *selection* with externally pinned S3 bucket, prefix, account, genesis SHA and **checkpoint-role ARN**. Runtime must never auto-create genesis or accept file-only rollback safety.
- Adds a second distinct `LoadCredential` entry for restricted checkpoint role (S3), while retaining owner-only separate SSM role session. The actual SSM role is still a **required uninstalled/unverified principal**. Neither session may come from gateway env, IMDS or shared Host role.
- Requires exact Host/installation/STATE, gateway executable and cgroup witness, installed operator/issuer key pins, original GitHub receipt, private observation signer and immutable root-source/RECORD manifest. These are explicit offline input requirements, not fabricated acceptance.
- Keeps one disabled `AF_UNIX SOCK_STREAM` `/run/zog/graphical-operation-owner.sock` unit and deletes the obsolete local checkpoint mount dependency from that candidate. No [Install] directive or service activation, no IAM operation.
- Rejects any manifest boolean claiming native pass. Actual Work/native independent evidence must verify policy, retention, installed package bytes, genuine original operator/issuer, S3 role and distinct SSM role custody, gateway credential/IMDS/STS denial and exact SSM result attribution.

[Host-install Work admission evidence](https://github.com/zog144/know-file/blob/c01b1bedf73b0dd7cc25492abec0e6fe7826577a/host-install/verification/graphical-owner-install-admission-2026-11-04/README.md) establishes **restricted checkpoint policy component checks only**. It does not prove effective gateway SendCommand isolation or a working owner SSM principal. The existing shared Host role is unchanged.

**Native NO-GO:** root-control `NATIVE_TASK_C_SEND_ADMISSION_IMPLEMENTED=False` still denies before any socket/credential. Do not toggle the flag as a substitute for Work admission. Native host-install installation, authority key/STATE custody, independent S3 genesis/retention, owner-only SSM principal, gateway denial, source/wheel/RECORD pin, signed-v2 client selection, kill/replay/revoke/reboot and the first positive original command require separate native Work execution and authorization.
