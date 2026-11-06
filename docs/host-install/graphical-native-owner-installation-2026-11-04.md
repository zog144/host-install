# Protected graphical owner native installation candidate — 2026-11-04

Follows [preflight gate](https://github.com/zog144/know-file/blob/451099be64433a013c4c0e76a3dbf335825c0f39/root-control/verification/graphical-owner-admission-preflight-2026-11-04/README.md). Exact companion selected root-control draft PR #33 current source; no accepted production pin changed.

## Units and privileges

Disabled `zog-graphical-owner.socket`: `AF_UNIX SOCK_SEQPACKET`, root socket owner, `zog-graphical-client` group, 0660, expected peer UID/GID verified by root-control using kernel `SO_PEERCRED`. No systemd `[Install]` block or automatic activation.

Disabled `zog-graphical-owner.service`: separate root-only protected service, installed root-control executable, no caller-selectable argv config, `NoNewPrivileges`, strict read-only system except selected protected owner ledger and checkpoint mounts. Uses systemd `LoadCredential` from an independent protected source; short-lived owner-only AWS credentials never enter gateway argv/env/files, and SDK cannot use IMDS or the default credential chain. A real issuer/rotation/revocation path for these session credentials must be authorized independently.

Installed ledger and checkpoint require separate dedicated root-owned mounts distinct from gateway STATE. Root-control source has fsynced irreversible checkpoint-before-local claim, original ID/approval verification, same lock revocation, no second send after lost ACK. This is separately durable relative gateway storage, **not** proof against coherent rollback of both protected stores. A nonrollbackable highwater authority must be independently installed and attested before native acceptance.

Selected shared-host model: the gateway *program's normal graphical source route* must pass through the authenticated owner, its original claims and revocation checks, then its pinned SSM session. The owner's explicitly selected SSM and checkpoint sessions remain distinct logical roles and may live on the same trusted administrative Host. The sample gateway-service IAM deny (`ssm:SendCommand`, `sts:AssumeRole`, `iam:PassRole`) and IMDS restrictions are optional defense in depth for a separately credentialed service principal—not a requirement to prove the trusted Host administrator cannot access SSM. Merely generating the sample policy is never actual IAM evidence. GitHub Actions OIDC is a separate external SQS-dispatch-only principal and must not acquire owner SSM capabilities.

## Native hold

This source module deliberately rejects fabricated success for installation, exact source RECORD, current boot/STATE/mounts, signer custody, IAM authorization, highwater, native socket enabled or SSM admitted. Work must attest source and RECORD, genuine operator/event authority, real UID/GID and socket peer, protected mount provenance, systemd credential selection, original S3 history and exact selected owner AWS role before testing interruption/reboot and any separately approved SSM. When separate gateway service credentials are deployed, effective gateway SendCommand/STS/IMDS denial is useful additional evidence, not a mandatory claim of root-admin isolation. The normal gateway→owner route is mandatory. Do not require proof that an administrator of this trusted Host cannot use its own authorized SSM authority. No service or key changes were made by this PR.


The three-owner exact trust model is recorded in [graphical-task-c-shared-host-trust-v1.json](../../graphical-task-c-shared-host-trust-v1.json). These edits alter native acceptance interpretation only; owner source and installed unit bytes, exact original checkpoint and immutable production pins have not changed.
