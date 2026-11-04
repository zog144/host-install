# Protected graphical owner native installation candidate — 2026-11-04

Follows [preflight gate](https://github.com/zog144/know-file/blob/451099be64433a013c4c0e76a3dbf335825c0f39/root-control/verification/graphical-owner-admission-preflight-2026-11-04/README.md). Exact companion selected root-control draft PR #33 current source; no accepted production pin changed.

## Units and privileges

Disabled `zog-graphical-owner.socket`: `AF_UNIX SOCK_SEQPACKET`, root socket owner, `zog-graphical-client` group, 0660, expected peer UID/GID verified by root-control using kernel `SO_PEERCRED`. No systemd `[Install]` block or automatic activation.

Disabled `zog-graphical-owner.service`: separate root-only protected service, installed root-control executable, no caller-selectable argv config, `NoNewPrivileges`, strict read-only system except selected protected owner ledger and checkpoint mounts. Uses systemd `LoadCredential` from an independent protected source; short-lived owner-only AWS credentials never enter gateway argv/env/files, and SDK cannot use IMDS or the default credential chain. A real issuer/rotation/revocation path for these session credentials must be authorized independently.

Installed ledger and checkpoint require separate dedicated root-owned mounts distinct from gateway STATE. Root-control source has fsynced irreversible checkpoint-before-local claim, original ID/approval verification, same lock revocation, no second send after lost ACK. This is separately durable relative gateway storage, **not** proof against coherent rollback of both protected stores. A nonrollbackable highwater authority must be independently installed and attested before native acceptance.

Gateway IAM must explicitly deny `ssm:SendCommand`, `sts:AssumeRole` and `iam:PassRole`; the owner's SSM principal must be disjoint and held in the dedicated LoadCredential source. Merely generating this denial JSON is not applying IAM. The actual gateway also needs IMDS and alternate SDK credential denial.

## Native hold

This source module deliberately rejects fabricated success for installation, exact source RECORD, current boot/STATE/mounts, signer custody, IAM authorization, highwater, native socket enabled or SSM admitted. Work must attest source and RECORD, independent authority, real UID/GID, protected mount provenance, systemd and kernel credentials, source+destination AWS STS identity, actual gateway SendCommand denial and owner-only original acceptance, then test interruption/reboot and SSM. No service or key changes were made by this PR.
