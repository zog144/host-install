# Task C v4 root-backed SSM owner and broker — recovered source-to-native handoff

2026-11-11. **Regular source correction; native admission remains HOLD.**

## Approved replacement for the old two-EBS-device requirement

The selected Task C v4 root-backed mode places the protected ledger and authority under the existing trusted `host-registry` root filesystem:

- `/var/lib/zog-owner-ledger`
- `/var/lib/zog-owner-authority`

No extra EBS volume, distinct mount, filesystem UUID pair or separately mounted filesystem is required for **v4**. Both directories must still be exact protected root-owned, non-symlink, mode-0700, installation-bound directories with signed identity digests and verified ancestors. The signed installer commit separately binds the approved root filesystem UUID, directory identities, service hashes, storage scope and operator-signed establishment. Root-backed v4 must never reuse a v3 two-mount receipt as approval; v3 remains separately selected and unchanged.

This correction does not change the compiler Host, its 30+2 GiB Fonts reservation, the ordinary standalone/root-directory `/state` installation contract, or the trusted shared-Host administrator boundary. It does not require any new registrar or Command Center dependency for local boot.

## Selected source and evidence

- **root-control PR #47:** `f2c765cc38a666b60a09729cd16ab63102ca1dd5`. The v4 root-backed storage contract, signed establishment and installed native selector, direct host-install STATE readback, independent S3 checkpoint, fixed owner SSM sender and broker authority source are on this head. Root-control v3/v4 integration workflow 42915040781 passed Python 3.12/3.13.
- **host-deploy PR #30 source pin:** `7cf4dd4a5e1967035d724462ba3ddff10f8fbefa`. The broker IPC now requires fresh protected backend readback for **both** signed v3 mount and v4 root-backed authority schemas; unknown future authority schemas deny, instead of falling into the legacy bypass. Regression tests cover v3/v4 success, missing observer and unknown schema. Source workflows 43028559132 and 43028559305 passed Python 3.12/3.13.
- **host-install PR #35 source pin:** `68785adc4d859d5f0d7d88a367515e34e0cf2952`. Its v4 disabled installation reviewer pins the corrected host-deploy source and root-control source. The two exact source workflows `graphical-v3-three-owner-install-freeze.yml` and `graphical-task-c-root-backed-v4.yml` select those immutable companions. Its v4 signer/RECORD and unit review remains disabled by construction.
- **host-deploy workflow-only follow-up:** `10ca60b1465ea31d107070a786ad0c386cc7af64` updates its companion host-install exact pin to `68785adc...`; no broker source bytes changed in that follow-up.

The **source** selection is the immutable code commit above, not a mutable PR branch; the workflows verify exact companion Git heads. Check the final action conclusions at the specified branch heads before source approval. This handoff is not an attestation of installed wheel files, RECORD hashes, Host identity, real IAM policies or S3 retention.

## External S3 operation-claim authority is mandatory

The selected installation-scoped `S3InstallationCheckpoint` replays a stable genesis and hash-linked event chain. Every SSM send requires a matching operator-approved operation ID/request digest, then an S3 conditional `PutObject(IfNoneMatch="*")` to the next sequence key before the single fixed SSM SendCommand attempt. The same conditional slot serializes a racing claim versus revocation; collision, timeout, response loss, bad readback or inconsistent chain holds, **without retry**. Same-scope revocation blocks a later claim; already-claimed send rights cannot be recovered from deleted, restored or altered local files.

This seriality depends on genuine S3 conditional write semantics and correct effective AWS permissions. Native Work must establish immutable history, object retention/Object Lock as approved, an independently protected retained anchor/high-water witness, and deny owner application credentials the ability to delete/overwrite or reset claims. No claim of resistance to a fully trusted AWS administrator is made. A local directory, or source-only fake S3 client, cannot stand in for accepted S3 authority.

The installed broker must have GetObject-only S3 rights plus its distinct signing credential, while the protected owner alone holds its SSM and checkpoint-writer sessions. GitHub OIDC remains SQS-only; the gateway has no direct SSM fallback.

## Relevant regression acceptance

- Synthetic source regressions test duplicate/rollback, request substitution, role/scope and commit swaps, conditional-creation conflict, claim/revoke ordering, crash/lost-ack uncertainty and legacy v3 downgrades. Rerun selected root-control, host-install and host-deploy suites at exact heads on Python 3.12 and 3.13.
- New broker regression: a root-backed **v4** authority is now subject to the same fresh per-request backend verification as v3. An unknown schema, no verifier or failed verification cannot produce a broker signature.
- Source-fixed systemd units still use historical `zog-graphical-*` **service names, sockets and interpreter paths**; these are installation ABI names, not the new root-backed data storage paths. Do not rename them as part of this focused storage change without reviewing all callers.
- Root-backed systemd services have no `[Install]` enablement; owner/broker depend on the read-only root-backed storage verifier and have no `RequiresMountsFor` physical-disk requirement. The verifier must check actual approved directories, signed installed source and live local STATE through the protected native host reader.

## Native Work acceptance — still unperformed

1. Read-only authenticate the existing retained `host-registry` Host key, installation/STATE identity and real root-backed directory identities; do not relocate its registry beacon just to satisfy removed EBS prerequisites.
2. Verify the original operator-signed storage establishment, immutable installer commit, pinned signer custody and actual **installed** root-control / host-deploy / host-install wheel and PEP 427 RECORD bytes, selected units/sockets/interpreters and grants.
3. Verify the existing selected S3 account/bucket/prefix/genesis, atomic conditional-create support, retention/Object Lock, external anchor/high-water, writer vs GetObject-only IAM effective permissions and cancellation/uncertain-ACK behavior; no local-file substitute.
4. Verify kernel-authenticated gateway IPC and actual gateway principal's **direct SSM denial**, separately from trusted Host admin capabilities.
5. Perform bounded native duplicate, crash/reboot, substitution, revocation and lost-ack proof. Require explicit native GO before enabling owner/broker/gateway trust pin or submitting the first Fonts job.

**Disposition: source candidate with corrected v4 broker boundary; native HOLD.** No EBS volumes, host migrations, signed approvals, S3 genesis, IAM mutation, Fonts submission, SQS dispatch or SSM send are authorized by this document.