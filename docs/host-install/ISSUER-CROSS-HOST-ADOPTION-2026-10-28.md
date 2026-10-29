# Unified protected HTTPS issuer credential receiver — host adoption

**2026-10-29 — SOURCE ACCEPTANCE CONTRACT; native credential delivery remains NO-GO.**

This supersedes the SSH-specific receiver/adoption design formerly carried by host-install PR #5 and root-control PR #13. The receiving side is an independently Enrolled Host. The Credential Authority is the separately approved Command-Center Host. No SSH identity, `known_hosts`, sshd Match User mapping, forced command, transport account, PTY or SSH broker socket is part of the supported receiver.

## Exact reviewed source tuple

- root-control PR #16 source: `d85aa7feb8a4db28249c5edde958d3d006e5e009`
  - `zog.root_control.issuer_https_receiver`: Git blob `4d3d11a874203336cb5bf386e78af20e6772d21f`
  - `zog.root_control.issuer_receipt_common`: Git blob `4c1fe6b37c95d3cd038aba0c8a0df3b71a55d13f`
  - retired `zog.root_control.issuer_cross_host` tombstone: Git blob `a1631150dd7df2cf10c36c953a9fcd6af9a3847e`
- host-deploy PR #6 source: `9ed396c08aa5be30bd514630838b8a4baf2e2087`
  - `zog.host_deploy.certificate_cross_host_admission`: Git blob `592983a3d299aaf1228248157fdea3908680f097`
  - `zog.host_deploy.certificate_cloudflare_https_consumer`: Git blob `cf771f8625e329e557939a1f268517c52faaf2de`
- canonical protocol owner: host-identify 0.3.5 source `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`
  - `zog.host_identify.credential_delivery`: Git blob `02332127defe565e00e398b71ada50d5c2bdd4d6`
- station-access PR #10 canonical interoperability source: `51295bd7a458a621ccbf33eab03da43ba84ce71a`
  - public credential-delivery vector: Git blob `227a043ffbf88489d2c8b65790058ef870e5c1bc`
  - unchanged shared interoperability test: Git blob `ca1701206507dbaaeccef049c930fac8ef5368f9`

The station files are byte-for-byte interoperability evidence only; they are not installed on the receiving Host and cannot become local authority by being checked out in CI. The receiving Host separately attests the installed canonical host-identify credential-delivery module because root-control executes that protocol implementation.

## Retained independent authority

The receiver preserves the already accepted Host UUID, installation UUID, STATE volume UUID, HostIdentity fingerprint, managed registry, independent station assignment signer pin, signed host-discover authority, host-install second owner ledger, certificate owner receipt, selected certificate-to-nginx policy, exact issuer UID/GID, original grant/storage IDs, immutable software view, credential UUID/revision and protected issuer storage.

The receiver profile is root-owned and purpose-scoped to `issuer-cloudflare-dns01`. It binds the HTTPS origin and independently installed TLS CA digest, station signer-pin digest, owner receipt digest, exact Host/install/STATE/registry, assignment/revision/receipt, consumer UID, issuer grant/storage and credential revision. The retained grant/storage values are the existing 32-lowerhex IDs; the HTTPS migration must not reinterpret or replace them as UUIDs.

The station authorization projection remains useful nonsecret authority evidence, but the receiving Host no longer requires the old same-host vault-reader peer UID/socket file merely to inspect it. The HTTPS receiver reads and validates the protected projection directly against the retained root approval. The Command-Center keeps its own local vault reader and broker isolation independently.

## Installed-byte and RECORD admission

`issuer_cross_host_adoption.attest_installed` requires root, the exact selected interpreter, no inherited `PYTHONPATH` or `PYTHONHOME`, protected one-link source and wheel-RECORD paths, exact Git blobs and exact RECORD SHA-256 entries. The receiving Host attests all four executable decision modules: the root-control HTTPS receiver and common protected-file helper plus host-deploy HTTPS owner admission and selected Cloudflare consumer.

This source migration does not silently repin the separately accepted certificate-controller root-control installation. Any actual receiver installation must preserve prior installation identities and independently prove the new reviewed bytes in the installed aggregate/standalone distribution.

## Transport-independent security checks retained

- exact current Host/installation/STATE/registry and HostIdentity fingerprint;
- independent TLS trust and station signer authority;
- current signed assignment, owner receipt and monotonic second owner ledger;
- exact purpose, consumer UID, credential revision, issuer grant/storage and policy;
- durable one-time request identity before outbound delivery;
- replay, rollback, same-revision substitution, stale/revoked/expired authority and source drift rejection;
- before/after authority and installed issuer recheck;
- bounded secret-free errors and audit;
- final secret installation only through the existing anonymous-FD `issuer_credentials.install_from_fd(expected_authorization_id=...)` path, retaining original issuer UID/GID, 0700 storage and atomic 0600 Cloudflare file semantics.

No generic root-control remote-command RPC is introduced.

## Canonical interoperability status

The receiver no longer carries a private HTTPS wire contract. Root-control PR #16 consumes the single canonical `zog.host_identify.credential_delivery` v0.3.5 protocol and is tested against station-access PR #10's exact public vectors. The fixed endpoints are the canonical credential-delivery v1 request, receipt and cancellation endpoints; authorization, request, delivery, installation receipt and cancellation bytes are validated by the canonical module.

host-deploy's draft modules remain a **transport-independent nonsecret owner/policy/consumer admission join**. They do not define or translate credential wire bytes. host-install must never manufacture a canonical receipt from a host-deploy object or accept a raw token body outside root-control's verified canonical delivery path.

Command-Center production activation remains a separate gate: station-access must still prove its protected HTTPS listener, durable server-side request/replay/revision ledger and vault isolation using the same canonical protocol. Source interoperability is PASS; live producer/native receiver acceptance is not.

## Native acceptance after protocol convergence

Work must install/read back exact source and RECORD identities, independently install and verify TLS/station authority pins, prove the genuine retained HostIdentity signer, exercise wrong origin/signer/Host/STATE/revision/purpose/UID/grant/storage negatives, durable request replay across crash/reboot, partial/truncated response, cancellation/uncertainty and before/after authority rotation. Use synthetic credentials before any real Cloudflare release. Only a separately approved root-selected operation may pass secret bytes by anonymous FD into the original issuer storage.

## RF5BGA and issuer-installation boundary

The retained issuer installation and all historical operations are immutable inputs to this migration. **Do not modify or re-prepare RF5BGA.** Its abandonment/recovery history and any future preparation require their own explicit authorization and repeat-safety review. This source work does not run Certbot, DNS, ACME, certificate publication, nginx reload, EC2/SSM mutation or a real credential transfer.
