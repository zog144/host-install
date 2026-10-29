# Unified protected HTTPS issuer credential receiver — host adoption

**2026-10-29 — SOURCE ACCEPTANCE CONTRACT; native credential delivery remains NO-GO.**

This supersedes the SSH-specific receiver/adoption design formerly carried by host-install PR #5 and root-control PR #13. The receiving side is an independently Enrolled Host. The Credential Authority is the separately approved Command-Center Host. No SSH identity, `known_hosts`, sshd Match User mapping, forced command, transport account, PTY or SSH broker socket is part of the supported receiver.

## Exact reviewed source tuple

- root-control PR #16 source: `05aef0ef4a8470e315aada0bd1c67eb5cd98b7aa`
  - `zog.root_control.issuer_https_receiver`: Git blob `0261525db0a4307ce7b3f0267646249e0e4bc5c4`
  - `zog.root_control.issuer_receipt_common`: Git blob `4c1fe6b37c95d3cd038aba0c8a0df3b71a55d13f`
  - retired `zog.root_control.issuer_cross_host` tombstone: Git blob `a1631150dd7df2cf10c36c953a9fcd6af9a3847e`
- host-deploy PR #6 source: `9ed396c08aa5be30bd514630838b8a4baf2e2087`
  - `zog.host_deploy.certificate_cross_host_admission`: Git blob `592983a3d299aaf1228248157fdea3908680f097`
  - `zog.host_deploy.certificate_cloudflare_https_consumer`: Git blob `cf771f8625e329e557939a1f268517c52faaf2de`
- station-access PR #9 producer source: `b9c202147856520172228f7115a621e6d9bb1cae`
  - protocol: `17ed5096db1ce146089fbc9c3ebf556f10e75d46`
  - isolated HTTPS ingress: `db2f403ca9a8985ef9b65b56ce73adfe0a291ffe`
  - protected credential authority: `102c75f72a6da59f39d139621e32286fce86509a`

The station files are source-compatibility evidence only; they are not installed on the receiving Host and cannot become local authority by being checked out in CI.

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

## Exact remaining interoperability blocker

The three draft owners are not yet one byte-for-byte wire contract:

- station-access PR #9 currently defines `zog-credential-delivery-request-v1`, verifies Host RFC 9421 plus its protected consumer proof, and returns a bounded raw token body after Command-Center authorization;
- host-deploy PR #6 prepares the richer nonsecret `zog-protected-credential-delivery-request-v1` and requires a separate authenticated nonsecret receipt plus private FD;
- root-control PR #16 currently carries its own signed-response draft while preserving the selected HTTPS/TLS/HostIdentity/one-shot/FD gates.

Host-install must not translate away signed authority fields, fabricate a receipt, treat raw token JSON as metadata, or call one draft “compatible” because their purpose strings match. Native `native_https_accepted` therefore remains **false** until the protocol owners publish one exact request, response/receipt signature and secret-FD contract and the reviewed receiver is repinned to those final bytes.

The retained HostIdentity private key remains under the existing host-identify service-account ownership. HTTPS work must consume an independently verified signing capability/receipt; root must not recreate or silently take ownership of that private key.

## Native acceptance after protocol convergence

Work must install/read back exact source and RECORD identities, independently install and verify TLS/station authority pins, prove the genuine retained HostIdentity signer, exercise wrong origin/signer/Host/STATE/revision/purpose/UID/grant/storage negatives, durable request replay across crash/reboot, partial/truncated response, cancellation/uncertainty and before/after authority rotation. Use synthetic credentials before any real Cloudflare release. Only a separately approved root-selected operation may pass secret bytes by anonymous FD into the original issuer storage.

## RF5BGA and issuer-installation boundary

The retained issuer installation and all historical operations are immutable inputs to this migration. **Do not modify or re-prepare RF5BGA.** Its abandonment/recovery history and any future preparation require their own explicit authorization and repeat-safety review. This source work does not run Certbot, DNS, ACME, certificate publication, nginx reload, EC2/SSM mutation or a real credential transfer.
