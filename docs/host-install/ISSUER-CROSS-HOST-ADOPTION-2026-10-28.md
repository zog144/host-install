# Unified HTTPS issuer credential receiver — native adoption

**2026-10-29 — SOURCE REVIEW ONLY; live credential receipt NO-GO.**

This replaces the SSH-specific adoption instructions originally proposed in host-install PR #5 and root-control PR #13. The approved architecture uses a protected HTTPS endpoint (port 443) on the Command-Center Host and the independently enrolled receiving Host. No SSH identity, forced command, transport account or key-to-UID mapping participates in the new receiver.

## Exact reviewed components

Root-control selected HTTPS receiver source commit:
253e80c9c22fad969a84a0c08d7f28940017e5f9

- zog.root_control.issuer_https_receiver Git blob: c91b8c6831568b6c927039f04bb74ddd3a1e6bca
- zog.root_control.issuer_receipt_common Git blob: 4c1fe6b37c95d3cd038aba0c8a0df3b71a55d13f
- Separate existing host-deploy nonsecret consumer module zog.host_deploy.certificate_cross_host_admission Git blob: ced728c5c8d7a2b1ced449091494e783680633c1, subject to its review/source successor.

The inspector checks exact installed root-owned Python source bytes, matching distribution wheel RECORD hash, selected interpreter, original verified STATE, approved second owner ledger and owner receipt, managed HostIdentity/installation, station signer pin, local grant/storage, selected delivery policy and current certificate credential revision. The station-access local vault-reader source remains separately pinned. A candidate's self-reported hash never substitutes for the independent reviewed Git pin.

The root-owned HTTPS client profile must follow zog-issuer-https-credential-client-v1, matching host-deploy's current nonsecret owner admission schema. Its fixed purpose is issuer-cloudflare-dns01. The receiver separately verifies TLS CA bytes/pin and a station authority Ed25519 signature, plus Host-signed request, request nonce, identity, assignment, consumer UID, credential UUID/revision, receipt, grant/storage and policy digest. A one-time request record must be durable before HTTPS dispatch; a lost reply is not automatic retry authority. Installation is only through the existing private anonymous-FD issuer installer, never a generic root-control remote-command RPC.

## Remaining native acceptance gates

1. Station-access and host-identify must approve/implement a single interoperable versioned HTTPS wire format and independently authenticated credential broker; the proposed signed-response envelope in root-control is not yet a running Command-Center endpoint.
2. The protected host-install owner must attest the exact installed root-control modules and their RECORD entries, approved HostIdentity consumption receipt, trusted TLS CA and signer authority, current STATE/owner/second ledger, current grant/storage and destination UID, and freeze source revisions. Native HTTPS approval remains false until genuine acceptance.
3. Validate active producer authorization, credential purpose and revision, revocation and durable anti-replay across interruption/reboot; reject partial response, wrong signer/TLS CA, wrong Host/STATE, changed policy and stale source.
4. Only a separately authorized selected receiver may call the private installer. Check protected destination mode/ownership, immutable history and success/uncertainty receipts. No credential content may enter logs/CLI/JSON diagnostics.

The original RF5BGA issuer preparation, its uncertainty/recovery and any new attempt require separate explicit authorization. Do not run another preparation, ACME, DNS, nginx or retained Host change from this source handoff.
