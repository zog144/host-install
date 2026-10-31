# Canonical HTTPS administrator password receiver — host-install source handoff

**2026-10-31, source-only.** Owners: host-install Regular + station-access Regular. Tracking: station-access #15 and PR #18, host-install #2. This does **not** repurpose the certificate issuer Cloudflare receiver or allow existing Enrolled Host privileges to set user passwords.

Canonical `zog.host_identify.credential_delivery` 0.3.5 is the sole protocol. The provider's signed v1 authorization must select exact Host/fingerprint/installation/STATE/registry, consumer `station-access`, purpose `station-access-administrator-password`, selected account, credential/revision and independently operator-signed protected account policy. The station local receiver uses a readonly, fully sealed anonymous Linux memfd with bounded plaintext after signature checks; Django hashes the password through `validate_password` and `set_password` under its protected `SecurityGate`, persists replay/version history and revokes sessions/unused VNC grants. Its public APIs and browser tokens never acquire that access.

The source-only helper `zog.host_install.station_admin_password_receipt.inspect` binds the **secret-free** protected Django commit record to the same canonical authorization, request and delivery, account ID and revision. It **intentionally cannot** authenticate how that local commit record was transported, attest its source/wheel RECORD, inspect local Django state, prove peer credentials or sign a canonical host receipt; its returned `host_signed_receipt_authorized=false` is permanent at this source stage.

**Remaining protected host-install/root-control integration:**
1. Implement independently authorized receiving Host/installation/STATE and operator-pin adoption, not inferred from signed enrollment/beacons. Verify exact selected `station-access` account, credential revision and operator-approved signed authorization while preserving unrelated certificate grants.
2. Prove HTTPS producer hostname/TLS authority, fixed bounded canonical request, signed response, durable nonce and no-repeat/rotation state. Never log, persist or route its secret through command lines, environment, cloud workflows, Django user API or browser sessions.
3. Transfer only sealed readonly anonymous memfd over an independently installed restricted local AF_UNIX `SCM_RIGHTS` broker. Verify Linux `SO_PEERCRED`, listener and process UID/cgroup/invocation and installed bytes/RECORD of the Django receiver. Do not run Django as root.
4. Recheck exact operator approval and selected account revision inside the Django security writer immediately before mutation. Obtain its secret-free post-commit record **only after** database commit and verify its protected origin. When uncertain, inspect durable request/revision high-water rather than reapplying credentials.
5. Only then construct and sign `zog-credential-installation-receipt-v1` via the authorized HostIdentity signing path, with exact original request/delivery/authorization identity and installed timestamp. Send it over canonical signed HTTPS receipt route. Verify replay, cancellation, lost reply, crash/reboot recovery and independent owner withdrawal without deleting account/audit history.

**No live administration-password delivery, source pin adoption, root socket installation, service activation or credential authority grant is approved by this contract.** Keep PR draft until receiver/source/rights reviews and protected native gates close.


## Task 4 — protected FD broker and ambiguous-commit recovery

`station_admin_password_handoff` provides source-only root-UID-guarded
`handoff`, `recover`, `read_committed_reply`, and
`inspect_recovered`. They use the source draft
[root-control #19](https://github.com/zog144/root-control/pull/19)
`administrator_fd` protocol. These helpers do **not** obtain authority,
deliver HTTPS credentials, validate installed executable bytes, launch a
service, adopt an operator key or issue an authorized Host receipt.

The future protected installer must independently select root-owned trust
material and the intended Django receiver process, authorize exactly the
account and credential revision, and verify the original signed producer
delivery (not merely a structurally valid canonical object). A root-only
sender transfers a sealed, readonly anonymous FD over an AF_UNIX
SOCK_SEQPACKET connection to that separately pinned non-root receiver.
Both peers pre-enable SO_PASSCRED on receiving sockets and validate the
connection's SO_PEERCRED plus actual message SCM_CREDENTIALS and pinned
PID/starttime/cgroup. No password travels in the control frame or receipts.

After a successful Django transaction the receiver replies with the exact
secret-free commit on the same protected connection. The caller validates
the reply's selected operation, approved account, and source contract. If
the send or reply is uncertain, **do not redeliver or regenerate a credential**:
on a fresh verified connection, ask for the original request/delivery and
inspect Django's existing protected commit. The source-only historical
comparison can match the protected commit after the original HTTPS grant
expires; it does not override current authorization, produce a receipt,
or grant permission to reinstall a password. Durable installer receipt
state, cancellation/highwater, live identity/wheel checks, and canonical
Host signing/transmission remain **native NO-GO** gates.
