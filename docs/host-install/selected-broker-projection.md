# Selected issuer broker authority: protected root-owner source contract

**Owners:** host-install Regular and host-deploy Regular. **Native writes:** Work only.
**Producer:** host-deploy draft PR #3 at b4e723abab3dadcf238b0552ee4d5f108e6a6d95.
**Broker client:** box-control issuer-lifecycle client 9111606eef306292d70fd4d941eeb73f48b33ff1.

The root approval **must be independently authenticated and digest-pinned**.
A user-supplied request, renewal timer JSON, network response, projected file,
or certificate owner receipt does not authenticate its own approval.

Pure source entry points are `projection_plan`, `no_replacement_check`,
and `revocation_plan`; they never write to disk. The native-only protected
writers `publish_verified_projection` and `publish_verified_revocation`
require root, a separately trusted original-root-record reader and an
installed-source/RECORD attestor. They accept neither caller-selected plans
nor HTTP/CLI JSON. They reopen the existing fixed root-owned /etc ancestry
with retained O_NOFOLLOW descriptors, hold a persistent root-owner lock,
recheck the original root evidence under the lock, and use exclusive
no-replacement hard-link publication with fsync and exact readback.
The writer functions exist in source but have **not** run against a live Host.
Work must provide the authentic native reader/attestor and verify installed
source, actual UID/GID and issuer grants, and post-reboot recovery before use.

The source plans and native-only writers require:
* reviewed root operator approval with an out-of-band expected SHA-256;
* original 0600 host-deploy private managed consumer binding from root-verified
  /etc, with matching canonical bytes and independently computed binding digest;
* host-install's root-owned managed certificate owner receipt, original
  monotonic owner ledger, exact signed assignment/Host/installation/STATE
  identity and protected revocation status (the protected native owner verifies
  these original sources; passing a copied dict is not provenance);
* exact certificate, hostnames, policy, issuer socket, distinct
  controller/caller/issuer UIDs, issuer GID, grant/storage, host policy digest
  and pinned box-control and host-deploy source;
* a currently approved/unexpired owner authority for projection, or a *higher*
  root-ledger revision and separately independently approved terminal revoked
  owner for revocation.

The projection is strictly the nonsecret `zog-host-deploy-selected-issuer-broker-authority-v1`
schema consumed by host-deploy at:

`/etc/zog/host-deploy/certificate-issuer-broker-authority.json` (root:root 0444).

Native Work, **after** independent installed source and original root-file
attestation, must publish that exact candidate using no-replacement,
durable lock, fsync and safe parent dirfds. Same byte is idempotent; conflict,
pending publication, installation/STATE mismatch and revoked marker all STOP.
An independent receipt reflecting **actual installed bytes**, not a source
plan, must be committed before any protected native acceptance.

Revocation is **irreversible for this projection identity**, not an in-place
replacement of the 0444 policy. A higher root-authenticated revoked owner
checkpoint and separate signed/operator-approved revocation intent produce a
permanent root-owned 0444 tombstone:

`/etc/zog/host-deploy/certificate-issuer-broker-revoked.json`.

The protected native owner must publish it by exclusive, no-replacement
`.pending.` hard-link staging and durable fsync, retain the original
projection/receipt and the higher revision history, then recheck after reboot.
**Never unlink the tombstone to reactivate the old projection.**
An explicitly reviewed new authority generation requires a separate path/
generation migration contract, not a same-path overwrite.

The nonroot host-deploy reader checks **both final and pending marker names**
via its retained root-verified parent fd before and after the projection read.
Any existing marker, including malformed/symlink/partial publication, is a
denial. This closes the stale 0444 projection acceptance after completed
or interrupted revocation. A test-only `root_reader` injection cannot
authorize native selected-broker activation.

**Native gates still NO-GO:** genuine owner source/RECORD and installed
root-owned files; controller SO_PEERCRED/systemd UID and actual issuer socket;
real issuer immutable view/grant/storage; rollback/crash/reboot through actual
kernel FS, an authentic revocation marker, session/renewal race, latest
signed hostname authority, and operator activation. Preserve host-deploy
`_require_approved_native_inspection` rejection. No live ACME/DNS,
Cloudflare secret, Certbot, nginx, 80/443, or canonical STATE mutation here.
