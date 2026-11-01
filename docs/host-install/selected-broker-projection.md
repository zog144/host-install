# Selected issuer broker authority: protected root-owner source contract

**Owners:** host-install Regular and host-deploy Regular. **Native writes:** Work only.
**Producer:** host-deploy draft PR #3 at e2e050a9562a07648ed58ba5a1357daed6da4e9e (consumer includes final install-commit validation).
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
An independent root-only 0600 receipt reflecting **actual installed bytes**,
not a source plan, must be fsynced and read back before publishing the last
root-owned 0444 immutable `certificate-issuer-broker-install-commit.json`.
This final commit binds SHA-256 of the exact 0444 projection, SHA-256 of the
0600 installed receipt, original Host/installation/STATE/certificate/policy,
original binding, owner revision/operation and pinned producer/box-control
source. A projection alone, or a projection plus receipt without the final
commit, is never usable by host-deploy. A pending, torn, altered, symlinked
or mismatched commit is also a denial. The final commit is published with the
same stable installer lock, exclusive no-replacement staging and fsync;
the timer checks it before and after reading the projection, and again
before **every** broker RPC. Original public projection and private receipt
remain immutable; recovery after an interrupted write resumes only exact
same-byte stages, without replacing an older generation.

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


## Commit-bound source acceptance (2026-11-01)

Source fixes add `COMMIT_SCHEMA`, the last-commit `publish_verified_projection`
boundary, and a matching `host-deploy.certificate_selected_broker_authority`
nonroot reader. The host-install interop workflow pins exact host-deploy
`e2e050a9562a07648ed58ba5a1357daed6da4e9e` plus its consumer Git
blob `c16c55f37495177974349100451d624f39cb9718`, and runs both
modules against the same ephemeral root-owned filesystem, injecting
interruptions after projection, after private receipt, and during the
final commit hardlink publication. Missing commit always blocks; exact-byte
recovery restores the authorized path without replacement.

These CI fixtures do **not** install the authority in native /etc or
prove root original-reader provenance, signed registry approval, root owner
ledger continuity, actual systemd/peer UID, reboot durability or ACME/HTTPS.
Selected-broker native activation remains NO-GO, and
`_require_approved_native_inspection` is unchanged.

## Shared selected issuer execution epoch (root-control #22)

The protected publisher has one native entry: `publish_verified_revocation`.
It acquires `issuer_execution_fence.installed_fence(for_revocation=True)`
under the same fixed root:root 0700
`/etc/zog/host-deploy/selected-issuer-execution` directory and durable
`selected-issuer-execution.lock` that the real
`BusctlSystemdBackend.start_service()` uses. It authenticates the committed
installation digest against the prior epoch ledger. There is NO independent
host-install execution lock and no unfenced fallback.

The actual root-control selected `renew`, `inspect`, `stage` launch persists
`admission-uncertain` before `StartTransientUnit` and holds this flock through
PID1 dispatch/observation. Host-install first durably advances terminal
revocation epoch and marks nonterminal operations `cancel-pending`, then
publishes pending/final no-replacement root tombstone under the same lock.
A lost publication acknowledgement remains revoked; same-marker retry
never clears the terminal epoch. The protected publisher reports
`execution_cleanup_native_verified=false`: admitted runtimes still require
native PID1/cgroup stop, observation, reconciliation and reboot evidence.

The dedicated source workflow pins root-control exact
`2ce325a6d3fe2937c6c885cad0424cc22964103f`, compares both real
source integration entries, and tests the original root fence source
concurrency, lost PID1 acknowledgement and tombstone replay.

**Native NO-GO** until trusted initial 0700 ledger and wheel RECORD,
genuine authority grant/source, exact unit/InvocationID identity, bounded
kill/cleanup, reboot reconciliation, and separately approved activation.
Do not fabricate STATE or equate cancel-pending with termination.
