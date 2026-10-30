# Protected externally-managed Command-Center authority bootstrap

Issue: host-install #7. This source implements the protected **offline writer** for the existing Command-Center station. It is not a resident-host STATE installer and does not authorize live credential delivery.

## Identity boundary

The Command-Center is explicitly bound to AWS instance `i-0c676721165320da0`, station-access candidate `c2540cc5c9a3a0c1fff2748552819685ed2fdff4`, and the existing protected station application database observed by the independently operator-signed `zog-command-center-offline-installation-identity-v1` record.

The enrolled issuer consumer Host/install/STATE identifiers remain separate. The module refuses a Command-Center Host or installation UUID equal to the consumer values and never calls canonical `/state` inspection or provisioning.

The source binds, but does **not itself cryptographically authenticate AWS IID provenance**. The protected installer owner must independently verify the AWS IID/selected instance and provide the exact evidence bytes whose SHA-256 is signed into the Command-Center identity. Likewise, the expected operator public-pin SHA-256 must arrive through an independently authenticated channel; a value supplied by the candidate station is not sufficient provenance.

## Three signing roles

The writer requires three distinct raw Ed25519 public keys: (1) independently pinned operator approval key; (2) retained station certificate-assignment signer, fixed for this bootstrap to SHA-256 `1ecf7d17bd8abc00ca50bde297f427b0fa28f2f6894b0a0cb71ae8d1237425cb`; and (3) Credential Authority v1 signer whose private PEM must match its public pin.

It verifies the operator signature over the Command-Center identity, the PR #9 root grant and its operator approval, the exact issuer-reader projection, the canonical v1 authorization signature made by the Credential Authority key, and the second domain-separated operator endorsement of the exact grant/envelope/authority-key hashes.

## Offline publication

The destination must already be a root:root 0700 directory below `/opt/station-trust/` whose basename ends in `-offline`. The writer creates only `host-install-command-center-authority/` below that inert directory and uses the persistent root-owner lock `.host-install-command-center-authority.lock`.

Publication uses host-install's descriptor-anchored `state_io.publish`: O_EXCL/O_NOFOLLOW staging, fsync, hard-link publication, same-byte recovery, and refusal to replace conflicting bytes. It stages the operator pin, signed identity and AWS evidence; retained certificate signer pin; root grant and operator approval; issuer-reader projection; Credential Authority private PEM and public pin; canonical signed authorization and operator role approval; and a root-private secret-free receipt.

No file is written under active `/etc`, no service points at this directory, and the receipt records `production_activation_authorized=false` and `credential_delivery_authorized=false`. The private-key bytes and any credential are never returned in the report.

## Native protected-installer sequence

The native owner must first attest the exact host-install writer source/wheel RECORD and the receipt's source closure: station-access PR #12 candidate, host-identify 0.3.5 `4a176373...`, host-discover 0.4.13 `ebe83775...`, and the frozen host-install 0.14.3 companion `6e8b3792...`.

Then independently verify AWS IID/instance provenance and the operator pin fingerprint. Supply already reviewed/signed authority inputs to `host-install command-center-authority-stage`, and rerun `command-center-authority-inspect` after interruption/restart to prove exact same-byte retention and unchanged database inode/owner/DAC.

This issue does not authorize migration 0018/0019 on the live database, SecurityGate advancement, socket/nginx enablement, Cloudflare token reads, credential delivery, Certbot/ACME/DNS changes, or conversion of the retained station into a canonical host-install STATE installation. Those remain later separately approved gates.
