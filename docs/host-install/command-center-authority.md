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

The destination must already be a root:root 0700 directory below `/opt/station-trust/` whose basename ends in `-offline`. The writer creates only `host-install-command-center-authority/` below that inert directory. **Staging and inspection now require a separately pre-provisioned, persistent root-owned `.host-install-command-center-authority.lock` plus immutable-in-place `.host-install-command-center-authority.lock-identity-v1.json`.** Neither operation creates or repairs a missing/replaced lock.

Publication uses host-install's descriptor-anchored `state_io.publish`: O_EXCL/O_NOFOLLOW staging, fsync, hard-link publication, same-byte recovery, and refusal to replace conflicting bytes. It stages the operator pin, signed identity and AWS evidence; retained certificate signer pin; root grant and operator approval; issuer-reader projection; Credential Authority private PEM and public pin; canonical signed authorization and operator role approval; and a root-private secret-free receipt.

No file is written under active `/etc`, no service points at this directory, and the receipt records `production_activation_authorized=false` and `credential_delivery_authorized=false`. The private-key bytes and any credential are never returned in the report.

## Native protected-installer sequence

The native owner must first attest the exact host-install writer source/wheel RECORD and the receipt's source closure: station-access PR #12 candidate, host-identify 0.3.5 `4a176373...`, host-discover 0.4.13 `ebe83775...`, and the frozen host-install 0.14.3 companion `6e8b3792...`.

Then independently verify AWS IID/instance provenance and the operator pin fingerprint. Supply already reviewed/signed authority inputs to `host-install command-center-authority-stage`, and rerun `command-center-authority-inspect` after interruption/restart to prove exact same-byte retention and unchanged database inode/owner/DAC.

This issue does not authorize migration 0018/0019 on the live database, SecurityGate advancement, socket/nginx enablement, Cloudflare token reads, credential delivery, Certbot/ACME/DNS changes, or conversion of the retained station into a canonical host-install STATE installation. Those remain later separately approved gates.


## Independent source-boundary review — 2026-11-02 (not native approval)

The station-access consumer-side source review treats this externally managed Command-Center identity separately from the enrolled consumer Host/installation/STATE. The operator-signed identity binds the fixed AWS instance ID, station source revision, registry selection, original protected station application database path/owner/DAC/device/inode and parent inode. The root grant must match that registry and the separate enrolled consumer identity. None of these claims substitutes for genuine AWS IID verification or an operator pin from a channel outside the candidate station.

The role graph requires all three *different* public Ed25519 key fingerprints: independently anchored operator, previously retained certificate-assignment signer and new Credential Authority signer. The operator signs the Command-Center identity, root grant approval and domain-separated role approval; the Credential Authority signs canonical v1 authorization, and its private PEM must match the authority public pin. Synthetic regressions exercise each possible signer-pair collision and a credential authority PEM/public-key mismatch.

Material is stored only under an existing root:root 0700 offline directory below /opt/station-trust, in a root-owned 0700 child with protected file modes, no-follow/no-hardlink file checks and a writer lock. Receipt publication is last; known same-byte staged/linked/published crash states may resume under the lock without replacing bytes, and missing/partial/foreign receipts fail closed. Inspection rereads the entire exact bundle and the protected station database. The source reviewer added a second database identity observation **under the publication lock, before writing the first material**, and a third observation after receipt publication/fsync. Database replacement at either point cannot return a successful stage result. After an interrupted post-receipt publication, **inert** staged bytes can remain, but inspection rejects the changed database. This is not a native guarantee of disk rollback.

### Remaining independent-owner and native holds

1. Independent operator authentication of the original Command-Center AWS IID, station database origin and original operator key. Caller-supplied hash and unsigned synthetic AWS evidence file do not authenticate themselves.
2. Attest exact 0.14.10 host-install installed wheel/RECORD, protected directories/mount/inode, real UID/GID separation, the original separately prepared root writer-lock inode and root-directory identity. The Command-Center path **does not** use generic state_io.lock anymore; the new anchored writer guard requires external bootstrap and tests loss/replacement as fail closed. Native integration must still verify genuine filesystem/disk provenance and recover a partial initial bootstrap through explicit operator review, not a silent replacement.
3. Independently inspect the retained certificate signer and distinct Credential Authority signer, approved issuer-reader group, restart/reboot readback, operator approval revision and no-replacement evidence.
4. Separate offline preparation from installation, production activation, certificate operations and canonical administrator credential delivery. This source never provisions STATE or authorizes a live listener/broker.

A second source review with the same GitHub actor is not a different person's security approval. Native/production disposition is **NO-GO** pending independent operator and installed-byte evidence.


## Protected offline writer-lock identity — source review 2026-11-03

The previously selected `state_io.lock` opened its lock pathname with
`O_CREAT`. If another root-owner path replaced that inode during an
interrupted multi-file publication, concurrent writers could acquire
different `flock` objects. The new Command-Center-specific source contract
refuses lock creation during **both** `stage_offline` and `inspect_offline`.

Before the *first* offline staging operation, the independently approved
protected native owner must prepare the existing root:root 0700 offline
directory's 0600 lock and a durable 0600 lock-identity marker recording
the exact root-directory `(st_dev, st_ino)` and lock-file `(st_dev, st_ino)`.
The source-only `prepare_offline_writer_lock_source` helper demonstrates
atomic no-replacement lock+marker staging inside the root-directory flock,
but is not a live installation or authority approval endpoint.

A crash after creating the lock but **before** its marker is durable leaves
an incomplete bootstrap. The helper and the subsequent staging operation
refuse to infer an intended original inode or recreate the lock. A
separately authenticated recovery decision is required.

Every later stage/inspect obtains an exclusive `flock` on the **root
directory inode first**, opens the original lock `O_NOFOLLOW` without
`O_CREAT`, confirms its owner/mode/one-link identity against the persistent
marker, and then flocks that original lock. The guard re-verifies the
directory, marker and original lock pathname at each staged file `fsync`,
hard-link publication and final receipt readback, as well as after all
materials are published. A lock deletion or replacement is a hard HOLD;
a second conforming writer cannot enter while the original directory
flock is held, and cannot adopt a newly created lock later.

Source regressions cover missing/deleted/recreated/symlinked/hardlinked
lock paths, concurrent interrupted writers, crash between initial lock
and marker, pathname substitution between staged file publication steps,
same-byte resumption with the intact original lock, and real root-owned
ephemeral `stage_offline`/`inspect_offline` entrypoints. A post-crash
partial bundle retains its inert bytes; no conflicting receipt is
published or accepted automatically.

**Native limits:** the separately administered owner must prove the
directory and lock identity, and prevent privileged replacement of
the root directory or its marker; synthetic `flock` tests cannot
exclude a compromised root principal, filesystem rollback, or a
foreign already-running writer that ignores the protected protocol.
No actual Command-Center signing authority, `/opt/station-trust`
state, canonical STATE, key, station database, or credential was
installed by these source changes.
