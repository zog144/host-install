# Selected registry Host — explicit UUID and fingerprint to v3 identity handoff

2026-11-07 · host-install PR #34 · Source-only, **native identity HOLD**.

## Observed native blocker

[root-control PR #46's native preflight](https://github.com/zog144/root-control/pull/46#issuecomment-6711635575) reports the selected registry Host has **no mounted /state**, only its root disk. Its genuine host-discover record uses a canonical UUID host ID and host public-key fingerprint, while the installation-level signed registry expects a **distinct** 64-hex Host ID, installation ID, STATE volume ID and 32-hex registry/controller identifiers. This is not solved by truncating, padding, hashing or converting a UUID. No other Host's STATE or enrollment receipt is valid evidence.

The existing root-control `graphical_installation_storage_authority.installation_scope()` already checks a signed registry with exactly the 64-hex v3 fields; do not weaken that validator. host-identify's Ed25519 fingerprint is the SHA-256 **hex digest of the raw host public key** and host-discover's `expected_host_uuid` is canonical UUID. The new signed bridge must retain BOTH representations without treating one as the other's identifier.

## Source producer and verifier

`src/zog/host_install/graphical_registry_identity_mapping.py`:
- `prepare_mapping_for_registrar()` produces **only an unsigned canonical proposal** using an independently signed v3 registered-installation record, original discover UUID/fingerprint, and separately observed selected Host /state identity. It cannot create IDs, keys, mounts or a signature and returns `mapping_signed=False` and `native_accepted=False`.
- `verify_mapping()` requires a separately protected Ed25519 **registrar** signature, its domain, and an independently pinned registrar public key distinct from the signed-v3 **registry** public key. It also checks the actual v3 registry signature with root-control's original scope verifier, exact registered H64 identities/registry/controller IDs, legacy UUID/fingerprint, AWS instance/region, STATE EBS volume ID, filesystem UUID/PARTUUID and original protected STATE receipt digest. A trusted, separately obtained native observation must explicitly attest the SAME Host, `/state` mounted, with the exact storage identity; an absent, borrowed or changed STATE proof refuses. A synthetically signed test cannot attest native proof.
- Native failure remains **fail closed**. A proposed H64 value is not generated from a UUID; only a genuinely enrolled registry signer can supply it independently, and Work must independently establish operator/registrar custody and the actual matching Host installation.

## Native evidence required — host-install Work and registry producer

1. Identify the exact selected registry Host from real AWS instance identity document and account/region readback; corroborate physical/registry Host selection against the existing host-discover enrollment, expected UUID, actual Ed25519 public key/fingerprint, signed beacon, operator approval, issuer and authoritative registry signer pins. Capture the original canonical UUID and fingerprint without rewriting enrollment records.
2. Read the selected Host's actual block inventory, attachment/volume IDs, filesystem UUID, PARTUUID, mount namespace and installation receipt. The present finding is **no /state**. Determine whether a real persistent STATE volume exists and may be adopted under a separate authorized installation operation; do not initialize or borrow STATE to make the identity check pass. If no genuine retained STATE is present or provable, return `HOLD_STATE_NOT_PROVEN`.
3. The host-discover/host-identify registry owner must produce an explicit independently signed registrar mapping, and the original registry signer must supply the distinct, separately signed v3 registry record. Both must bind the same enrolled UUID+fingerprint, AWS instance/region, actual STATE EBS identity, installation ID and protected registrar public key. Independently authenticate the source of each H64/32-hex ID; **never** derive the values from UUID padding, hashing, a different Host's state receipt, or a self-declared mapping JSON.
4. host-install Work must verify exact pinned mapping and root-control v3 scope signatures, protected /state source/UUID/PARTUUID and receipt, registrar identity and independent trust custody. Record the original UUID, fingerprint and v3 opaque IDs in a secret-free retained acceptance report with source pins, AWS identity and mount readbacks. Never claim a PASS solely from the source-only validator.
5. Keep installation S3 checkpoint establishment, two independent protected mounts, IAM changes, original history disposition, broker/owner units and SSM inactive while identity selection is ambiguous. Only then proceed to the separately queued v3 pair installer selection for root-control PR #47 and host-deploy PR #30.

**Exit:** one authenticated, unambiguous registry Host and installation/STATE identity with a signed producer/verifier chain, or an explicit native HOLD naming missing evidence. Source-level tests are not native acceptance.
