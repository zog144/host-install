# Architecture and ownership

Host-install is an offline-first installer and durable host-state coordinator. It consumes a reviewed [image-build artifact](image-build-integration.md), prepares a synthetic or explicitly authorized installation target, and preserves host installation and identity evidence through STATE. It does **not** replace `image-build`, `host-identify`, `host-discover`, or the application controller.

## Data and control flow

1. **Artifact source** — `image-build` exports an immutable candidate. Host-install verifies the expected artifact identity, stages a local snapshot and checks extracted content. Artifact verification is not proof of production bootability or authorization to write a device.
2. **Offline preparation** — The [fixture plan](fixture-plan.md) drives synthetic GPT/filesystem tests. A read-only target preflight gathers evidence for a possible physical target, but does not create exclusive ownership or authorize a write.
3. **Persistent STATE** — [STATE validation and inspection](state-interface.md) determine whether protected installation records and storage meet the runtime contract. [Provisioning](state-provisioning.md) is an explicit separate mutating operation.
4. **Identity boundary** — `host-identify` generates and manages the durable Ed25519 host identity under the protected profile. Host-install coordinates and verifies installation evidence; it does not silently replace an existing identity.
5. **Admission** — A local protected [admission observation](state-admission.md) allows a narrowly scoped consumer to evaluate existing installation/identity state. It is not an authorization for enrollment or remote control.
6. **Optional transport** — [Managed beacon composition](managed-beacon.md) configures a separately gated signed heartbeat transport. It is not a replacement for local installation checks.
7. **Observed host provenance** — [Host generation provenance](host-generation-provenance.md) reports verified currently booted slot evidence without choosing a next slot or inventing inactive-slot state.
8. **Certificate application enablement** — [Certificate enablement](certificate-enablement.md) orders protected prerequisites and exposes secret-free headless status. It does not issue, publish, reload, expose a proxy, or alter archive roles.

## Persistence and failure

STATE records and immutable-generation choices must survive interruption. An incomplete operation is evidence to inspect and preserve, not a cue to restart destructively. Root-owned identities and records are kept outside disposable HOST generation partitions. Changes that can erase a device, replace an identity, or promote a boot generation require separately authorized lifecycle steps.

## Integration contracts

| Producer | Consumer | What crosses the boundary |
| --- | --- | --- |
| image-build | host-install | Exact reviewed artifact and verifier contract |
| host-install | host-discover | Narrow protected existing-identity admission observation |
| host-identify | host-install / host-discover | Durable host identity operations and verification |
| host-install | host-discover | Read-only verified booted-generation report |
| host-deploy | installer host | Provisioning and remote transport, not installation policy |
| certify-manage / controller / host-deploy | host-install status gate | Authenticated secret-free lifecycle evidence only; no inherited certificate or proxy authority |

## Not yet implied by local success

Passing tests for STATE, protected socket admission, read-only provenance, or disposable AWS acceptance does not prove bootable physical installation, enrolled station control, signed UKI/Secure Boot, TPM attestation, or A/B upgrade/promotion. See [verification and evidence](verification.md).
