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
9. **Console-first bootstrap readiness** — [Console bootstrap](console-bootstrap.md) exposes a sanitized authenticated local readiness snapshot without granting host-welcome raw STATE, identity secrets, device writes, controller commands or optional-application authority. The producer can answer `unknown` before STATE/network/controller/browser readiness and does not own the TTY/login session.
10. **Station controller-progress observation** — [Application-progress observer deployment](application-progress-observer.md) stages the protected box-control read-only broker socket using the station runtime's numeric protected execution identity, exposes only its host-export directory to the station web program, and does not authorize controller mutation.
11. **Host-welcome controller-progress observation** — [Dedicated console observer](host-welcome-progress-observer.md) stages a second, non-shared read-only broker socket for the host-rootfs bootstrap consumer, with a fixed root policy and reviewed broker/client byte identities. It does not inherit the station socket or arbitrary host runtime files.
12. **Native certificate issuer installation** — [certify-manage native installation](certify-manage-native-install.md) stages the immutable issuer software binding, controller application declaration, read-only host policy grants and lifecycle broker while leaving hostname authority, DNS credentials, ACME mutation and TLS delivery with their separate owners.

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
| host-install | host-welcome trusted adapter | Sanitized bootstrap readiness over a fixed peer-authenticated local socket; no raw STATE or mutation authority |
| box-control observer via host-install deployment | station-access web | Read-only application progress over a fixed AF_UNIX socket, numeric peer UID and protected host-export capability |
| box-control observer via host-install deployment | host-welcome | Separate read-only controller progress socket and exact root-owned policy; no station socket, raw STATE or mutation authority |

## Not yet implied by local success

Passing tests for STATE, protected socket admission, read-only provenance, or disposable AWS acceptance does not prove bootable physical installation, enrolled station control, signed UKI/Secure Boot, TPM attestation, or A/B upgrade/promotion. See [verification and evidence](verification.md).
