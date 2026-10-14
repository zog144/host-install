# Persistent STATE and identity

## Canonical mount and ownership

The intended durable mount is `/state`. STATE is distinct from immutable HOST-A/HOST-B and application software. Root-owned installer records, protected identity keys, controlled runtime STATE and authorization/consumption receipts have their own paths and ownership; missing mount or storage errors cannot be solved by creating fresh identity under the rootfs.

## Transition from proposal to implementation

The preserved [original STATE proposal](../state-contract-v1.md) is historical: it names numeric assignments subject to checks and explicitly was not implemented at the time. The later [state interface](../state-interface.md) and [provisioning](../state-provisioning.md) introduce schema validation, descriptor-retained inspection, offline record publication, root-owned authorization and unprivileged host-identify consumption. The authoritative current implementation, not the older draft excerpt, decides actual allowed operations.

## Recovery holds and inspection

A live inspection retains an open STATE directory descriptor, performs explicitly requested write probes, verifies record/schema and current mount facts, then checks root-owned holds/consumption evidence. An unreadable hold is not equivalent to no hold. Existing key and receipt mismatches require reconciliation; storage faults preserve protected state and prevent normal enrollment.

## Exact reference material

- [state-contract-v1.md](../state-contract-v1.md)
- [state-interface.md](../state-interface.md)
- [state-provisioning.md](../state-provisioning.md)
- [state-admission.md](../state-admission.md)

The original documents retain exact machine schemas, historical implementation status and tests. A document describing an installed source feature does not imply operator-authorized host deployment.
