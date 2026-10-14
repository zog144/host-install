# Host generations and boot evidence

## Selected versus actually booted

The installer record captures immutable installation identity, selected HOST-A/HOST-B generation and root PARTUUID. The actually booted slot is separately proved by live kernel/root evidence, not deduced from a selected record. If the host is still booted from a transitional foreign root, `booted_slot` remains unknown/null rather than becoming HOST-A by implication.

## Conservative legacy compatibility

Old `state-contract-v1` records may identify the selected slot only; absent inactive-slot provenance stays unknown. New records can retain both slots with distinct PARTUUIDs. Upgrades preserve nonselected-slot evidence while changing the explicitly selected installation transaction. Do not reconstruct an inactive generation from filenames or mutable current active symlinks.

## Provenance and downstream readers

Host-discover reads verified host-generation evidence from host-install and signs it into its beacon; station-access stores and displays it only from the authenticated route. Archive rootfs resolution is a separate digest-bound lookup and may remain unresolved or ambiguous. A signed boot report does not establish every package license or public release readiness.

## Exact reference material

- [host-generation-provenance.md](../host-generation-provenance.md)
- [state-interface.md](../state-interface.md)
- [image-build-integration.md](../image-build-integration.md)

The original documents retain exact machine schemas, historical implementation status and tests. A document describing an installed source feature does not imply operator-authorized host deployment.
