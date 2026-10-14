# Validation and recovery

## Evidence ladder

Offline schema/fixture tests verify manifest shapes and record consistency. Disposable AWS STATE acceptance verifies a separate explicitly disposable ext4 partition, live mount, fixed-account and identity persistence, while retaining the original OS boot root. That is a different gate from installing Zog HOST-A/B and booting the resulting native rootfs.

## Recover exact installation intent

An interrupted prepare/write/selection transaction preserves frozen target, image digest, operation ID and protected STATE. Recovery inspects the recorded ledger and current disk PARTUUIDs before resuming; it never substitutes a new source revision or disk. Missing boot proof, unknown storage state, restored stale key or absent prepared device blocks installation rather than fabricating successful acceptance.

## What live acceptance does not prove

Normal reboot tests are not sudden power-loss testing. A published fixture or accepted STATE test does not certify Secure Boot, TPM measurement, LUKS recovery, remote attestation, production enrollment, or full native-host services. Keep evidence of exact host/volume and failures; never perform destructive disk operations from a read-only documentation review.

## Exact reference material

- [aws-state-acceptance.md](../aws-state-acceptance.md)
- [fixture-plan.md](../fixture-plan.md)
- [state-provisioning.md](../state-provisioning.md)
- [host-generation-provenance.md](../host-generation-provenance.md)

The original documents retain exact machine schemas, historical implementation status and tests. A document describing an installed source feature does not imply operator-authorized host deployment.
