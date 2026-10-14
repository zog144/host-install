# Installation and disk model

## A deliberate host installation, not a build side effect

Host-install consumes an **exact verified image-build host-install artifact** and applies an explicit disk/slot plan. Image-build produces bytes and provenance; host-install owns target disk/partition preparation, accepted boot-state records and installer transaction. A successful rootfs build does not authorize overwriting a host root disk.

## Five logical partitions and immutable host slots

The accepted GPT design reserves ESP, HOST-A, HOST-B, STATE and APPLICATIONS. HOST generations remain immutable during normal use; STATE holds durable identity, installation operations, controller state and protected secrets. Installation prepares the inactive/selected slot only under a reviewed exact target and never interprets a mutable filename as an identity. A transitional foreign Linux kernel/initramfs/boot bundle may be recorded as provenance without claiming a native Zog boot.

## Safe artifact handling and rehearsal

The consumer validates archive manifest/owner identity, digests, extracted entry types, paths, symlinks, ownership and expansion limits, then independently verifies staged bytes. The local fixture plan is a **test harness** with exact generation, boot and filesystem descriptors; its presence does not prove the target was provisioned or booted. Physical-device write authorization, original EBS root retention and post-boot rollback are external operator gates.

## Exact reference material

- [image-build-integration.md](../image-build-integration.md)
- [fixture-plan.md](../fixture-plan.md)
- [aws-state-acceptance.md](../aws-state-acceptance.md)

The original documents retain exact machine schemas, historical implementation status and tests. A document describing an installed source feature does not imply operator-authorized host deployment.
