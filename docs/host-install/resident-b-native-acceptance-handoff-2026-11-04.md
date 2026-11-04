# Resident B: host-install ↔ image-build native acceptance handoff v1

**2026-11-04. Source-only, disabled.** This handoff is built against the exact image-build hardened installed-evidence candidate [PR #16](https://github.com/zog144/image-build/pull/16), source `06e2714ff032dc8ca985d056a1e8800515847f65`. The accepted controller/source predecessors are unchanged. The first resident boot contract and [host-install issue #4](https://github.com/zog144/host-install/issues/4) remain authoritative: neither image-build nor this helper selects/accepts a live rootfs.

## Three independent witnesses — no circular acceptance

1. **Image-build source-generation selection**: a separately pinned generation authority signs `zog-resident-b-selected-input-generation-v1`, binds a trusted immutable `generation_id` and source-generation receipt SHA-256 and retains `native_boot_authorized=false`. Host-install may use this as an *input* but never infer that generation is bootable.
2. **Image-build installed-byte observer**: a different trusted native attester signs `zog-resident-b-installed-generation-evidence-v1`, binding the same generation, exact STATE identity, reviewed file inventory and Python 3.12 wheel/RECORD/ELF, service and socket claims. The hardened read-only image-build verifier performs independent byte inspection and returns `EVIDENCE_COHERENT_UNACCEPTED`.
3. **host-install protected installation and physical observer**: separately protected Ed25519 signers certify a host-install-selected Host identity, installation identity, exact generation, HOST-A/B slot, rootfs PARTUUID/device, STATE volume ID/PARTUUID/device, selected socket GID, root controller identity and service-disabled state. The *physical observer* additionally reports source-backed rootfs read-only mount ID, separately mounted STATE, mount identity, UID/GID/modes, root-owned socket, and its own unique observation identity. Its signing key is distinct from the host-install selection signer and both image-build signers.

Every cross-owner identity is checked for equality; changing a mount device, swapped PARTUUID, wrong slot, STATE volume, service UID/GID, or changing any signed field after its signature rejects. The host-install selection/physical observation cannot be authorized using a caller-controlled public key; the caller must independently pin all four trust roots, physical mount authority and exact source revision before any native use.

## Executable source-verification sequence

`src/zog/host_install/resident_b_acceptance_handoff.py` verifies the four distinct signed identities, exact source pin `06e2714ff032dc8ca985d056a1e8800515847f65`, generation/STATE/device/permission consistency, and an explicit **no-native-acceptance** claim. It returns only `CROSS_OWNER_SIGNED_CLAIMS_MATCH_UNACCEPTED`, with `generation_accepted=null`, `native_activation_allowed=false` and `physical_mounts_independently_verified=false`.

`tests/test_resident_b_acceptance_handoff.py` checks this interface against the actual pinned image-build PR #16 verifier on a disposable synthetic rootfs. It rejects wrong generation, substituted rootfs/STATE device or mount IDs, wrong PARTUUID/installation, false read-only/STATE ownership, forged or re-used signing keys and fabricated acceptance. The image-build verifier rejects an actual substituted installed executable even when source-level claims are otherwise coherent. No source-only signature is equivalent to a kernel-reported mounted device.

## Native Work evidence and stop conditions

Future disposable native acceptance must capture selected rootfs generation and source receipt under its own independently authenticated provenance; actual partition table/PARTUUIDs and selected read-only rootfs mount; authenticated STATE mount identity across reboot; installed artifact hashes, wheel RECORD entries and interpreter/OpenSSL/SQLite/CA loader provenance; root-control socket numeric GID and actual ownership; and disabled/controlled systemd unit status. Source claims do not replace physical mount inspection, native kernel and wheel evidence or original rights/redistribution approval.

A protected Host authority selects those input keys/pins and witnesses and compares runtime `/proc/self/mountinfo`, `stat`, `statvfs` and systemd evidence to immutable selected identities. Only that future independent owner may render a native approval decision with explicit operator authorization; neither source verifier creates, signs or declares one. No actual generation is selected, no service activated, and no STATE, EBS, EFI partition or Amazon Linux boot input was changed by this work.

**Source status: interface CI PASS. Native Resident B NO-GO.**
