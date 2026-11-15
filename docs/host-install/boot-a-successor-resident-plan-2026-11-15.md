# Boot A successor — exact resident disposable installation plan (2026-11-15)

Owner: host-install Regular. Tracking: [host-install issue #4](https://github.com/zog144/host-install/issues/4).
Native owner: host-install + host-deploy Work. **Source selection only; no disk or boot authorization.**

## Why this is a new plan

The original [first Boot A plan](../../src/zog/host_install/first_boot_a_plan.py)
remains frozen to failed image-build generation
`5af34ec67cbfdcd1e7936bf70e3cf2f5c6945c7e3de5f95993918325f6e29c44`.
The October 30 UEFI attempt reached the reviewed AL2023 kernel/initramfs and mounted
HOST-A read-only by PARTUUID, but did **not** reach resident PID 1:
`initrd-switch-root` rejected the target root's missing OS-tree marker.
Never relabel that attempt as PASS or patch that generation after publication.

The October 31 image-build Work acceptance verified the **distinct**, inactive
immutable corrected generation

```
273de2a04a8a0b8d4db3005bca078639f3c2fdcd6f9e24a9619d2b0ca6947aab
```

- Reviewed producer source `68d6397ca20c4651df8f13c8a840dc8f77d55034`.
- Retained targeted parent `45a81ec3ea473bfa397e546b5c0ec1ae306bf00cb864eaa9a86d94c13c623f2e`.
- 40,974-entry installed inventory, canonical archive around 4.19 GB,
  27-record provenance graph, installed Boot A verification PASS **at the
  publisher** (not a new boot test).
- Immutable `/usr/lib/os-release` contains exactly
  `NAME="Zog"`, `ID=zog`, `PRETTY_NAME="Zog"`; `/etc/os-release`
  is the exact symlink `../usr/lib/os-release`.
- The successor's rebuilt systemd-boot EFI has a different SHA-256 from the
  failed predecessor. **Do not reuse the former EFI digest or archive digest.**
- The old failed attempt remains separate evidence; the corrected generation
  has **not yet been tested in the disposable UEFI VM**.

The available source handoff does not include all exact successor canonical
manifest/archive/inventory/EFI digest values. The plan therefore records the
known **exact selected generation** while keeping those artifact byte pins
explicitly `null` and denying device writes. These are not substitutes for
retained source evidence: Work must reopen the original image-build generation
and obtain/verify every exact digest before materialization.

## Concrete GPT / root selection

The executable read-only command is:

```sh
host-install successor-boot-a-plan
# Equivalently:
python3 -m zog.host_install successor-boot-a-plan
```

The checked-in identical JSON is
[`examples/resident-boot-a-successor-2026-10-31/plan.json`](../../examples/resident-boot-a-successor-2026-10-31/plan.json).

This is a **32,768 MiB disposable disk**, original disk GUID
`cfa94099-d379-5c5a-9f98-384f941cf237`, GPT, with exactly the five
original partitions:

| Role | MiB | Filesystem | PARTUUID | Rootfs UUID, if applicable |
|---|---:|---|---|---|
| ESP | 512 | FAT32 | `9d57e75e-93aa-50ec-9940-4c61ad99115c` | ESP identity in its actual FAT32 artifact |
| HOST-A | 8192 | ext4, selected **read-only** | `79c78b1d-84d6-5fc4-bb31-deb9a6d7091e` | `f18601cd-d219-5d6b-a6b0-fa499489cb63` |
| HOST-B | 8192 | ext4, inactive recovery | `0e93acb9-77bb-5f87-91d3-8fc35d4ac6fa` | `41dd3ee3-f027-5cf0-a5e4-f29874b724b4` |
| STATE | 2048 | ext4 | `8d6760a1-bfe2-5bbb-8bd9-063bfaedb871` | `656042e5-d689-5141-b94d-d99171ddfe3d` |
| APPLICATIONS | 2048 | ext4 | `7c54dcb0-f0d9-5287-892b-0604c74e18f7` | `b8d40caf-eea2-5159-9f35-4216f3eeef12` |

ESP uses the **exact loader bytes in the new verified generation**, copied
without modifying the selected immutable HOST filesystem. The installation
specific EFI command line must include:

```
root=PARTUUID=79c78b1d-84d6-5fc4-bb31-deb9a6d7091e ro
```

HOST-B remains unpopulated: its generation is explicitly `null`; the
installer cannot invent a recovery generation. Mounted `/state` and
`/applications` on the immutable root remain empty root:root mode `0000`
until separately verified partitions are mounted at Resident B. No
machine-specific identity, keys, UUIDs, or boot selector are added to image-build
rootfs bytes.

## Frozen reviewed foreign boot provider

Retain the original accepted Amazon Linux 2023 x86_64 bundle:

- Kernel: `6.18.44-99.149.amzn2023.x86_64`,
  SHA-256 `1faf0278011e0d62f01b28ddf81fc32af9e3fd032be0b805a1d38d981933431b`,
  14,207,224 bytes.
- Initramfs: SHA-256
  `06bca6e41de36109384ba019212ab1be72643a578d0afb9f3fa3c561a190f599`,
  21,381,902 bytes.
- Modules inventory:
  `8dbf40e1497ff8857a6a0602e66626155e897cfd54b6731aa1eea8f842899da4`.
- Kernel config:
  `de3812ae0e81108f86550781cac8302c8b400bf7bfefe5ea23e115074b6e0ef6`.
- dracut `102-3.amzn2023.0.4.x86_64`.

The old native test proved PARTUUID dispatch and read-only root mounting
with this provider; it did **not** prove switch-root to the corrected Zog
resident PID 1. That acceptance must be obtained by a new Work boot attempt.

## Exact Work pre-write handoff

1. Reopen the retained *new* generation under image-build and verify:
   generation ID; canonical manifest/record; 40,974-entry inventory;
   27-record graph; archived rootfs SHA-256/byte count; content manifest;
   publication-recovery receipt; installed verification identity and command;
   `/usr/lib/os-release` content and `/etc/os-release` symlink; exact
   successor EFI loader SHA-256/size. **Do not populate these fields from
   `first_boot_a_plan`, which is the failed predecessor.**
2. Check all frozen five-partition identities, selected HOST-A PARTUUID,
   reserved empty HOST-B, and exact foreign AL2023 kernel/initramfs/modules
   bytes again on the disposable target.
3. Only after exact producer byte pins and ordinary operator disk approval
   may Work construct a physical-device transaction. This source plan itself
   has `device_writes_authorized=false` and
   `native_boot_authorized=false`; it contains **no disk-write operation**.
4. Materialize the source-verified archive into HOST-A read-only with
   no post-publication os-release patch; copy the verified new EFI only to ESP;
   retain all original mountpoint modes and installation-specific EFI config.
5. Boot, prove UEFI → reviewed AL2023 initramfs → selected HOST-A read-only →
   `/usr/lib/systemd/systemd` as PID 1; journal and serial/getty work.
   Reboot and attest live HOST-A PARTUUID and exact generation. Test fallback
   without inventing HOST-B image bytes.

Certbot, DNS, certificates and station-access are not Boot A gates. Resident B
remains a separate subsequent milestone; all installed private STATE and
APPLICATIONS inspection, network services and Python SSL/SQLite acceptance
must be verified then.

## Source regression

`tests/test_successor_boot_a_plan.py` and
`.github/workflows/boot-a-successor-plan.yml` check exact generation,
GPT IDs/geometry, the root argument and read-only state, reviewed foreign
boot hashes, immutable os-release marker/symlink, absence of copied failed
archive/EFI digests, preservation of the legacy failed plan, denial of
mutated selections and equality between CLI and checked-in JSON.

**Status: concrete source plan selected, no native installation/boot run,
no rootfs mutation, no device-write authorization.**
