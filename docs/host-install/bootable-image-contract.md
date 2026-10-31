# Bootable resident image contract

Owner: host-install Regular
Source verifier: image-build Regular
Native acceptance: host-install + host-deploy Work

This contract separates three questions that were previously mixed together:

1. Is an exact immutable image-build rootfs generation structurally capable of becoming a resident Zog boot image?
2. Does the separately bound first-boot provider contain the required UEFI, kernel, initramfs and module capabilities?
3. Does a real disposable VM actually boot those exact bytes and preserve installation/STATE invariants?

A source PASS for the first two does not imply native boot acceptance.

## Machine-readable contract

Run `host-install bootable-image-contract`. Its schema is `zog-host-install-bootable-image-contract-v1`.

A reviewed image-build host-install artifact can be assessed without writing a disk:

    host-install bootable-image-assess /path/to/export --expected-id <trusted-artifact-id>

The command first uses image-build's canonical host_export.verify(). It then checks the verified rootfs inventory and boot-bundle structure. Native boot always remains NOT RUN.

## Immutable generation boundary

image-build must return one exact x86_64 rootfs generation with canonical generation/provenance identity and exact installed inventory. host-install must not fix missing boot components by modifying the selected HOST filesystem after generation selection. Missing OS bytes require a new immutable image-build generation.

Host-specific machine identity, host private keys, station credentials and installation-specific PARTUUIDs are forbidden from the reusable generation.

The rootfs must contain empty root:root mode 0000 mountpoints at /state and /applications. This makes absent persistent mounts fail closed instead of accepting writes into the immutable HOST slot.

## Disk and mount contract

The resident disk is GPT with exactly ESP, HOST-A, HOST-B, STATE and APPLICATIONS, in that order. ESP is FAT32; all four remaining partitions are ext4. HOST-A and HOST-B have equal capacity. The selected HOST slot is bound by PARTUUID and mounted read-only. STATE and APPLICATIONS are separately mounted writable partitions.

Runtime-only writable filesystems are /run, /tmp, /dev, /proc and /sys. /tmp is tmpfs mode 1777. Exact disk GUID, partition PARTUUIDs, filesystem UUIDs, selected slot and installation UUID are host-install identities, not image-build generation inputs.

## Boot gate A — UEFI to systemd PID 1

The first disposable boot test does not require station enrollment, Certbot, DNS, nginx or any certificate.

Required rootfs executables:

- /usr/lib/systemd/systemd
- /usr/lib/systemd/systemd-journald
- /usr/lib/systemd/systemd-udevd
- /usr/bin/systemctl
- /usr/bin/journalctl
- /usr/bin/udevadm
- /usr/bin/bash
- /usr/sbin/agetty
- /usr/bin/login
- /usr/bin/findmnt
- /usr/sbin/fsck.ext4
- /usr/bin/kmod

Required files:

- /usr/lib/systemd/system/getty@.service
- /usr/lib/systemd/system/serial-getty@.service
- /usr/lib/systemd/boot/efi/systemd-bootx64.efi
- /usr/lib/os-release

For the foreign AL2023 initramfs used by the first Boot A lane, systemd's switch-root
operation treats the resident init as systemd and therefore requires the target root
to be an OS tree. /usr/lib/os-release is the immutable vendor marker. host-install
must reject a candidate without it; installation must not add it after generation
selection.

The EFI loader belongs to the selected rootfs generation so image-build can bind its exact bytes. host-install copies those exact accepted bytes to the ESP and creates installation-specific loader configuration; the rootfs itself is not modified.

The first-pass kernel provider may remain foreign Amazon Linux 2023. A Zog-built kernel is not a prerequisite for this first boot experiment. The boot bundle must bind exact kernel, initramfs and matching modules/<kernel-release>/ content/provenance.

The initramfs must be independently shown capable of resolving root=PARTUUID=<selected-HOST-partuuid>, mounting ext4 root read-only, loading the storage driver required by the disposable VM, and switching root to /usr/lib/systemd/systemd.

The 2026-10-30 native attempt proved UEFI, the frozen foreign kernel/initramfs,
PARTUUID selection and read-only HOST-A, then failed in initrd-switch-root.service
before resident PID1. The selected generation 5af34ec67cbf... lacked both
os-release paths. With init=/usr/lib/systemd/systemd, systemctl recognizes that
init as the resident systemd binary and the system manager applies its OS-tree
check; a missing os-release therefore rejects SwitchRoot. That generation is
retained as failed evidence and must not be retried as an accepted boot input.

Boot A native PASS requires UEFI to execute the exact loader; exact reviewed kernel/initramfs selection; root mounted from the selected HOST PARTUUID read-only; PID 1 systemd; journald evidence; serial/getty recovery; and host-install's live host-generation report proving the booted slot from the live root PARTUUID.

## Resident gate B — persistent storage and core services

After Boot A, the same installation may proceed to Resident B.

Additional required executables:

- /usr/lib/systemd/systemd-networkd
- /usr/lib/systemd/systemd-resolved
- /usr/lib/systemd/systemd-timesyncd
- /usr/bin/networkctl
- /usr/bin/resolvectl
- /usr/bin/python3
- /usr/bin/dbus-daemon
- /usr/sbin/ip
- /usr/sbin/ss
- /usr/sbin/tc
- /usr/sbin/mkfs.ext4
- /usr/sbin/e2fsck
- /usr/bin/host-install
- /usr/bin/host-discover
- /usr/bin/box-control
- /usr/bin/root-control

Additional required file: /usr/lib/systemd/system/dbus.service.

image-build must also bind acceptance evidence for Python SSL + SQLite, the public CA trust store, systemd with seccomp, D-Bus, Kmod, the host-boot package batch and exact generation provenance.

Resident B native PASS requires exact STATE and APPLICATIONS mounts, verified STATE before private material is opened, host-install preparation without identity replacement, and basic D-Bus/network/Python trust probes.

## Explicitly outside Boot A and Resident B

Certbot issuance, ACME account creation, Cloudflare credentials, DNS mutation, certificate publication, nginx HTTPS cutover and station-access graphical services are not boot prerequisites.

## image-build verification handoff

image-build Regular should evaluate the currently intended rootfs generation and return:

1. exact generation ID and canonical provenance root;
2. exact rootfs inventory/verification record;
3. PASS/MISSING for every Boot A and Resident B path;
4. proof or blocker for systemd-boot exact bytes;
5. exact foreign Amazon Linux 2023 kernel/initramfs/modules provenance;
6. source determination of initramfs PARTUUID/ext4/storage-driver/switch-root support;
7. verification identities for systemd core + seccomp, host-boot packages, Kmod, Python SSL/SQLite and public CA trust;
8. any missing OS component that requires a new generation.

Current source facts requiring explicit review:

- image-build 68d6397ca20c4651df8f13c8a840dc8f77d55034 adds the immutable
  /usr/lib/os-release marker (and /etc/os-release symlink) to the systemd-final
  output and requires it in the targeted installed check;
- the accepted 2026-10-30 generation predates that correction and remains rejected;
- the current first-host design intentionally uses a foreign kernel; image-build has not built a Zog kernel and does not need to do so for Boot A.

Do not rebuild the whole rootfs merely because this contract exists. First inspect the exact candidate generation. Build a successor only for requirements that are actually missing or incompatible.

## Work boundary

Once image-build returns a source-complete successor generation containing the OS-tree marker, host-install Regular binds that exact generation into a new installation plan. The failed 5af34ec6... plan is historical evidence only and is not a retry input. A separate host-install/host-deploy Work run owns disposable-VM installation, reboot, Boot A evidence and subsequent Resident B evidence.

No source-only contract or image-build verification authorizes device writes, EC2 creation, production activation or release publication.
