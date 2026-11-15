# Boot A resident system-account materialization — source-to-image-build Work handoff

November 15, 2026 · host-install Regular · proposed source selection
`regular/resident-boot-accounts-materialization-20261115`

## Actual boot findings

The independently booted successor generation
`273de2a04a8a0b8d4db3005bca078639f3c2fdcd6f9e24a9619d2b0ca6947aab`
reached **resident systemd PID 1**, journald, selected HOST-A by PARTUUID and
read-only root across two observed boot IDs. It is not the missing-os-release
failure that affected the earlier `5af34ec6...` generation.

The remaining observed problems are:
- Systemd 261.2's installed getty unit selected `/usr/bin/agetty`, but
  util-linux installs `/usr/sbin/agetty`; image-build PR #25 has corrected
  `-Dagetty-path=/usr/sbin/agetty`.
- `systemd-journal` group was absent in resident `/etc/group`. Journald
  runs and logs exist, but its access socket cannot apply the missing group.
- `messagebus` user was absent in resident `/etc/passwd`. The selected
  system D-Bus service cannot start successfully.

Those are **upstream service identities**, not the discarded
`certbot-build-owner` / `certbot-build-worker` compiler identities.
Do not reintroduce any dedicated compiler accounts or UID/GID switching.

## Chosen boundary: offline sysusers before rootfs publication

Image-build PR #25 publishes upstream vendor declarations:
- `/usr/lib/sysusers.d/systemd-journal.conf` with a group declaration
  `g systemd-journal - -`;
- `/usr/lib/sysusers.d/dbus.conf` with the user declaration
  `u messagebus - ...`.

Vendor fragments alone **do not materialize NSS entries** on a read-only HOST.
The new `host-install-resident-accounts` source command performs this
ordinary **offline staging step**, rather than adding runtime account creation
to an immutable filesystem or editing a published image after verification.

The command selects **only** those two upstream sysusers declarations,
uses an explicit OS-managed `systemd-sysusers --root=<staged-root>` binary,
and validates actual `/etc/passwd` and `/etc/group` before and after.
It preserves all existing root/Zog account entries, refuses duplicate UID/GID
or forbidden compiler account names, checks service identities and non-login
messagebus shell, and records actual allocated IDs without pinning new
numeric UID/GID values. No command constructs its identity from the
interactive login, `$USER`, `$HOME`, or a process-account selector.

## Exact image-build Work sequence

Install the reviewed host-install component in the **existing** authorized
build environment. On the unpublished **fully assembled** rootfs staging
directory, after systemd/D-Bus package outputs have been installed but
**before** image-build inventories, hashes, verifies, archives or publishes
the successor generation, run:

```sh
set -euo pipefail
ROOTFS="$EXACT_UNPUBLISHED_ROOTFS_STAGE"
SYSUSERS=/usr/bin/systemd-sysusers
test -d "$ROOTFS" && test "$ROOTFS" != /
test -x "$SYSUSERS"

host-install-resident-accounts --inspect --root "$ROOTFS"
host-install-resident-accounts --materialize --root "$ROOTFS" \
  --sysusers-executable "$SYSUSERS"
host-install-resident-accounts --verify --root "$ROOTFS"
```

`ROOTFS` is deliberately a mandatory independently selected build-stage
path, **not** the mounted installed HOST-A partition, running process /,
or a previously accepted immutable generation. The command will refuse /.
`SYSUSERS` must be a validated OS-owned executable, not a binary
downloaded or selected through a mutable Project.

Required native report fields:
- `vendor_declarations.systemd-journal.kind=g` and
  `vendor_declarations.messagebus.kind=u`;
- `before.passwd_sha256`, `before.group_sha256`, and
  `after.passwd_sha256`, `after.group_sha256`;
- `after.created_groups` subset `[systemd-journal,messagebus]`,
  `after.created_users` subset `[messagebus]`;
- `after.all_preexisting_records_preserved=true`;
- `after.messagebus_uid/gid` nonzero and identical to the matching
  private group's GID; `after.systemd_journal_gid` nonzero;
- `materialized=true`, `compiler_users_created=false`.

The upstream tool may create normal shadow/gshadow data along with the passwd
and group entries. This is native package/system-account state, not
machine identity, credentials or an enrollment key. Do not put a Host
machine-id, personal account password or cryptographic secret into this
reusable immutable image.

Re-run `--verify` after image-build has composed its final tree, and add
`etc/passwd`, `etc/group`, the exact two sysusers vendor fragments and
their content hashes to the **new generation's** canonical installed file
inventory and verification record. Inspect the resulting group/account lines
rather than assuming fixed numeric IDs. Do not run sysusers against a
sealed/published generation, manually patch HOST-A after publication, or
carry the prior image's exact archive/EFI checksums into the new generation.

## New generation and disposable boot acceptance

image-build Work owns compilation of PR #25 with the corrected getty units,
followed by this offline account step, complete inventory/provenance,
rootfs archive/EFI byte verification and **new generation publication**.
Preserve existing os-release/switch-root success, the selected GPT roles
ESP/HOST-A/HOST-B/STATE/APPLICATIONS, fixed selected HOST PARTUUID and
foreign Amazon Linux 2023 kernel/initramfs. host-install's PR #39
disposable plan is the previous-generation historical selection; issue a
**new plan with the exact newly verified successor ID/bytes** rather than
rebinding the previous sealed generation behind the same identifier.

Then host-install + image-build Work repeat a disposable UEFI boot, proving:
1. switch-root to resident systemd PID 1 from selected read-only HOST-A;
2. systemd getty unit ExecStart points to installed `/usr/sbin/agetty`
   and a usable serial/getty console is available;
3. `systemd-journal` is resolvable via the installed resident NSS files,
   journald sockets work and logs can be read;
4. `messagebus` is resolvable, the system D-Bus service starts and the
   bus can be queried;
5. exact generation and HOST PARTUUID report remain correct across reboot;
6. clean shutdown and journal/serial evidence are retained.

No Certbot, AWS S3, dedicated compiler worker, external registrar,
command-center signature or additional account-provisioning mechanism
belongs in this Boot A fix.

**Source-only disposition:** host-install Regular does not compile systemd,
alter the live Host, apply passwd/group to the running system, rebuild an image,
create an EC2 instance, publish a generation or accept the native boot.
