# Dedicated host-welcome controller-progress observer

**Status:** host-install 0.9.0 source/deployment-profile implementation.
Native systemd, UID/DAC/SELinux, reboot and getty acceptance remain a separate
disposable-host gate.

This profile implements the host-install portion of the 2026-10-17
host-welcome console observer handoff. It is intentionally separate from the
station-access application-progress observer introduced in 0.8.0.

## Runtime model and visibility

host-welcome is treated as a **host-rootfs bootstrap consumer**, not a selected
box-control application. Its controller-progress socket therefore lives directly
at:

`/run/host-welcome/controller-progress.sock`

No arbitrary host `/run` bind is introduced. No station-access socket,
controller credential directory, raw STATE path or unrelated runtime file is
mounted into host-welcome.

The existing station listener remains unchanged at
`/run/zog-host-export/application-progress/application-progress.sock`; this
profile neither rewrites nor grants access to it.

## Numeric peer authorization

The deployment owner supplies the authoritative numeric UID of the dedicated
host-welcome account plus the numeric controller-owner UID/GID. host-install does
not invent a UID or derive controller ownership from a generic username.

The generated socket is:

```text
ListenStream=/run/host-welcome/controller-progress.sock
SocketUser=<authoritative host-welcome UID>
SocketMode=0600
```

The activated broker runs as the distinct controller owner:

```text
User=<controller-owner UID>
Group=<controller-owner GID>
python -m zog.box_control.application_progress_broker \
  --project <fixed-controller-project> \
  --authorized-uid <authoritative host-welcome UID> \
  --root-control-socket /run/zog/root-control.sock
```

The broker therefore performs kernel `SO_PEERCRED` authorization against the
same UID that owns the mode-0600 socket.

## Protected policy

The staged root-owned policy is exactly:

`/etc/zog/host-welcome-progress-observer.json`

with schema `zog-host-welcome-progress-observer-v1` and only these fields:

- `schema`;
- `enabled=true`;
- `consumer_uid`;
- `controller_owner_uid`;
- `socket=/run/host-welcome/controller-progress.sock`;
- `box_control_source_commit`.

The staged file is mode 0444 under the root-owned non-group/world-writable
`/etc/zog` directory. The host-welcome consumer independently rejects symlinks,
unsafe ownership/mode, unknown or duplicate fields and wrong socket/UID values.

## Reviewed box-control bytes

The policy metadata pins box-control commit
`644170fc441863307092f329bf7e23cb64eb33e2`.

Metadata alone is not activation evidence. host-install also pins the Git blob
identities of the reviewed:

- `zog.box_control.application_progress_broker`;
- `zog.box_control.application_progress_client`.

Staging requires the reviewed box-control source checkout and refuses changed
module bytes. After aggregate installation,
`host-install host-welcome-progress-verify-installed` compares the actual
imported module files with those same reviewed blob identities. The profile
manifest marks the socket as
`enable-after-installed-byte-verification`; deployment must not enable it on
metadata alone.

## Boot and authority boundary

The socket may be enabled as an optional multi-user service but does not make
STATE, station-access, network, image-build, graphics or the observer itself a
prerequisite of getty. It owns no TTY and starts no polling loop.

Missing controller availability therefore remains an optional
`unavailable` observation while the independent host-install bootstrap producer
can still report headless installation state.

The profile grants no authority to submit/cancel builds, launch applications,
write STATE, start a login manager or reboot the host.

## Staging

```sh
host-install host-welcome-progress-stage \
  --output /path/to/new-overlay \
  --controller-project /absolute/controller/project \
  --consumer-uid <uid-from-authoritative-host-welcome-account> \
  --controller-owner-uid <uid-from-controller-owner-evidence> \
  --controller-owner-gid <gid-from-controller-owner-evidence> \
  --box-control-source /path/to/reviewed/box-control
```

The overlay contains the dedicated systemd socket/service, protected policy and
a manifest recording the runtime model, source/blob pins and excluded
capabilities. Staging never calls systemctl or mutates STATE.

After the aggregate Zog Python installation is present:

```sh
host-install host-welcome-progress-verify-installed
```

must succeed before the socket is enabled.

## Native acceptance still required

A disposable host must verify the actual host-welcome UID and controller owner
against authoritative account/grant evidence, mode/ownership/SELinux and socket
ancestry, wrong-peer denial before request parsing, server peer UID, exact
installed-byte verification, current-boot/freshness behavior, activation and
restart/reboot cleanup, controller timeout, offline/headless getty fallback and
continued isolation of the station-access observer.

This source profile is not native acceptance and does not authorize a graphical
login stack.
