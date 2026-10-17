# Dedicated host-welcome controller-progress observer

**Status:** host-install 0.10.0 source/deployment implementation. Native socket,
DAC/SELinux, reboot and getty acceptance remains a separate disposable-host gate.

This profile implements the host-install side of the reviewed box-control
host-welcome observer contract at
`8249715708c6ef8a1fd30a3fb529b4034ffffe25`. It remains completely separate
from the station-access progress observer.

## Independently resolved numeric identities

The public staging command no longer accepts consumer or controller UID/GID
arguments. Running as root, host-install derives them from independent host
facts:

1. the dedicated `host-welcome` account is validated through the existing
   host-install account checker, including a unique non-root UID/GID, nologin
   shell and no supplementary groups;
2. the fixed controller project directory must be a protected, non-symlinked,
   non-group/world-writable directory owned by an unprivileged host account;
3. that account UID/GID must agree with the actual host account database;
4. `/run/zog/root-control.sock` must have protected root-owned ancestry and
   its socket owner UID must equal the controller project owner UID.

The welcome UID and controller UID must be distinct. A mismatch aborts staging.
There are no numeric UID command-line overrides.

## Dedicated unit pair

The staged socket is exactly:

```text
ListenStream=/run/host-welcome/controller-progress.sock
SocketUser=<resolved-host-welcome-uid>
SocketMode=0600
Accept=no
```

The service runs as the resolved controller owner and invokes the reviewed
console-specific broker contract:

```text
<approved-python> -m zog.box_control.application_progress_broker \
  --project <fixed-controller-project> \
  --authorized-uid <resolved-host-welcome-uid> \
  --root-control-socket /run/zog/root-control.sock \
  --observer-role host-welcome \
  --controller-owner-uid <resolved-controller-owner-uid>
```

The consumer never receives direct access to the root-control socket.

## Protected policy

The staged root-owned file remains exactly:

`/etc/zog/host-welcome-progress-observer.json`

with schema `zog-host-welcome-progress-observer-v1` and only:

- `schema`;
- `enabled=true`;
- `consumer_uid`;
- `controller_owner_uid`;
- `socket=/run/host-welcome/controller-progress.sock`;
- `box_control_source_commit=8249715708c6ef8a1fd30a3fb529b4034ffffe25`.

The file is mode 0444 under root-controlled `/etc/zog`. Source metadata is not
treated as installed-software proof.

## Reviewed source inventory

Staging checks the pinned Git blob identities and SHA-256 values of the
security-critical box-control observer path:

- `application_progress_broker.py`;
- `application_progress_client.py`;
- `application_progress.py`;
- `role_broker.py`;
- `api.py`;
- `project.py`;
- `errors.py`;
- `root_protocol.py`;
- `runtime/root_control.py`.

Any changed source byte aborts staging.

## Installed aggregate attestation

After the aggregate `zog` wheel is installed, run:

```sh
host-install host-welcome-progress-attest-installed \
  --python-executable /usr/bin/python3
```

This command is read-only. It requires root and rejects a non-empty
`PYTHONPATH`. It verifies that the running interpreter is the approved service
interpreter and that its path is root-controlled and non-writable.

The verifier then loads the actual installed `zog` distribution and the nine
reviewed box-control modules. For every module it requires:

- a real regular loaded source file;
- a path beneath the installed aggregate distribution root;
- root ownership and no group/world write on the file and ancestry;
- the exact reviewed Git blob identity;
- a separately calculated SHA-256;
- a matching SHA-256 entry in the aggregate wheel `RECORD`.

The wheel `RECORD` itself must be present once, protected, and is SHA-256
identified in the returned attestation. The result also records the actual
module origins, aggregate version and interpreter path.

A successful software attestation still returns
`production_activation_authorized=false`: native wrong-peer, systemd, LSM,
reboot and getty acceptance is still mandatory.

## Staging command

```sh
host-install host-welcome-progress-stage \
  --output /path/to/new-overlay \
  --controller-project /absolute/controller/project \
  --box-control-source /path/to/box-control@8249715708c6ef8a1fd30a3fb529b4034ffffe25 \
  --python-executable /usr/bin/python3
```

The overlay contains the dedicated socket/service, exact policy and a manifest
recording the independently resolved identity evidence and source inventory.
The manifest explicitly marks enablement as blocked until installed-software
attestation **and** native acceptance complete.

## Runtime visibility and fallback

host-welcome remains a native host-rootfs bootstrap consumer. No station
host-binding policy is changed. It receives no station socket, raw STATE,
controller credentials, arbitrary host `/run`, or direct root-control access.

STATE, station-access, root-control availability, network, image-build, graphics
and the optional observer do not become getty prerequisites. If the optional
controller is unavailable, the separately authenticated host-install headless
bootstrap path remains usable.

## Native gate still open

Host-deploy Work must still verify the live account/grant identities,
supplementary groups, socket parent/inode/mode/SELinux, DAC and broker
`SO_PEERCRED` denial of wrong UIDs, positive correct-UID access, actual server
UID, systemd activation/restart/reboot cleanup, timeout/stale-boot behavior,
offline getty fallback and continued isolation of the original station listener.

Production observer activation remains NO-GO until that acceptance is retained.
