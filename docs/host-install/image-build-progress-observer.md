# Dedicated host-welcome image-build progress observer

**Status:** host-install 0.11.0 source/deployment implementation aligned to
image-build native-deployment contract v1. Production activation remains
**NO-GO** until disposable-host Work acceptance.

## Exact producer contracts

Producer-owned deployment reference:

- repository: `zog144/image-build`
- deployment-reference revision:
  `b5cf3d761087c157b71724986bc94503089932a2`
- deployment module:
  `zog.image_build.post_install_progress_deployment`
- deployment module Git blob:
  `bd0d13be67bcebc380001fb64b646f6e04400640`
- contract: `image-build-post-install-progress-native-deployment-v1`
- socket template blob:
  `8e7e7bbd6af41572441f33e8db178f6588e117d6`
- service template blob:
  `8c9b548d0e47b1f5a82fe511d2db81c4865dfab3`

The authenticated runtime projection/source binding intentionally remains:

- source revision:
  `fcc12f3db959afe395b1adfb5b0b4dc1f16a3258`
- projection: `image-build-post-install-progress-v2`
- wire: `image-build-post-install-progress-rpc-v2`
- source binding: `image-build-post-install-source-v1`

The 13 security-critical snapshot modules are byte-identical between the
runtime revision and the later deployment-reference revision. The consumer
policy therefore continues to name `fcc12f3...`; the root-owned staging
manifest separately records `b5cf3d...` as the deployment reference.

Reviewed host-welcome consumer:
`6edb11140a44a10061e5308fab03a43d9008dbfc`.

## Fixed v1 role

The root-owned policy is exactly:

`/etc/zog/host-welcome-image-progress-observer.json`

with schema `zog-host-welcome-image-progress-observer-v1` and only:

- `schema`;
- `enabled=true`;
- independently resolved numeric `consumer_uid`;
- independently resolved, distinct numeric `producer_uid`;
- `socket=/run/host-welcome/image-progress.sock`;
- `image_build_source_commit=fcc12f3db959afe395b1adfb5b0b4dc1f16a3258`.

The first-wave immutable allowlist is exactly:

- `agreety`;
- `firefox-esr`;
- `greetd`;
- `i3`;
- `xorg-server`.

Chromium, TurboVNC, Weston/Wayland and the non-ESR Firefox name are deliberately
not admitted by v1.

## Independently resolved live identities

The staging CLI accepts no consumer or producer UID/GID values. Running as root,
host-install:

1. validates the actual dedicated host-welcome account;
2. resolves one canonical durable image-build state root;
3. requires its `image-build/` component state directory to have a protected,
   distinct non-root owner;
4. resolves that numeric owner through the host account database and validates
   its primary GID;
5. rejects symlinked, group/world-writable or ownership-conflicting state
   ancestry;
6. verifies the resolved producer can read/traverse that fixed state root.

No UI-supplied identity is accepted.

## Exact producer-owned unit pair

Host-install packages the producer templates byte-for-byte and verifies them
against the pinned `b5cf3d...` checkout before staging.

The socket is:

```text
ListenStream=/run/host-welcome/image-progress.sock
SocketUser=<resolved-host-welcome-uid>
SocketMode=0600
DirectoryMode=0711
Accept=no
Backlog=8
RemoveOnStop=yes
```

The service runs as the resolved image-build producer UID/GID and fixes:

```text
python -m zog.image_build.post_install_progress_broker
  --state-dir <protected-image-build-state-root>
  --authorized-uid <resolved-host-welcome-uid>
  --application agreety
  --application firefox-esr
  --application greetd
  --application i3
  --application xorg-server
  --source-repository zog144/image-build
  --source-revision fcc12f3db959afe395b1adfb5b0b4dc1f16a3258
```

The reference service clears inherited `PYTHONPATH`, restricts networking to
AF_UNIX, drops capabilities, applies no-new-privileges and namespace/kernel
hardening, and exposes the selected image-build state root read-only. It has no
station-access socket, controller-progress socket or root-control socket.

The producer broker itself permits exactly one systemd-activated AF_UNIX socket,
authenticates `SO_PEERCRED` before request parsing and exposes only the bounded
read-only `snapshot` operation.

## Source and installed-software attestation

Before rendering the overlay, host-install verifies:

- the exact deployment module blob at `b5cf3d...`;
- the exact producer socket and service template blobs;
- the producer-defined 13 security-critical runtime module Git blobs associated
  with `fcc12f3...`.

The 13 modules are the broker, projection, application software/view readers,
build views, errors, filesystem, metadata, engine, rootfs compatibility,
artifact observations, runtime facilities and application data targets.

After the aggregate `zog` wheel is installed:

```sh
host-install host-welcome-image-progress-attest-installed \
  --python-executable /usr/bin/python3
```

The attester requires root, rejects inherited `PYTHONPATH` and `PYTHONHOME`,
verifies the approved root-controlled interpreter and aggregate distribution,
imports all 13 reviewed modules, and requires every one to have:

- a protected regular-file origin under the aggregate distribution;
- the exact reviewed Git blob identity;
- an independently calculated SHA-256;
- a matching SHA-256 entry in the aggregate wheel `RECORD`.

The `RECORD` itself is protected and SHA-256 identified. Successful software
attestation still reports `production_activation_authorized=false`.

## Selection, rootfs and boot semantics

host-install remains sole post-install selection/intent owner. This observer
does not infer selection from a pipeline and cannot write the selection.

Native acceptance must present the exact immutable selection receipt/revision
and monotonically bound sequence. A compatibility-checked publication must name
the exact selected retained rootfs generation. Missing, superseded or mismatched
selection/rootfs evidence is unknown rather than success.

The live producer snapshot must name the current Linux boot. Durable terminal
controller command evidence may legitimately name an older boot after restart;
that does not imply a live process. The observer cannot submit, resume, retry,
cancel, publish, install or start services.

## Staging

```sh
host-install host-welcome-image-progress-stage \
  --output /path/to/new-overlay \
  --image-build-state-root /fixed/image-build/state/root \
  --image-build-source /path/to/image-build@b5cf3d761087c157b71724986bc94503089932a2 \
  --python-executable /usr/bin/python3
```

`--image-build-source` names the deployment-reference checkout. host-install
uses it to validate the later deployment contract/templates and the 13
byte-identical runtime modules. The consumer-visible policy still pins
`fcc12f3...`.

Staging writes only a new root-owned overlay. It never calls systemctl, enables
the socket, mutates image-build state or grants graphical readiness.

## Native Work gate

Disposable-host acceptance must still return:

- actual safely resolved consumer and producer UID/GID values and supplementary
  group evidence;
- installed module SHA-256 values plus wheel `RECORD` digest;
- actual selection receipt/sequence, selected rootfs generation and reviewed
  application-view identities where available;
- socket parent/inode/mode and SELinux/LSM evidence;
- authorized observer success and wrong-UID denial at both DAC and broker
  `SO_PEERCRED`;
- source-pin and stale/wrong-boot replay rejection;
- activation/restart/reboot cleanup and read-only state proof;
- truthful failure, cancellation, interruption/reboot, generation mismatch and
  absent/superseded publication behavior;
- isolation from the station and controller observers;
- offline first-boot/getty usability with the optional observer absent;
- disposal/cleanup evidence.

Passing source CI is not production activation authorization.
