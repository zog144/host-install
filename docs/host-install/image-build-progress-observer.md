# Dedicated host-welcome image-build progress observer

**Status:** host-install 0.13.3 source/deployment implementation aligned to
image-build native-deployment contract v2. Native transport/lifecycle evidence
exists, but production activation remains **NO-GO** until the consistent bundle
rerun and remaining malformed-response cases are dispositioned.

## Exact producer contracts

Producer-owned deployment reference:

- repository: `zog144/image-build`
- deployment-reference revision:
  `10d5c89f9ad865f3f58094ba2b5a629c211d918d`
- deployment module:
  `zog.image_build.post_install_progress_deployment`
- deployment module Git blob:
  `0ed5e383f0aeaa49761a82cfc94b7cc3148075da`
- contract: `image-build-post-install-progress-native-deployment-v2`
- socket template blob:
  `8e7e7bbd6af41572441f33e8db178f6588e117d6`
- service template blob:
  `111d878e873a0c393153cedb148c2003b227cbc7`

The authenticated runtime projection/source binding intentionally remains:

- source revision:
  `7348ec730a3181f1a8ecc62a6e4d633ce191674a`
- projection: `image-build-post-install-progress-v2`
- wire: `image-build-post-install-progress-rpc-v2`
- source binding: `image-build-post-install-source-v1`

The 13 security-critical snapshot modules are byte-identical between the
runtime revision and the later deployment-reference revision. The consumer
policy therefore continues to name `7348ec73...`; the root-owned staging
manifest separately records `10d5c89f...` as the deployment reference.

Reviewed host-welcome consumer:
`1bb771b00be9f5e1a52e5419af9f78662c7913e8`.

## Fixed v1 role

The root-owned policy is exactly:

`/etc/zog/host-welcome-image-progress-observer.json`

with schema `zog-host-welcome-image-progress-observer-v1` and only:

- `schema`;
- `enabled=true`;
- independently resolved numeric `consumer_uid`;
- independently resolved, distinct numeric `producer_uid`;
- `socket=/run/host-welcome/image-progress.sock`;
- `image_build_source_commit=7348ec730a3181f1a8ecc62a6e4d633ce191674a`.

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
against the pinned `10d5c89f...` checkout before staging.

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
  --source-revision 7348ec730a3181f1a8ecc62a6e4d633ce191674a
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

- the exact deployment module blob at `10d5c89f...`;
- the exact producer socket and service template blobs;
- the producer-defined 13 security-critical runtime module Git blobs associated
  with `7348ec73...`.

The deployment contract also records transport `image-build-post-install-progress-linux-credentials-v1`. Under systemd socket activation the listener `SO_PEERCRED` may identify PID 1/root; consumer authentication of the producer therefore requires the broker's explicit reply `SCM_CREDENTIALS`, matched to the protected policy producer UID. The broker authenticates the client with accepted-connection `SO_PEERCRED` before request parsing.

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
  --image-build-source /path/to/image-build@10d5c89f9ad865f3f58094ba2b5a629c211d918d \
  --python-executable /usr/bin/python3
```

`--image-build-source` names the deployment-reference checkout. host-install
uses it to validate the later deployment contract/templates and the 13
byte-identical runtime modules. The consumer-visible policy still pins
`7348ec73...`.

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


## 0.13.2 correction

The reviewed runtime source is now
`7348ec730a3181f1a8ecc62a6e4d633ce191674a`; the root-controlled deployment
reference is
`10d5c89f9ad865f3f58094ba2b5a629c211d918d`. Of the thirteen installed
runtime modules, only `zog.image_build.post_install_progress_broker` changed:
its reviewed Git blob is
`e7ba6eab10e70e91fc5921bba1eec26f31ace1db`. The other twelve module pins
remain unchanged.

The socket template remains blob
`8e7e7bbd6af41572441f33e8db178f6588e117d6`; the service template is now
`111d878e873a0c393153cedb148c2003b227cbc7`, and the deployment module is
`0ed5e383f0aeaa49761a82cfc94b7cc3148075da`.

Installed-software attestation continues to require the protected aggregate
`zog` wheel, exact Git-blob identity and wheel `RECORD` SHA-256 for all
thirteen modules. A successful source/installed-byte gate does not authorize
production. Native Work must still prove response `SCM_CREDENTIALS`, wrong
sender rejection, disconnect containment with the same broker process,
socket stop/start and reboot, read-only state, and offline getty fallback.


## 0.13.3 consumer provenance correction

The staged profile manifest now identifies the exact reviewed host-welcome
SCM_CREDENTIALS consumer as
`1bb771b00be9f5e1a52e5419af9f78662c7913e8`.

This field is provenance metadata only. It does not change the consumer-visible
policy schema, numeric consumer/producer UID authority, image-build runtime pin,
deployment reference, unit templates, transport authentication, socket DAC,
or production activation state.

Regression coverage requires the generated `profile.json` field
`host_welcome_consumer_commit` to equal the reviewed consumer revision exactly.
