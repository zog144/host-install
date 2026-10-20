# Dedicated host-welcome image-build progress observer

**Status:** host-install 0.11.0 source/deployment profile. Native systemd,
DAC/`SO_PEERCRED`, SELinux/LSM, reboot and getty acceptance remains a
separate disposable-host gate.

This profile implements the host-install side of the reviewed host-welcome /
image-build post-install progress contract.

Pinned producer source:

- repository: `zog144/image-build`
- source revision: `fcc12f3db959afe395b1adfb5b0b4dc1f16a3258`
- projection: `image-build-post-install-progress-v2`
- wire: `image-build-post-install-progress-rpc-v2`
- source binding: `image-build-post-install-source-v1`

Pinned consumer source:

- host-welcome: `6edb11140a44a10061e5308fab03a43d9008dbfc`

The observer is independent from both the station application-progress socket and
the host-welcome controller-progress socket.

## Fixed consumer contract

The root-owned consumer policy is exactly:

`/etc/zog/host-welcome-image-progress-observer.json`

with schema `zog-host-welcome-image-progress-observer-v1` and fields:

- `schema`;
- `enabled=true`;
- independently resolved numeric `consumer_uid`;
- independently resolved numeric `producer_uid`;
- `socket=/run/host-welcome/image-progress.sock`;
- `image_build_source_commit=fcc12f3db959afe395b1adfb5b0b4dc1f16a3258`.

No source directory, raw image-build state path, application selector, build job,
credential, mutation action or arbitrary evidence reference is exposed through
the host-welcome UI/RPC.

## Independent live identity resolution

The public staging command accepts no consumer or producer UID/GID values.

Running as root, host-install:

1. validates the dedicated host-welcome account using the existing
   `welcome_account()` contract;
2. requires a canonical durable image-build state root;
3. requires its `image-build/` component directory to exist with a distinct
   non-root owner and protected permissions;
4. resolves that owner through the host account database and rejects duplicate
   numeric UIDs or primary-GID disagreement;
5. verifies protected, non-symlinked, non-group/world-writable ancestry and
   checks that the resolved producer can traverse/read the fixed state root.

The resulting producer UID/GID is therefore derived from the actual image-build
state owner, not from UI input or a synthetic source constant.

## Dedicated unit pair

The staged socket is:

```text
ListenStream=/run/host-welcome/image-progress.sock
SocketUser=<resolved-host-welcome-uid>
SocketMode=0600
Accept=no
```

The service runs as the distinct resolved image-build owner and invokes only:

```text
<approved-python> -m zog.image_build.post_install_progress_broker \
  --state-dir <fixed-reviewed-state-root> \
  --authorized-uid <resolved-host-welcome-uid> \
  --application agreety \
  --application chromium \
  --application firefox \
  --application firefox-esr \
  --application greetd \
  --application i3 \
  --application turbovnc \
  --application weston \
  --application xorg-server \
  --source-repository zog144/image-build \
  --source-revision fcc12f3db959afe395b1adfb5b0b4dc1f16a3258
```

The state root is explicitly read-only to the broker. The unit clears
`PYTHONPATH`/`PYTHONHOME`, disables bytecode writes, restricts networking to
AF_UNIX and applies systemd filesystem/kernel hardening. The broker itself
requires exactly one systemd-activated AF_UNIX listener, performs
`SO_PEERCRED` before request parsing and permits only the bounded `snapshot`
operation.

The allowlist is the exact nine-application set accepted by the reviewed
host-welcome consumer. It is not caller selectable.

## Reviewed source and installed-byte attestation

Source staging checks the complete installable image-build Python inventory at
the pinned revision: 85 `src/zog/image_build/**/*.py` files, each by exact Git
blob and SHA-256, plus component metadata and license/notice files.

After the aggregate `zog` wheel is installed, run:

```sh
host-install host-welcome-image-progress-attest-installed \
  --python-executable /usr/bin/python3
```

The attester is read-only. It requires root, rejects inherited `PYTHONPATH` or
`PYTHONHOME`, verifies the actual interpreter and protected aggregate
distribution root, imports the broker/projection, enumerates the image-build
modules actually loaded, and requires every loaded module to:

- belong to the reviewed 85-module source inventory;
- match the exact reviewed Git blob;
- have a separately calculated SHA-256;
- come from a protected regular file under the aggregate installation;
- have a matching SHA-256 entry in the wheel `RECORD`.

The aggregate `RECORD` is itself protected and SHA-256 identified. A successful
attestation still reports `production_activation_authorized=false`.

## Selection, rootfs and reboot semantics

host-install remains the sole post-install selection/intent owner. The staged
profile does not manufacture intent or infer selection from a running pipeline.

Native acceptance must retain and report the exact immutable host-install
selection revision and sequence. A compatibility-checked application publication
must additionally name the exact retained selected rootfs generation. Missing,
superseded or mismatched selection/rootfs evidence is unknown, not success.

The producer's fresh snapshot must identify the active Linux boot. Durable
terminal controller command evidence is allowed to name an older controller
boot after reboot; that does not make the old process live. The observer cannot
submit, resume, retry, cancel, publish, install or start services.

## Staging command

```sh
host-install host-welcome-image-progress-stage \
  --output /path/to/new-overlay \
  --image-build-state-root /fixed/image-build/state/root \
  --image-build-source /path/to/image-build@fcc12f3db959afe395b1adfb5b0b4dc1f16a3258 \
  --python-executable /usr/bin/python3
```

The output contains root-owned policy and unit files plus a source/identity
manifest. Staging itself never calls systemctl and never writes image-build state.

## Native gate still open

Before enablement, Work must verify on a disposable host:

- actual safely resolved welcome and image-build numeric IDs;
- socket parent/inode ownership, mode and SELinux/LSM label;
- positive authorized access and wrong-UID denial at both DAC and
  producer `SO_PEERCRED`;
- actual broker process UID/GID and exact installed aggregate bytes;
- station and controller observer isolation;
- current-boot snapshot acceptance and stale/wrong-boot replay denial;
- exact source-revision replay denial;
- selection revision/sequence and selected-rootfs generation agreement;
- truthful failure, cancellation, interruption/reboot, generation mismatch and
  absent/superseded publication states;
- first boot/offline getty operation when the optional observer or image-build
  is absent.

Production enablement remains NO-GO until that evidence is retained.
