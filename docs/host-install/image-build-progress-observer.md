# Dedicated host-welcome image-build progress observer

**Status:** host-install 0.14.1 is source-bound to the reviewed receipt-only Gate C successor. The predecessor credential/framing transport remains historically accepted only for its exact old bundle. Successor native selection/publication/controller acceptance remains **NOT RUN / production NO-GO**.

## Exact current producer and consumer contracts

- image-build repository: `zog144/image-build`
- runtime/source revision: `7b653e8be3f89730a52688d71df28513456f9cf3`
- deployment-reference revision: `890da58d5ff5b09fa4daf189e3d35e374bcb46a6`
- deployment module blob: `f3662a3c61784b289e7f21e9f253266823302ae8`
- socket template blob: `8e7e7bbd6af41572441f33e8db178f6588e117d6`
- service template blob: `a3ebc63202ee5bb4b361c5493c5415a759941141`
- changed runtime projection blob `zog.image_build.post_install_progress`: `f5de79b847b77ab55a0c6bca432a067853628609`
- reviewed host-welcome consumer: `cf22abc98fef05231b0c6dabc9f6f7930862affc`
- deployment contract: `image-build-post-install-progress-native-deployment-v2`
- projection: `image-build-post-install-progress-v2`
- RPC wire: `image-build-post-install-progress-rpc-v2`
- transport: `image-build-post-install-progress-linux-credentials-v1`
- policy schema: `zog-host-welcome-image-progress-observer-v1`

The other twelve security-critical image-build module Git blobs remain unchanged from the previously reviewed inventory. host-install verifies all thirteen against source and, after installation, against their loaded protected files plus the aggregate wheel `RECORD`.

## Receipt-only successor semantics

The successor fixes one read-only projection gap: after a current host-install selection is established, image-build independently verifies immutable publication before pipeline lookup. A verified artifact/view publication can therefore be reported even when no matching post-install pipeline exists.

This does not invent build history or controller success. With no matching pipeline, pipeline identifiers and source-pin identity remain null, commands remain empty and runtime admission remains unobserved. Missing publication stays waiting; corrupt or mismatched publication remains unknown/conflicted; a real pipeline conflict is not hidden by a valid publication receipt.

## Fixed protected role

The root-owned policy remains exactly `/etc/zog/host-welcome-image-progress-observer.json`, with the same v1 schema and fields. Its `image_build_source_commit` is now the exact successor runtime `7b653e8be3f89730a52688d71df28513456f9cf3`.

The first-wave allowlist remains exactly `agreety`, `firefox-esr`, `greetd`, `i3`, and `xorg-server`. Chromium, TurboVNC, Weston/Wayland and non-ESR Firefox remain outside this profile.

The service template is copied byte-for-byte from deployment `890da58d…` and invokes the broker with `--source-revision 7b653e8b…`. Socket DAC, distinct live consumer/producer UID resolution, AF_UNIX-only service hardening, read-only image-build state and `SCM_CREDENTIALS` authentication are unchanged.

## Source and installed-byte attestation

Before staging, host-install verifies the exact successor deployment module, socket/service templates and all thirteen runtime module Git blobs. The changed projection module must be exactly `f5de79b…`; retaining the predecessor projection bytes while claiming the successor source revision is rejected.

After the aggregate `zog` wheel is installed, `host-welcome-image-progress-attest-installed` still requires root, a protected approved interpreter, no inherited `PYTHONPATH`/`PYTHONHOME`, protected regular-file module origins, exact Git-blob identities and matching SHA-256 entries in the aggregate wheel `RECORD`. The returned RECORD SHA-256 is retained as installed-byte evidence. Successful attestation does not authorize production activation.

## Native Work gate

Work must still prove the intended installed composition using the successor tuple:

1. stage and attest the reviewed aggregate observer on the chosen host;
2. record a genuine current host-install selection and independently verified publication receipt over real immutable rootfs/application-view objects;
3. observe that receipt through the authenticated installed host-welcome consumer;
4. separately inspect the real controller and compare controller evidence with the observer projection;
5. confirm the observer remains read-only and does not create selection, publication, pipeline or runtime state;
6. retain exact PASS/BLOCKED/NOT RUN disposition for failure/cancel/interruption and other cases not actually exercised.

The historical `7348ec73… / 10d5c89f… / 1bb771b0…` transport PASS remains valid only for that predecessor bundle. It does not establish successor Gate C acceptance.

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
