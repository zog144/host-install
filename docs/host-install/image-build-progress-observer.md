# Dedicated host-welcome image-build progress observer

**Status:** host-install 0.14.7 is source-bound to the reviewed Gate C cold-start successor. The prior native Gate C run remains retained evidence: its first cold socket-activated request exceeded the unchanged 12-second consumer deadline, so native cold-start acceptance remains **BLOCKED** until Work retests the exact successor bundle after host-welcome also completes its source-pin adoption.

## Exact current producer and consumer contracts

- image-build repository: `zog144/image-build`
- runtime/source revision: `fe625fd901a62ef3c877a8fbc159e3b4aae7f952`
- deployment-reference revision: `53ad8c2166e6b73dffbc722c2e47ccf3593612ec`
- deployment module blob: `32a0ff998087ea3337046fef117820dca29fad8f`
- socket template blob: `8e7e7bbd6af41572441f33e8db178f6588e117d6`
- graphical service template blob: `b2faa79886f54ec54ba15a57416acbbfa8806166`
- Certbot Gate C service template blob: `deef20a24c7ae3a6b54512e65c8c8efdffe34dde`
- changed broker blob `zog.image_build.post_install_progress_broker`: `997f802492f5bc60724bc6cebff2c045191f2fc1`
- changed projection blob `zog.image_build.post_install_progress`: `7fa485ca5d3f067999dbe16ff66986315abcf1e3`
- currently reviewed host-welcome consumer provenance: `a1d554bb78de27e9f365f4254db25c77cc49ec27`
- deployment contract: `image-build-post-install-progress-native-deployment-v3`
- observer-profile contract: `image-build-post-install-progress-observer-profile-v1`
- projection: `image-build-post-install-progress-v2`
- RPC wire: `image-build-post-install-progress-rpc-v2`
- transport: `image-build-post-install-progress-linux-credentials-v1`
- policy schema: `zog-host-welcome-image-progress-observer-v1`

The two runtime modules above changed for the cold-start correction. The other eleven security-critical runtime-module blobs are unchanged from the prior reviewed inventory. host-install still verifies all thirteen against source and, after installation, against protected aggregate-wheel files plus the wheel `RECORD`.

Host-welcome Regular has independently adopted the same runtime pin at `a1d554bb78de27e9f365f4254db25c77cc49ec27` with its unchanged 12-second timeout and credential/parser contract. host-install records that exact consumer provenance in `profile.json`; Work must install and attest this combined consumer/producer tuple rather than substituting either predecessor.

## Cold-start successor semantics

The broker now performs only configuration validation during construction: exact reviewed applications, producer source binding, current boot identity and canonical state-path validation. Construction performs **no full durable publication/progress snapshot**.

The first actual request still performs a complete fresh `snapshot()` and therefore re-verifies current host-install selection, publication receipt, immutable artifact, immutable application view, selected rootfs generation, compatibility descriptor, consumer binding and any real retained pipeline/command evidence. A second request performs a second full validation; no publication/provenance result is cached between requests.

This preserves the earlier receipt-only behavior while removing only the redundant pre-request verification. It is not a timeout relaxation, cache shortcut or inventory-verification reduction.

## Fixed protected role

The root-owned policy remains exactly `/etc/zog/host-welcome-image-progress-observer.json`, with the same v1 schema and fields. Its `image_build_source_commit` is now exactly `fe625fd901a62ef3c877a8fbc159e3b4aae7f952`.

The two reviewed observer profiles remain disjoint. `graphical-first-wave-v1` is exactly `agreety`, `firefox-esr`, `greetd`, `i3`, and `xorg-server`; `certify-manage-gate-c-v1` is exactly `certify-manage`. No profile membership changed.

Both packaged host-install service templates are copied byte-for-byte from deployment `53ad8c21…` and now invoke the broker with `--source-revision fe625fd9…`. The socket template is unchanged. Socket DAC, distinct live consumer/producer UID resolution, AF_UNIX-only hardening, read-only image-build state and `SCM_CREDENTIALS` authentication are unchanged.

## Source and installed-byte attestation

Before staging, host-install verifies the exact deployment module, socket template, both reviewed service templates and all thirteen runtime module Git blobs. The selected profile name, exact application allowlist and reviewed source inventory are retained in `profile.json`.

After the aggregate `zog` wheel is installed, `host-welcome-image-progress-attest-installed` still requires root, a protected approved interpreter, no inherited `PYTHONPATH`/`PYTHONHOME`, protected regular-file module origins, exact Git-blob identities and matching SHA-256 entries in the aggregate wheel `RECORD`. Both changed cold-start modules are therefore required to be the accepted successor bytes before native activation can be considered.

Successful staging or installed-byte attestation remains read-only and does not authorize production activation.

## Targeted native Work gate

With both Regular consumers now source-bound to the same successor, Work should reuse the retained genuine Gate C environment/evidence where still valid and perform only the targeted cold-start acceptance:

1. install/stage and attest the exact successor bundle;
2. prove a true cold socket activation with the broker process absent before the request;
3. use the unchanged installed `request_image_progress()` consumer and unchanged 12-second deadline;
4. require the **first** credential-bearing response to complete within that deadline;
5. verify the same truthful immutable publication semantics and exact source/boot binding;
6. retain read-only proof across the cold request;
7. optionally record an immediate second request only as diagnostic evidence;
8. do not count a longer-deadline branch as acceptance.

The already accepted general SCM_CREDENTIALS, malformed framing, wrong-sender, disconnect and reboot suite does not need repetition. The historical 12.056-second cold-start failure remains valid retained evidence until this exact retest passes.

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
