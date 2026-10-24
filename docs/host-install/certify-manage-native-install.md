# Native certify-manage issuer installation

**Status:** host-install 0.14.4 source/deployment successor. The immutable issuer producer is rebound to the reviewed image-build recovery/profile successor. Native ACME, systemd, nginx and HTTPS acceptance remains **NO-GO** until host-deploy Work completes the isolated gate.

This profile supplies the host-install-owned native issuer substrate identified by
host-deploy PR #3 Work acceptance. It does **not** install hostname authority,
Cloudflare credentials, issue a certificate, enable renewal, reload nginx or
authorize production HTTPS.

## Exact reviewed inputs

- certify-manage: `8d073ff449557fc82c12eea93e240cdeec1b0fcc`
- image-build immutable issuer producer:
  `d6fe6f0386eccd2ba577b45c32fa16baf6540c69`
  (`certify_manage_software.py` blob `a6216f5031c8155cd020ce4424e94307af319213`)
- box-control selected issuer controller:
  `a3e939b7a22ef6277ae9712961ffbd5a18ccac39`
- root-control native mechanism:
  `3a2dd9c935e332e811adaccedf04b16bd2de1ea7`

The immutable certify-manage software result must be
`image-build-certify-manage-software-result-v1` and bind exactly one
`application-software-consumer-v1` view at
`/applications/certify-manage`.

Canonical immutable command paths remain:

```text
/applications/certify-manage/bin/python3
/applications/certify-manage/bin/certbot
```

The image-build profile may be `http-01` or `cloudflare-dns-01`. Host-install
does not resolve or install Python dependencies itself.

## Staged native layout

`host-install certify-manage-native-stage` emits a new root-owned overlay with:

- `/etc/zog/certify-manage/install.json`: secret-free immutable deployment
  binding, numeric controller/lifecycle consumer identities, generation, software
  view/artifact/binding digest and exact producer pins;
- `/etc/zog/host-bindings.json`: the existing host binding policy plus exactly
  five `certify-policy` entries for `prepare`, `issue`, `renew`,
  `inspect` and `stage`;
- `zog-certify-lifecycle.socket` and `zog-certify-lifecycle.service`;
- a rendered controller application declaration at
  `controller/application/certify-manage/application.py`, intended for the
  exact controller project named in the manifest.

The overlay deliberately contains **no**:

- `/etc/zog/certify-policy/policy.json`;
- Cloudflare token;
- ACME account or certificate material;
- pre-created `/var/lib/zog-certify-manage` host directory;
- host-deploy delivery policy;
- nginx configuration;
- enabled service.

Hostname authority and root-owned policy installation remain
station-access/host-discover + host-owner responsibilities. Issuer-only DNS
credential installation remains a separate root-control/certify-manage capability.

## Live controller identity

Staging resolves the controller project owner from protected project filesystem
ownership. The supplied root-control socket must have protected root-owned
ancestry and be owned by that same exact controller UID, matching the pinned
root-control peer contract.

The lifecycle consumer is supplied by **account name**, never numeric UID. The
installer resolves the actual unique unprivileged UID/GID from the host account
database and records only the resolved numeric values in the staged contract.
The lifecycle consumer must differ from the controller owner.

No issuer UID is chosen during staging. The issuer identity is controller-issued
during application preparation.

## Immutable application declaration

The rendered application is persistent, externally controlled, single-instance
and uses `execution_identity="application"`. It fixes the exact reviewed
software view and one writable mount named `certificate-data` at:

`/var/lib/zog-certify-manage`

Preparation revision remains `certify-manage-state-v1`.

Programs are exactly:

- preparation: `prepare`;
- selected runtime: `issue`, `renew`, `stage`, `inspect`.

Every program receives only the controller-managed `certificate-data` mount and
the root-owned read-only policy at
`/run/zog-host/certify-policy/policy.json`.

The host binding source is fixed to `/etc/zog/certify-policy`; a program cannot
choose an alternate host directory.

## Dedicated lifecycle broker

The staged listener is fixed at:

`/run/zog/certify-lifecycle.sock`

It is mode 0600 and owned by the resolved host-deploy lifecycle consumer UID.
The service runs as the distinct controller project owner and invokes only:

```text
python -m zog.box_control.issuer_lifecycle_broker
  --project <fixed-controller-project>
  --authorized-uid <resolved-lifecycle-consumer-uid>
  --generation <exact-rootfs-generation>
  --software-view <exact-image-build-view>
  --root-control-socket <fixed-root-control-socket>
```

The broker itself permits only selected `renew`, `inspect` and `stage`
operations. It does not expose `issue` through the unattended host-deploy
lifecycle socket.

Staging never enables this listener.

## Prepared issuer attestation

After the host owner explicitly prepares certify-manage through box-control, run:

```sh
host-install certify-manage-prepared-attest \
  --controller-project /absolute/controller/project \
  --root-control-socket /run/zog/root-control.sock \
  --software-view sha256:<view>
```

This read-only command:

1. reads the actual retained box-control application preparation;
2. requires state `ready`, revision `certify-manage-state-v1`, and the exact
   expected immutable software view;
3. extracts the controller-issued `zog-execution-identity-v1` grant;
4. independently asks root-control `execution_identity_resolve` for the same
   application;
5. requires both identities to match exactly;
6. opens the retained
   `state/mounts/persistent/<storage_id>/certificate-data` directory;
7. requires direct directory mode 0700 and owner UID/GID equal to the grant.

The returned attestation contains only grant/storage identifiers and numeric
UID/GID, never ACME keys, certificate PEM or DNS secrets.

## Installed controller/root-control attestation

Run:

```sh
host-install certify-manage-controller-attest-installed \
  --python-executable /usr/bin/python3
```

The command rejects inherited `PYTHONPATH`/`PYTHONHOME`, loads the actual
aggregate `zog` distribution, verifies selected issuer lifecycle/inspection,
application-storage and root-control modules against the exact reviewed Git blobs,
and requires matching wheel `RECORD` hashes from protected module origins.

A pass proves the selected source bytes are installed. It does not prove a
running socket, application grant, systemd InvocationID, mount namespace or
certificate health.

## Staging command

```sh
host-install certify-manage-native-stage \
  --output /path/to/new-overlay \
  --controller-project /absolute/controller/project \
  --root-control-socket /run/zog/root-control.sock \
  --lifecycle-consumer-account <approved-host-deploy-service-account> \
  --generation <64-hex-rootfs-generation> \
  --software-result /trusted/image-build-certify-manage-result.json \
  --host-bindings-policy /trusted/current/host-bindings.json \
  --image-build-source /reviewed/image-build \
  --certify-manage-source /reviewed/certify-manage
```

The command is staging-only and returns
`production_activation_authorized=false`.

## Remaining native gate

Host-deploy Work still must prove:

- the actual installed immutable certify-manage/Certbot view and rootfs ABI;
- actual controller and root-control process/socket identities;
- actual issuer grant UID/GID, storage ID and 0700 persistent state;
- exact runtime credentials, supplementary groups and mount namespaces;
- root-owned installed hostname authority and policy digest;
- issuer-only Cloudflare credential installation/rotation where DNS-01 is used;
- finite renew -> inspect -> stage request identity continuity;
- exact systemd boot/InvocationID/journal observations;
- interrupted/lost-reply/reboot recovery;
- fingerprint-bound host-deploy delivery, nginx validation/reload/rollback;
- real local CA-valid SNI verification.

Production renewal and live HTTPS remain NO-GO until those checks pass.


## Managed hostname-authority root pin

For the managed command-center authority path, host-install now consumes the
separately reviewed station-access Ed25519 assignment key only as a native
installation input. `beacon-stage` accepts:

```text
--certificate-assignment-authority-pin <reviewed-json>
```

The input must be schema 1 / kind
`zog-certificate-assignment-authority-pin`, contain one registry ID, raw
Ed25519 public key and matching SHA-256 fingerprint. host-install validates the
key/fingerprint and stages exactly:

```text
/etc/zog/host-install/certificate-assignment-authority.json
```

as root:root mode 0444. The managed supervisor source is pinned to
`host-discover@69ef2620f644a83ccc309f13b71b7f0e30a684aa`; its reviewed
supervisor and certificate-assignment module Git blobs are checked before the
profile is staged. The existing STATE account contract remains unchanged:
`host-discover` UID/GID 970 with groups 972/973, a root supervisor, and a
root:970 supervisor socket. No new identity allocator is introduced.

The root-owned host-discover checkpoint remains:

```text
/state/host-discover-certificate-authority/authority.json
```

under a root:root 0700 parent, with the observation root:root 0600. host-install
does not copy or consume UID-970 `certificate-assignment.json`; native
readiness reads only this root-owned checkpoint and independently requires it
to match the installed key pin and the current host-install installation/STATE
identity.

## Authenticated native readiness observation

After controller/application installation and preparation, run:

```sh
host-install certificate-native-observe \
  --controller-project /absolute/controller/project \
  --root-control-socket /run/zog/root-control.sock \
  --generation <64-hex-rootfs-generation> \
  --software-view sha256:<view> \
  --record /protected/certificate-lifecycle.json \
  --event status
```

For an already selected inspection, add the durable controller request identity:

```text
--inspect-request-id <32-hex-request-id>
```

The adapter is read-only with respect to controller, STATE, issuer state,
hostname authority and certificates. Its only write is the existing
secret-free `zog-certificate-lifecycle-record` through the established atomic
status-record path.

The matrix independently reports PASS/BLOCKED/NOT RUN for:

- verified host-install STATE and recovery hold;
- installed reviewed host-discover root-observation producer;
- root-owned managed hostname authority checkpoint and installed pin;
- installed reviewed box-control/root-control controller bytes;
- exact published rootfs generation plus revalidated
  `application-software-consumer-v1` certify-manage view;
- exact five selected program commands and immutable Python path;
- protected root-owned certify policy and read-only mount digest;
- original preparation attempt/boot/InvocationID;
- original root-control grant ID, numeric UID/GID and controller-managed
  `certificate-data` storage ID/mode;
- optional root-authenticated selected inspect result.

When the lifecycle record has already observed an ACME identity or healthy
lineage, reboot/upgrade without a fresh authenticated selected `inspect`
changes the persistent evidence to `uncertain` and blocks issuance. Storage
identity alone is not treated as proof that account/lineage content survived.

The adapter deliberately leaves
`host_deploy_owner_policy_binding = NOT RUN` and
`host_deploy_native_gate_handoff_ready = false`. host-deploy Regular owns the
separate conversion of the root host-discover observation to the exact local
consumer and `policy_sha256`; host-install neither fabricates that receipt nor
uses the UID-970 file as a shortcut.
