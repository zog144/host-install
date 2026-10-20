# Verification and deployment evidence

This chapter describes the evidence needed to characterize host-install as tested, and keeps the different acceptance scopes separate. Consult the [documentation index](INDEX.md) and current source/tests before promoting a claim from an old versioned handoff.

## Evidence ladder

| Layer | What it can support | What it cannot support |
| --- | --- | --- |
| Parser, record and policy tests | Input rejection, record schema, pure lifecycle decisions | Mounted disk or service behavior |
| Offline fixture rehearsal | Deterministic GPT/partition content and rootfs extraction on disposable file images | Physical-block-device safety, EFI boot |
| Protected STATE and identity acceptance | Explicit permissions, protected identity coordination, interruption handling | Remote command control, station enrollment |
| Disposable AWS STATE acceptance | Exactly the exercised AWS Linux, systemd, storage, UID and reboot paths | Zog-native boot, live production cutover |
| Local admission and managed beacon tests | Their specific socket, session and heartbeat behavior | Automatic remote-control or archive privileges |
| Boot generation observation | Read-only report for a known verified booted slot | Selecting or switching a boot slot |

## Reproduction

Run the local unit suite and offline rehearsal using the commands documented for the exact host-install checkout; see the [component manual](README.md) and [fixture plan](fixture-plan.md). Do not use unrelated aggregate-root installation commands to execute disk tests. The rehearsal writes a new disposable regular file only. Physical target preflight is read-only and remains planning evidence.

Use the [disposable AWS STATE acceptance](aws-state-acceptance.md) procedure for the narrow live scope documented there. Always record the exact `host-install` revision, companion revisions, target platform, tests run, accepted/unknown properties, and links to retained logs and results.

## Release-readiness gates

Before reporting an end-to-end install, require separate verified evidence of: boot payload matching the rootfs/kernel; safe exclusive physical-target writes; protected STATE identity persistence across boot/reboot; network and enrollment; controller admission; and reviewed recovery or rollback. Missing evidence is a stated gap, not a success by inference.

Dated immutable results and handoffs are retained separately as private historical evidence, not as public acceptance or installation authority. Do not rewrite a historical pass result to imply new acceptance.

## Certificate enablement contract evidence

The 0.5.0 source suite includes contract tests for the certificate application
dependency order, operator-approved hostname/challenge hold, durable ACME identity
preservation across immutable generation changes, rejection of attempted identity
regeneration, uncertain/failed issuance behavior, host-deploy publication
separation, and the independent external HTTPS readiness boundary. These tests
are source-level policy evidence only; they are not live ACME, nginx, DNS,
controller-grant, reboot, or browser-trust acceptance.


The 0.6.0 suite additionally simulates certificate-application availability and
persists the lifecycle record across process reopen, reboot observations and
immutable software generation changes. It verifies one-time preparation
preservation, ACME-account-before-lineage handling, persistent-state replacement
rejection, preparation migration gating, identity/lineage disappearance handling,
local/central policy revocation/conflict/migration hard blocks, atomic record
replacement and stale-writer rejection. This remains simulated application
acceptance; no image deployment, live controller grant, ACME endpoint, DNS API,
nginx reload or browser trust path is exercised.


## Console-first bootstrap readiness evidence

The 0.7.0 source suite adds the sanitized `zog-host-install-bootstrap-readiness-v1`
producer, peer-bound Unix-socket protocol, boot/freshness validation, optional
graphical handoff gate, and systemd ordering templates. Synthetic tests cover
offline reboot, unavailable controller, malformed STATE, incomplete identity
initialization, stale/prior-boot observations, delayed network, no browser,
foreground-console login ownership and protected recovery hold. They also verify
that the producer grants no STATE/device writes, identity-secret access,
controller command or application-mutation authority, and that graphical
availability is not a prerequisite for headless success.

The systemd source test verifies the readiness socket can coexist with an
independent getty transaction without ordering cycles or TTY takeover. This is
not native first-boot acceptance: the dedicated `host-welcome` OS account,
actual getty rendering, emergency-console behavior and later graphical
session/PAM/logind integration still require authorized disposable-host testing.


## Station application-progress observer deployment evidence

The 0.8.0 source suite adds a deployable protected box-control application-progress
observer profile. Tests require the station consumer UID/GID and controller-owner
UID/GID to be supplied numerically, reject root or same-UID identities, render
socket DAC and broker `--authorized-uid` from the same station UID, and preserve
unrelated existing `host-bindings.json` entries while adding only the exact
read-only `station-access/web` application-progress capability.

The profile is staging-only: it emits root-owned units, merged host policy,
station configuration values and an enablement manifest without invoking
systemctl, restarting station-access, changing a protected execution grant,
starting a build/application, or touching STATE. Native acceptance still requires
the actual protected station grant and controller owner to be compared to live
process/socket credentials, including wrong-peer denial, application namespace
visibility, SELinux where applicable and reboot behavior.


## Dedicated host-welcome controller-progress observer evidence

The 0.9.0 source suite stages a second controller-progress listener exclusively
for the host-rootfs host-welcome consumer. It verifies an exact mode-0600 socket
owned by the supplied numeric host-welcome UID, a distinct numeric controller
service identity, the fixed root-control socket/project arguments, and an exact
root-owned `zog-host-welcome-progress-observer-v1` policy. The station-access
observer path and host-binding policy are not reused.

The profile pins box-control source
`644170fc441863307092f329bf7e23cb64eb33e2` and the exact Git blob identities
of the reviewed broker and strict client modules. Source staging refuses changed
bytes, and a separate installed-byte verifier checks the actual imported module
files before deployment may enable the socket. Source tests also assert that
STATE, station-access, network, image-build, graphics and the observer itself do
not become getty prerequisites.

Native acceptance still requires authoritative live UID/grant comparison,
SELinux/socket ancestry, wrong-peer denial, server peer verification, current
boot/freshness, activation/restart/reboot cleanup, controller timeout and offline
headless getty fallback while proving the original station listener remains
isolated.


## Independently resolved console observer identities and installed software

The 0.10.0 suite removes caller-supplied UID/GID authority from the
`host-welcome-progress-stage` command. Live staging resolves the validated
host-welcome account, protected controller project owner and actual root-control
socket owner independently and requires those controller UID observations to
agree before rendering the dedicated listener.

The reviewed box-control source pin advances to
`8249715708c6ef8a1fd30a3fb529b4034ffffe25` and includes the console-specific
`--observer-role host-welcome` and `--controller-owner-uid` broker contract.
Source staging verifies the broker/client plus seven security-critical direct
controller/runtime dependencies by Git blob and SHA-256.

The installed-software attestation is separately read-only. It rejects
`PYTHONPATH`, requires the approved root-controlled interpreter, loads the
actual aggregate `zog` distribution, verifies protected module origins and
ancestry, exact reviewed Git blobs, SHA-256 values and matching wheel
`RECORD` hashes for every pinned module. A successful attestation explicitly
does not authorize production activation; native peer/DAC/SELinux/systemd/reboot
and getty acceptance remains required.


## host-discover public migration compatibility

The 2026-10-18 compatibility gate compares the exact public host-install 0.4.4
consumer API baseline with the current 0.10.0 STATE/admission surface used by
`host-discover@341255fd0ebdee5eedfd4be9a40829ec17391887`. The imported
function/class signatures and the fixed UID 970 STATE account mapping remain
unchanged, and `tests/test_host_discover_compatibility.py` freezes that narrow
surface.

A separate non-root CI matrix installs the exact selected host-discover source
with dependency resolution disabled only for the compatibility execution, then
runs the host-discover source/synthetic tests that directly consume
`zog.host_install`. The root-only supervisor/recovery files are excluded from
that lane and remain separately prepared Work/native fixtures. This preserves
the packaging failure as well: the selected host-discover revision still
declares the stale standalone `host-install==0.4.4` dependency and therefore is
not itself an accepted aggregate release input. host-discover Regular must issue
and test a new metadata-correct revision before host-deploy can regenerate its
six-component source manifest. Native UID/STATE/socket acceptance remains
Work-owned.


## Dedicated image-build progress observer evidence

The 0.11.0 suite implements the host-install side of image-build's producer-owned
`image-build-post-install-progress-native-deployment-v1` contract at deployment
reference `b5cf3d761087c157b71724986bc94503089932a2`. The consumer-visible
runtime/source binding intentionally remains
`fcc12f3db959afe395b1adfb5b0b4dc1f16a3258`.

The source verifier requires the exact deployment module and producer socket/service
template blobs from `b5cf3d...` and the exact 13 security-critical runtime
module blobs defined by the producer reference. Those runtime modules are
byte-identical to the reviewed `fcc12f3...` projection source. The staged
allowlist is exactly `agreety`, `firefox-esr`, `greetd`, `i3`, and
`xorg-server`; Chromium, TurboVNC and Weston are not included in v1.

Live staging derives the host-welcome UID from the validated account and the
producer UID/GID from protected image-build state ownership. It accepts no numeric
identity CLI authority, verifies protected state ancestry, packages the producer
templates byte-for-byte, and never enables the unit.

Installed-software attestation rejects inherited `PYTHONPATH`/`PYTHONHOME`,
verifies the approved interpreter and aggregate wheel `RECORD`, imports all 13
reviewed modules, and requires protected origins, exact Git blobs, independent
SHA-256 values and matching wheel hashes. A pass still returns
`production_activation_authorized=false`.

Native acceptance remains separate: actual UID/GID/supplementary groups, socket
inode/mode/SELinux, wrong-peer DAC and `SO_PEERCRED` denial, producer peer UID,
source/boot replay rejection, read-only state behavior, restart/reboot cleanup,
selection/rootfs/application-view readback, failure/cancel/interruption truthfulness,
observer isolation, offline getty fallback and disposal must be retained before
enablement.


## Native certify-manage issuer installation evidence

Host-install 0.12.0 adds a staging-only native issuer profile aligned to
`certify-manage@b0e80b92a121678244f1a18fa2055ec769ea8852`,
`image-build@b5cf3d761087c157b71724986bc94503089932a2`,
`box-control@a3e939b7a22ef6277ae9712961ffbd5a18ccac39`, and
`root-control@3a2dd9c935e332e811adaccedf04b16bd2de1ea7`.

Source tests freeze the image-build software-result/binding digest, exact immutable
Python/Certbot paths, rendered software view, five `certify-policy` host bindings,
lifecycle socket peer UID, controller service UID/GID and source pins. Staging
does not install hostname policy or DNS secrets, pre-create issuer state, prepare
the application, enable systemd or grant certificate mutation.

A separate prepared-state attester reads box-control's retained preparation,
compares its execution grant with root-control's independent identity resolution,
and checks the actual controller-managed `certificate-data` directory is mode
0700 with the exact grant UID/GID. A separate installed-software attester verifies
the selected lifecycle/inspection/application-storage and root-control modules by
reviewed Git blob plus aggregate wheel `RECORD` hash.

These passes are prerequisites only. Native Work still owns actual immutable
Certbot/plugin ABI verification, running systemd/runtime credential and mount
evidence, hostname-policy installation, issuer-only DNS credential provisioning,
renew→inspect→stage continuity, interruption/reboot recovery, nginx
delivery/rollback and real local CA/SNI verification.


## Native issuer readiness and managed authority pin — 0.13.0

The 0.13.0 source gate advances the native issuer installation handoff without
granting certificate execution. The managed beacon composition is now pinned to
`host-discover@69ef2620f644a83ccc309f13b71b7f0e30a684aa`; staging validates
the reviewed supervisor/assignment source blobs and, when supplied, a
station-produced Ed25519 authority pin before publishing it root:root 0444 at
`/etc/zog/host-install/certificate-assignment-authority.json`.

The new `certificate-native-observe` adapter consumes only root-authenticated
STATE/controller/authority observations. It revalidates the immutable
certify-manage application software view, exact selected commands, original
execution grant/storage ownership, root policy mount and preparation
boot/InvocationID. It can consume an explicit selected inspect request only
through the reviewed root-control invocation-scoped reader. It never opens
UID-970 certificate assignment state directly.

Source regression requires prior observed ACME/lineage evidence to become
uncertain after reboot/upgrade until a fresh selected inspect succeeds. The
returned matrix always leaves host-deploy's root-observation to
`policy_sha256` owner binding NOT RUN; native Gate B/HTTPS Gate C therefore
remain blocked until host-deploy Regular and Work complete their separate
contracts.
