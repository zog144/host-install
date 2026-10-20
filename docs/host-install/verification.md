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

The 0.11.0 source suite implements the host-install deployment side of
host-welcome's reviewed `image-build-post-install-progress-v2` consumer. It pins
image-build source
`fcc12f3db959afe395b1adfb5b0b4dc1f16a3258`, keeps the image observer
separate from both existing station/controller progress listeners, derives the
host-welcome UID from the validated account and the producer UID/GID from the
protected live image-build component-state owner, and renders the fixed
`/run/host-welcome/image-progress.sock` plus exact
`zog-host-welcome-image-progress-observer-v1` policy.

The source verifier binds all 85 installable `zog.image_build` Python files by
Git blob/SHA-256 plus component metadata and license/notice inputs. The installed
attester rejects `PYTHONPATH`/`PYTHONHOME`, verifies the approved interpreter
and aggregate wheel `RECORD`, imports the broker/projection, and requires every
loaded image-build module to match the reviewed Git blob and wheel hash.

Source tests also freeze the reviewed nine-application allowlist, read-only unit
arguments, current-boot semantics, host-install selection ownership, exact
selection receipt/sequence requirement, selected-rootfs-generation requirement
for compatibility-checked views, and the absence of mutation authority. This
does **not** constitute native deployment acceptance. Wrong-UID DAC/peer denial,
actual systemd service identity, socket inode/SELinux labeling, stale/wrong-boot
and source replay, reboot/interruption truthfulness, selection/rootfs readback,
offline getty behavior and disposal remain Work-owned gates before enablement.
