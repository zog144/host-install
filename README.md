# host-install

Version 0.13.1 corrects host-welcome malformed protected STATE classification: readable malformed/untrusted records (including malformed JSON, duplicate fields, forbidden numbers, oversized records and invalid closed-contract fields) sanitize to `failed/state-invalid`, while genuinely absent, inaccessible, racing or otherwise unavailable STATE remains `unknown/state-unavailable`. No nonce, peer-UID, current-boot, read-only capability or mutation boundary changed.

Version 0.11.0 adds the [dedicated host-welcome image-build progress observer](docs/host-install/image-build-progress-observer.md), aligned to producer deployment contract `image-build-post-install-progress-native-deployment-v1` at `b5cf3d761087c157b71724986bc94503089932a2` while preserving runtime/source binding `fcc12f3db959afe395b1adfb5b0b4dc1f16a3258`. It resolves real host identities, stages the exact producer-owned unit pair and five-application v1 allowlist, verifies the 13 security-critical runtime modules plus aggregate wheel `RECORD`, and remains disabled pending disposable-host DAC/`SO_PEERCRED`/SELinux/reboot/getty acceptance.

Version 0.10.0 also carries an explicit [host-discover compatibility gate](docs/host-install/host-discover-compatibility-2026-10-18.md) for the public migration: the exact selected host-discover source is executed against the current STATE/admission APIs while its obsolete standalone `host-install==0.4.4` metadata remains a host-discover-owned blocker.\n\nVersion 0.10.0 hardens the dedicated host-welcome controller-progress observer: the public staging command now derives the welcome UID and controller UID/GID from independent live host evidence instead of accepting numeric identity arguments, consumes the post-integration box-control observer contract at `8249715708c6ef8a1fd30a3fb529b4034ffffe25`, and attests the actual aggregate `zog` installation against pinned source blobs plus wheel `RECORD` hashes before native activation can be considered.

Version 0.9.0 adds the [dedicated host-welcome controller-progress observer](docs/host-install/host-welcome-progress-observer.md): a separate mode-0600 AF_UNIX listener and exact root policy for the host-rootfs console consumer, numeric UID peer authorization, reviewed box-control broker/client byte pins, and an installed-byte verification gate before enablement. The station-access progress listener remains separate and unchanged.

Version 0.8.0 adds the [protected station application-progress observer deployment profile](docs/host-install/application-progress-observer.md). It renders the box-control observer socket/service with the station consumer's protected numeric execution UID/GID, runs the broker under the distinct numeric controller owner, preserves and extends the root-owned host-binding policy, and exports the exact station settings needed for the read-only adapter. No username is trusted as an authorization source, and staging itself does not start systemd or station-access.

Version 0.7.0 adds the [console-first bootstrap readiness contract](docs/host-install/console-bootstrap.md): a sanitized authenticated local status producer that can answer `unknown` before STATE/network/controller/browser readiness, preserves normal getty/emergency login independence, keeps headless installation success separate from optional graphical applications, and defines a no-autostart graphical handoff gate. Source/synthetic acceptance only; no greetd/X11/browser deployment is implied.

Version 0.6.0 adds a durable, secret-free certificate lifecycle coordinator and simulation path for application availability. It preserves bound certificate state, completed preparation revision, observed ACME account/lineage existence and software-generation history across reboot/upgrade; it blocks silent state replacement, identity/lineage disappearance and preparation-revision migration. Actual image deployment and Certbot/nginx execution remain outside this pass.

Version 0.5.0 adds the [certificate application enablement contract](docs/host-install/certificate-enablement.md): a fail-closed dependency/status evaluator for verified STATE, controller grant, immutable software, operator-approved hostname/challenge policy, durable ACME identity preservation, one-time preparation, issuance, host-deploy publication and independent external HTTPS verification. It never issues certificates, exposes nginx, changes archive roles, or regenerates an existing ACME identity.

**Documentation:** [technical manual](docs/host-install/README.md) · [architecture](docs/host-install/architecture.md) · [verification and evidence](docs/host-install/verification.md). These consolidate current boundaries while preserving historical implementation-pass reports and their original acceptance scope.

Version 0.4.4 adds [verified host generation provenance](docs/host-install/host-generation-provenance.md): backward-compatible HOST-A/HOST-B generation records, transition preservation, and live booted-slot observation for host-discover. It does not select or switch a boot slot. Host generation reporting is observational and preserves unknown inactive-slot state rather than guessing.\n\nVersion 0.4.3 preserves persistent admission/supervisor listeners and sends graceful-stop signals to the main beacon first, allowing in-flight health checks to finish before the protected run closes. See [managed-beacon composition](docs/host-install/managed-beacon.md).

Version 0.4.0 adds a [local protected-ledger observation interface](docs/host-install/state-admission.md)
for host-discover's narrow existing-identity admission. Networking and control
remain disabled. Joint consumer/socket acceptance passed on disposable AWS Linux
on 2026-10-02 after correcting the socket boot ordering; see the maintained interface.

Latest validation: disposable AWS STATE/identity acceptance (historical private verification)
passed on 2026-10-01 against host-install 0.3.0. Actual UID 970, systemd, reboot,
mount/storage failures and interrupted initialization were exercised. Managed
transport and bootable Zog image deployment remain outside that acceptance.
The implementation-pass notes below retain their original scope.

First implementation pass, 0.1.0. Cross-program integration validated 2026-10-01.

Offline Zog host-installation foundations: image-build artifact staging, root
filesystem population, GPT disk-image assembly, read-only target preflight, and
durable incomplete-operation evidence. Python 3.11+ on Linux; no Python runtime
dependencies for the standalone test path.

**There is no physical block-device writer in this pass.** The only disk writer
creates a new regular file inside a newly created private operation directory.
Existing destinations are rejected. No mounts, loop attachment, cloud requests,
root replacement, first-boot enrollment, Secure Boot or TPM operations occur.

## Two separate interfaces

1. **image-build artifact v1:** `manifest.json`, `rootfs.tar`, optional `boot.tar`.
   `stage-artifact` delegates integrity/authenticity-binding checks to
   `zog.image_build.host_export.verify(directory, expected_id)`, snapshots the bundle,
   verifies the snapshot again, safely extracts it and verifies the extracted
   inventory. `installable=false` and submitted readiness/security evidence stay
   visible. Stage success grants no installation permission.
2. **host-install fixture plan v1:** an installer-local manifest describes exact
   disk/partition/filesystem identities and preformatted ext4/FAT32 images. This
   drives synthetic disk tests. It is **not** a replacement for image-build's
   artifact format or a requirement that image-build export raw filesystem images.

The real image-build exporter/consumer integration passes against commit
a historically pinned image-build source revision (retained in private provenance records). All four supplied fixture outcomes pass, including
preservation of sticky `/tmp` permissions and rejection of false readiness.
The real valid artifact also populates ext4 successfully; debugfs confirms its
file bytes and `/tmp` mode. All 34 tests pass with the pinned dependency supplied.

Payload member names use POSIX semantics: literal backslashes (including systemd
`\x2d` unit escapes) are preserved without unescaping. Absolute, empty, dot and
parent components, duplicate entries and symlink-parent writes remain rejected.
Use a reviewed, compatible image-build exporter/verifier revision
for the matching exporter/verifier contract.

## Run locally

```sh
python3 -m zog.host_install --help
python3 -m unittest discover -s tests -v
PYTHONPATH=src:tests python3 tests/rehearse.py /tmp/host-install-new-rehearsal
```

The rehearsal creates a 322 MiB disposable disk file with five 64 MiB partitions.
It requires `mkfs.ext4`, `e2fsck`, `partx`, and `blkid`. FAT32 fixture bytes are
created by test code only: the empty ESP has no EFI program and cannot boot.
The test size is not a production recommendation. Source inputs and images
consume additional temporary disk space; retain about 1 GiB for one rehearsal.

Read-only operations on the resulting fixture:

```sh
python3 -m zog.host_install plan /tmp/host-install-new-rehearsal/artifacts/manifest.json --disk-mib 322
python3 -m zog.host_install inspect /tmp/host-install-new-rehearsal/operation
```

To consume an image-build export, make the reviewed image-build source available
on `PYTHONPATH` (alongside host-install), then:

```sh
python3 -m zog.host_install stage-artifact /path/to/export --expected-id TRUSTED_ARTIFACT_ID --operation /path/to/new-staging
python3 -m zog.host_install build-root-fixture /path/to/new-staging --operation /path/to/new-filesystem --mib 8192 --filesystem-uuid NEW_UUID
```

`build-root-fixture` requires uid/gid 0 to preserve the all-root-v1 policy. It
rejects unexpected source ownership, xattrs and hardlinks, uses `mkfs.ext4 -d`,
checks filesystem geometry/UUID and runs non-modifying `e2fsck`. Source parents
and operation directories must be caller-controlled and quiescent. Do not run
commands from an unreviewed source checkout as root. The resulting root image
remains an offline fixture: no modules/kernel overlay or EFI configuration is
added, and filesystem checking does not establish bootability.

Read-only physical-target planning is available on a supported Linux installer:

```sh
python3 -m zog.host_install preflight fixture-plan.json --disk-mib 32768 --target /dev/nvme1n1 --identity serial:EXPECTED_VOLUME_SERIAL
```

This gathers `lsblk`, `findmnt`, sysfs holders and swap evidence, rejects root
ancestors including layered devices, mounted descendants, active holders, swap,
missing/duplicate identities, insufficient size and read-only targets. Overlay,
tmpfs, Btrfs, ZFS and unresolved running-root topology fail closed. A passing
report records path, device number, stable identity and size. It is planning
evidence only, not a durable authorization token or proof of system-wide exclusive
access. Cross-mount-namespace checks, exclusive device opening, topology races,
logical-sector handling and revalidation at the actual write boundary remain
required before a block-device writer can be added.

## Interrupted work

`operation.json`, `staging.json` and `filesystem.json` use fsynced temporary
records and atomic replacement. Inputs are copied and verified before GPT
writing. A failed/terminated operation is never automatically resumed or
overwritten. Inspect its state and preserve evidence; use a fresh operation
directory for a new attempt. `inspect` refuses incomplete installation states.
There is no resume, promotion, rollback or abandonment command in this pass.

`inspect` binds the image to its original device/inode/size and verifies primary
and backup GPT bytes plus every partition hash. Moving/copying the image to
another filesystem is not transparent to that binding. The operation directory
is trusted local state, not a signed receipt against a hostile administrator.

## Remaining integration work

- Agree exact STATE/APPLICATIONS mounts, host accounts, services and first-boot
  composition. `/state` and `/applications` in the fixture plan are placeholders.
- Compose a complete foreign boot set, including EFI binaries/configuration,
  matching kernel/modules/initramfs, selected HOST-A identifiers and read-only
  root arguments. Current image-build `boot.tar` alone is insufficient.
- Define production sizes and filesystem features against the foreign kernel.
- Implement physical-device writes after installer-host safety tests; include
  root/holder/mount races, exclusive opens and target identity revalidation.
- Authorized loop-device and later EBS tests, then boot/promotion/rollback and
  enrolled Zog-native control. No such tests have occurred here.

See `docs/host-install/image-build-integration.md`, `docs/host-install/fixture-plan.md` and
maintainer-held private verification records for the exact boundaries and observed results.

## STATE interface, pass 2

The `/state` contract now has strict record validation, read-only Linux inspection,
a pure lifecycle gate and a separate explicit storage probe. Start with
[the interface and safety boundaries](docs/host-install/state-interface.md) and the
[synthetic bundle](examples/state-contract-v1/bundle.json).

```sh
python3 -m zog.host_install state-validate examples/state-contract-v1/bundle.json
python3 -m zog.host_install state-inspect
```

`state-inspect` fails closed on a machine without the canonical installation
records and verified STATE. `state-probe` is a separate write operation requiring
UID/GID 970 and an already provisioned health directory. This pass does not enable
first-boot identity creation or install services.

## STATE provisioning and identity, pass 3

Offline configuration overlays, verified STATE preparation and the durable root
identity coordinator are implemented. Key operations use host-identify in a
separate UID 970 process; completed identity is never silently regenerated.

- [Provisioning commands and transaction contract](docs/host-install/state-provisioning.md)
- Host-discover / host-identify integration handoff is retained privately; use the public integration contracts and source tests
- [Disposable AWS acceptance procedure](docs/host-install/aws-state-acceptance.md)

Managed host-discover transport remains blocked pending its admission integration.
The supplied startup units are reviewable templates, not automatically installed
services. No live cloud or disk deployment is performed by this pass.

## Managed beacon profile

See [explicit managed-beacon composition](docs/host-install/managed-beacon.md) for optional service staging, protected provisioning, upgrade and recovery rules.


Earlier private handoffs and execution evidence remain in the maintainers' restricted records. Their historical source identities are distinct from this public repository.

## Public source and licensing

Original first-party host-install source and documentation are licensed under
`BSD-3-Clause OR GPL-3.0-only`. See [LICENSE](LICENSE), [LICENSES](LICENSES/)
and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
The new public repository has clean Git history; historical private branches,
tags, verification scripts and handoff metadata are not part of this source.
The public CI verifies source-level and synthetic integration tests, not a live
AWS deployment, physical-disk write, bootable host or production recovery.
