# host-install

Version 0.14.9 defines the first explicit resident bootable-image contract. It separates Boot A (UEFI → exact HOST PARTUUID → read-only root → systemd PID 1 → journal/getty) from Resident B (verified STATE/APPLICATIONS mounts plus core D-Bus/network/Python trust services), and explicitly excludes Certbot/ACME/DNS/nginx from both gates. `bootable-image-contract` emits the machine contract; `bootable-image-assess` evaluates an independently verified image-build host artifact without writing disks or claiming native boot. Missing boot components require a new immutable image-build generation rather than post-selection rootfs mutation. Image-build owns exact generation/source verification and missing OS-component disposition; host-install/host-deploy Work owns disposable-VM boot acceptance.

Version 0.14.8 repins the managed certificate consumer to host-deploy PR #3 successor `098b6813dc1016ae748de8c5e836648a7b244c7f` while preserving all previously accepted installation/STATE/signer/issuer/policy/credential/grant/owner-ledger identities. Installed-byte attestation now requires managed-authority blob `f07c0655280d9724cc59a7fc8bbd7af5e5415913`, unchanged hostname-authority blob `fc833cb3164e018076e2cc4a4a75aa12923c4c8d`, and delivery blob `d69b59afe3060f5c92bf527c82d9aafc85127493`; standalone host-deploy remains version 0.10.6. This is an in-place reviewed consumer-code adoption only: no root authority, issuer storage, local binding, credential revision, owner ledger, ACME, DNS, nginx or production HTTPS state is recreated or authorized.

Version 0.14.7 adopts the image-build Gate C cold-start successor: runtime `fe625fd901a62ef3c877a8fbc159e3b4aae7f952`, deployment/reference `53ad8c2166e6b73dffbc722c2e47ccf3593612ec`, and independently accepted host-welcome consumer `a1d554bb78de27e9f365f4254db25c77cc49ec27`. The broker/projection module blobs and both producer-owned service templates are rebound exactly while the socket template, named observer profiles, policy schema, SCM_CREDENTIALS transport, UID separation, read-only state and 12-second consumer deadline remain unchanged. Installed aggregate-wheel/RECORD attestation requires the two corrected runtime modules, and the staging manifest freezes the exact new consumer provenance. Both Regular consumers are now source-ready; native Gate C remains blocked only on the targeted true cold socket-activation first-response retest. The historical 12.056-second first-request failure remains retained evidence.

Version 0.14.6 implements the host-install-owned managed certificate authority handoff required by reviewed host-deploy PR #3 (`04c1006742e7592f2ec5f2103c7874404fc361a8`). It adds independent signer-pin installation, non-secret local consumer/credential intent, exact host-deploy source and installed-wheel RECORD attestation, a canonical `/etc/zog/host-deploy/certificate-managed-binding.json`, and a second monotonic owner ledger/receipt under verified STATE. The ledger freezes local policy, delivery-policy hash, credential revision and prepared issuer grant/storage identity, fences torn publication, and makes revocation terminal. `certificate-native-observe` now requires that owner state plus a genuine selected inspect before exposing the native host-deploy Gate B handoff. No ACME, DNS, nginx or production HTTPS action is authorized by this release.

Version 0.14.5 selects host-discover 0.4.11 at `9e741d9a86bb2fd466ac46b252be0b78528eeff7` for the retained non-resident managed-beacon composition. Staging now verifies all 17 reviewed host-discover runtime modules, records their exact Git/SHA-256 inventory, and exposes a root-only installed-wheel `RECORD` attestation for either the retained standalone `host-discover` distribution or an explicit aggregate `zog` distribution. CI replaces the historical 0.4.8/0.4.4 compatibility lane with the successor's host-install 0.14 resident/non-resident suite. Recovery remains state-preserving: no repeated `beacon-prepare`, no journal/ledger recreation, and no station approval/export before a genuine pending enrollment request and independent fingerprint verification.

Version 0.14.4 resolves the Gate C application-profile blocker without widening the accepted graphical observer. The image-progress deployment reference is now image-build `d6fe6f0386eccd2ba577b45c32fa16baf6540c69` / contract v3 and exposes two reviewed, disjoint profiles: the unchanged five-application `graphical-first-wave-v1` profile and the single-application `certify-manage-gate-c-v1` profile. Staging records the exact profile and allowlist, renders only that profile's producer-owned service template, and rejects ad-hoc or in-place profile substitution. Runtime projection bytes, protected policy schema, SCM_CREDENTIALS transport, numeric identity separation, read-only image-build state, and production NO-GO remain unchanged. Native Gate C selection/publication/controller comparison remains Work-owned.

Version 0.14.3 corrects real EC2/Nitro EBS STATE-volume resolution after native 0.14.2 planning exposed simultaneous NVMe `SERIAL` and `WWN` aliases. Block inventory now preserves all stable aliases while retaining the existing primary identity, AWS provider binding requires the selected whole disk to carry the serial derived from `aws-ebs:vol-…`, and an independently supplied WWN or serial may identify that same disk. Child partitions inheriting controller aliases do not become candidate whole disks. Apply revalidates the saved alias set and provider binding under a host-wide `/run/lock` transaction lock shared across operation directories, while retaining the per-operation durable journal lock. No formatting/native success is claimed until Work reruns the dedicated-volume gate.

Version 0.14.2 serializes the complete non-resident dedicated-STATE apply transaction under a durable root-owned operation lock. The authoritative target topology/signature or already-mounted STATE observation is now performed only after that lock is acquired, and the lock remains held through operation-record reconciliation, partitioning, formatting, mount activation, account/configuration publication, STATE preparation and final phase publication. A plan remains read-only evidence rather than write authority; a device that changes between planning and the locked apply observation fails closed before partitioning.

Version 0.14.1 rebinds the protected host-welcome image-progress observer to the reviewed receipt-only Gate C successor: image-build runtime `7b653e8be3f89730a52688d71df28513456f9cf3`, deployment `890da58d5ff5b09fa4daf189e3d35e374bcb46a6`, and host-welcome consumer `cf22abc98fef05231b0c6dabc9f6f7930862affc`. The policy schema, Linux credential transport, fixed five-application allowlist, distinct numeric identities, read-only producer state, and production NO-GO are unchanged. Installed attestation now requires the successor `post_install_progress.py` blob and the matching protected aggregate wheel RECORD; native selection/publication/controller acceptance remains Work-owned and NOT RUN.

Version 0.14.0 adds the [non-resident installation contract](docs/host-install/non-resident-installation.md): schema-2 installation records explicitly separate host-OS ownership from fresh/upgrade/recovery lifecycle, reuse the canonical verified `/state` boundary without inventing HOST slots, and provide read-only stable-volume planning plus an explicit resumable dedicated-STATE apply path. The apply path records intent before partitioning, reconciles only exact PARTUUID/ext4 UUID results, verifies the mounted STATE before configuration/tree preparation, and never authorizes host identity. Legacy schema-1 resident validation is unchanged. The physical path is source-tested but native-NOT-RUN; no cloud volume, live block device, reboot, issuer lifecycle or resident boot was modified by this release.

Version 0.13.3 corrects the image-progress staging manifest to identify the reviewed host-welcome SCM_CREDENTIALS consumer `1bb771b00be9f5e1a52e5419af9f78662c7913e8`. The image-build runtime `7348ec73…`, deployment reference `10d5c89f…`, Linux-credentials transport, distinct live identities, read-only state model, and production NO-GO remain unchanged.

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
