# Disposable AWS acceptance: STATE and identity

**Executed on disposable AWS Linux on 2026-10-01.** See
the results (historical, retained privately; not a public acceptance claim) for tested pins, evidence, and limits.
The procedure below describes bounded STATE/identity acceptance. This is not a bootable Zog installation, production enrollment,
station command transport, Secure Boot or attestation acceptance. This document
does not itself launch an instance, allocate a disk or authorize a disk wipe.

## Test environment and preparation

Use a newly designated disposable instance with systemd and Python 3.12+, an
independently recoverable administration channel, and a separate explicitly
disposable data disk. Retain the normal operating-system boot disk. host-deploy
should record exact instance and volume IDs and validate that the data device is
not the root disk before its separately authorized partitioning/formatting step.
Host-install's physical-device writer remains disabled.

Provision one ext4 partition with recorded GPT PARTUUID and filesystem UUID.
Mount it at `/state`; mounted root is root:root 0755. The unmounted directory
should be empty, root:root 0000. Verify the root operating system remains usable
without STATE. Do not use this experiment on host-registry or an existing enrolled
host. Keep station endpoints unreachable or use reserved `.invalid` fixtures;
never approve a test fingerprint against a production host UUID.

Provision the fixed account profile after checking every name and numeric ID for
collisions: host-discover UID/GID 970, box-control UID/GID 971, archive-consumers
GID 972, host-control GID 973. Host-discover groups are 972/973; box-control group
is 972. Homes are `/state/<account>`; shell is `/usr/sbin/nologin`; passwords locked,
no sudo and no capabilities. Reject a conflicting host rather than allocating
other IDs. Do not create identity directories through account-creation defaults.
NSS checks are implemented; deployment must additionally verify locked passwords
and privilege policy.

Install the exact published host-install pass and pinned host-identify package
in one root-controlled Python environment readable/executable by UID 970. Match
the unit ExecStart paths to its installed host-install console script. Do not rely
on PYTHONPATH: the child deliberately clears it. Pin dependency versions in the
host-deploy test payload; record those actually installed. Our local integration
used Python 3.12.14, host-identify 0.3.1, cryptography 50.0.2,
http-message-signatures 2.0.1, requests 2.32.5 and PyJWT 2.10.1.

Build a reviewed bundle using the actual test partition/volume/installation IDs,
new authorization/record UUIDs and truthful artifact/generation expectations. A
synthetic artifact remains explicitly non-bootable. `state-stage` validates and
publishes an offline overlay. The deployment harness must separately place its
record set under `/etc/zog/host-install` before enabling any startup units. No
active service should read a partially copied overlay. Publish bootstrap last,
verify ownership and fsync the destination directories. No key enters this overlay.

## Acceptance sequence

1. Before marking the filesystem, run `state-inspect`. Expect rejection for the
   absent volume marker and no identity or control writes.
2. Run `state-prepare --initialize-volume <state_volume_id>`. Verify metadata and
   all fixed owners/modes. Repeat it without the flag: same result, no identity.
3. Run `state-initialize` without authorization. Expect rejection and no key.
4. Run `state-authorize --initialization-id <authorization_id>`, then
   `state-initialize`. The child must genuinely execute as UID/GID 970. Verify
   identity/receipt ownership, root-private consumption and the root-owned `/run`
   projection. Retain only public fingerprints in test reports.
5. Repeat initialization and reboot. Verify identical fingerprint/key identity,
   no prepare call for consumed state, successful load-existing and a projection
   for the new boot ID. A reboot does not approve a station session.
6. Install the reviewed mount and root oneshot templates and start the identity
   unit. Verify the requires/after/binds-to behavior. Do not install the managed
   host-discover drop-in: its live admission remains deliberately unavailable.
7. Stop dependent services before resetting each destructive failure fixture.
   Exercise absent mount, wrong volume, read-only mount, permission conflict,
   storage exhaustion/write failure and removal of a completed control directory.
   Every case must fail without fallback directories or replacement state.
8. On a separate disposable reset/snapshot, interrupt after key publication but
   before consumption. Resume the same key. Interrupt consumption publication:
   resume the same receipt. Restore the original test state between independent
   cases; never delete evidence to make a failed case succeed.
9. After a completed transaction, remove/corrupt key material on a disposable
   copy. Expect load-existing failure, no prepare/regeneration, no usable runtime
   projection, and a protected recovery hold where storage remains writable.
10. Declare migration/recovery mode or supply incompatible schemas. Expect
    refusal; automatic adoption, downgrade, hold clearing and remote recovery
    are outside this pass.

For mount-loss testing, confirm that systemd stops the dependent oneshots and
future initialization fails. There is no running admitted beaconer yet, so this
cannot establish its future in-flight command/signing shutdown behavior. Test
that separately when host-discover's adapter is ready. Synthetic ENOSPC/EIO tests
already run locally, but real error propagation and filesystem behavior need
this independent host run.

Capture exact source/dependency pins, systemd/kernel/filesystem versions, unit
exit results, mount observations, owner/mode listings and public fingerprint
continuity. Never export identity.pem or prepared-key.pem as ordinary test logs.
Preserve protected STATE evidence if a case fails. Cleanup/termination belongs
to the separately authorized disposable-host test operation.

## Explicit limits

The original pass-3 implementation used only local tests; the subsequent AWS
acceptance is recorded separately in the results linked above. The Work container
maps only UID 0 and cannot establish actual UID 970 ownership/execution. Local
integration uses real host-identify crypto and persistence in disposable files,
with a synthetic mount context and UID 0 ownership substitution. Unit syntax was
checked against systemd-analyze in a synthetic root; no systemd services ran.

host-discover's newer handoff at `84b969284e6105ca85ca70fc4867fe7ec2132a12`
uses the authoritative host-install validator, resolving the preliminary parser
mismatch. Live admission, station fresh-session/replay recovery and the box-control
gateway still need completion before
an end-to-end managed enrollment/control deployment. A whole-STATE rollback cannot
be detected by local records; this test must not be reported as solving it.
