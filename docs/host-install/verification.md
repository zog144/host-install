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
