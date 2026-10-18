# host-discover 0.4.8 / host-install 0.10.0 compatibility contract

**Date:** 2026-10-18  
**host-discover candidate:** `341255fd0ebdee5eedfd4be9a40829ec17391887`  
**historical host-install API baseline:** `b2323c8d2cb7f00b1d0145451ca72fbbbd5fb486` (0.4.4)  
**host-install implementation under review:** 0.10.0 on `unstable`

This document addresses the public-migration remediation item caused by the
selected host-discover source declaring the obsolete standalone dependency
`host-install==0.4.4` while the selected aggregate component is host-install
0.10.0.

That requirement must **not** be satisfied by publishing an old standalone
host-install distribution, adding a compatibility top-level package, or merely
editing a version string. Zog's public Python publication is the aggregate
`zog` distribution.

## Actual host-discover imports

The reviewed host-discover candidate consumes these canonical
`zog.host_install` surfaces:

- `state_contract`: `StateError`, `canonical`, `decode`, `fields`,
  `header`, `require`, `sha`, `validate` and the fixed STATE records;
- `state_inspect`: `directory`, `metadata`, `read_at`,
  `assess_mount`, `inspect_live`, `host_generation_report`;
- `state_admission.request_live`;
- `state_gate.decide`;
- `state_probe.probe_live`;
- `state_io.raw`, `publish`, `ensure_directory`, `lock`.

It does not import the newer certificate, welcome-progress or controller-observer
modules to satisfy its existing STATE/admission path.

## Source API comparison

The public host-install 0.4.4 source commit and the current 0.10.0 source expose
the same function/class signatures for every imported interface above.

The fixed account contract also remains:

- host-discover UID/GID: `970:970`;
- supplementary groups: archive-consumers `972`, host-control `973`;
- identity path: `/state/host-discover/identity`;
- trust path: `/state/host-discover/trust`;
- control path: `/state/host-discover/control`;
- STATE account profile: `zog-host-accounts-v1`.

`tests/test_host_discover_compatibility.py` freezes that exact consumer-facing
surface. It deliberately does not declare unrelated internal host-install
functions stable.

## Cross-component execution gate

Public CI checks out the exact host-discover candidate above plus its reviewed
host-identify companion and installs host-install from the current repository.
host-discover is installed with `--no-deps` **only for this compatibility
execution**, so its stale packaging requirement cannot decide the result.

The compatibility lane runs the host-discover tests that directly consume
host-install:

- beacon HTTPS/unit fixtures;
- bootstrap/STATE policy;
- host-generation observation;
- managed STATE;
- managed admission;
- namespace layout;
- narrow admission;
- network retry;
- session recovery;
- supervised beacon.

This proves source/runtime compatibility only for the tested source pair. It
does **not** make `host-discover@341255f...` a releasable aggregate component,
because that revision still publishes stale independent-component dependency
metadata.

## Required host-discover follow-up

host-discover Regular should issue a new reviewed source revision which:

1. removes the obsolete independent-PyPI `host-install==0.4.4` requirement
   rather than changing it to `host-install==0.10.0`;
2. represents host-install as an aggregate component dependency in the
   component manifest;
3. retains the canonical `zog.host_install` imports tested here;
4. reruns its own namespace/package tests and this exact cross-component suite;
5. includes its complete runtime Python/package-data/license closure for the
   host-deploy source manifest.

Only that new host-discover revision, paired with the exact tested host-install
revision, should be handed back to host-deploy for regeneration of
`beacon_sources.json`.

## Native evidence boundary

The CI compatibility suite is intentionally non-root source/synthetic evidence.
It does not replace the existing native STATE/account/mount/socket acceptance.
The host-deploy Work rerun must prepare the confined root fixtures separately
and verify the real UID 970 account, STATE ownership/mounts, admission socket,
reboot/failure paths and installed aggregate bytes.

No production publication or host-deploy GO follows from this source
compatibility result alone.
