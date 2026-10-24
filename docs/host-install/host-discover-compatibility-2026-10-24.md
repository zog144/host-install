# host-discover 0.4.11 / host-install 0.14 compatibility

**Selected host-discover source:** `9e741d9a86bb2fd466ac46b252be0b78528eeff7`  
**host-discover version:** 0.4.11  
**Independently tested host-install baseline:** `889f137dc19d1f34fca42fd3dd8df862f8ebae9d` (0.14.3)  
**Selected host-identify source:** `1a5eac0b255c995022db6a3a4c0051efffa748cc`

This is the current managed-beacon consumer selection. It supersedes the
historical 2026-10-18 host-discover compatibility selection for new beacon
composition, while preserving that older document as historical migration
evidence.

## Why this successor is required

The retained non-resident native installation exposed a real source mismatch:
the predecessor managed report path unconditionally read the resident-only
`installer_recorded.foreign_boot_bundle` field before enrollment. A valid
schema-2 non-resident installation correctly has no such field.

host-discover 0.4.11 first asks host-install's exact
`installation_mode()` contract:

- resident installations retain the existing foreign-boot/provider behavior;
- non-resident installations do not invent HOST slots, root generations or a
  foreign boot bundle and instead attach host-install's verified schema-2
  `host_generation_report()`.

The successor's privileged default-report regression exercises production
`Beacon.tick()` without injecting a prebuilt report, verifies the real signed
pending-enrollment request, and proves that the non-resident branch does not
call the resident AWS metadata helper.

## Exact source and installed-byte binding

`beacon_profile.CONSUMER_COMMIT` is the immutable revision above. Source
staging verifies all 17 top-level `zog.host_discover` Python modules by Git
blob identity, including corrected
`zog.host_discover.managed_transport=386384ade8606797cd7be855e26951be63bac2e1`.

The three producer templates used by the managed-beacon composition and the
supervisor/certificate-assignment authority source blobs are byte-identical to
the previously reviewed selection; adopting 0.4.11 therefore does not silently
change the service graph.

The staged `zog-managed-beacon-profile` manifest records:

- exact host-discover commit and component version;
- the full reviewed runtime module inventory and SHA-256 values;
- rendered unit hashes;
- explicit supervisor preparation policy;
- any separately reviewed certificate-assignment authority pin, if one is
  intentionally supplied.

No authority pin is required or implied by selecting this consumer.

Before restarting a retained installation, run the supported installed-byte
attestation against the distribution actually installed there:

```sh
sudo env -u PYTHONPATH -u PYTHONHOME \
  /opt/zog-state-test/venv/bin/host-install beacon-attest-installed \
  --python-executable /opt/zog-state-test/venv/bin/python \
  --distribution host-discover
```

The default is the standalone `host-discover` wheel used by the retained
native installation. `--distribution zog` is available for an aggregate-wheel
composition. Attestation requires root-owned protected module ancestry, exact
reviewed Git blobs and matching SHA-256 entries in the selected wheel
`RECORD`. It does not write STATE or authorize station approval.

## Current compatibility CI

host-install CI checks out exact host-discover 0.4.11 and host-identify sources,
verifies the immutable revisions and host-discover's declared
`host-install==0.14.3` dependency, then runs the successor's full ordinary and
privileged host-install compatibility suites on Python 3.12 and 3.13.

host-install's own compatibility regression also preserves the fixed UID/GID
contract and imported STATE/admission API call shapes, including
`installation_mode()` and `host_generation_report()`.

## Retained-installation continuation

The retained installation, STATE volume, host identity, consumer journal and
supervisor fault are inputs to recovery. Software adoption must not erase or
recreate them.

After installing and attesting the accepted 0.4.11 successor:

1. do **not** run `beacon-prepare` again;
2. do **not** delete/recreate STATE, identity, journal or supervisor ledger;
3. stop the beacon and freshly inspect the current supervisor revision, active
   or faulted run UUID and journal;
4. use `host-discover-supervisor reset` only with those freshly observed CAS
   values and an explicit operator reason;
5. restart the corrected managed-beacon composition and observe the actual
   enrollment response.

Historical revision/run literals from retained evidence are not retry
authorization and must not be replayed blindly.

## Station and certificate boundary

A successful corrected beacon is expected only to produce the real pending
enrollment request. Station approval/export must wait until that request exists
and its host fingerprint has been independently verified against the retained
installation.

Selecting or attesting host-discover 0.4.11 does **not**:

- approve a station Host;
- export station authority;
- install a root signer/authority pin;
- initialize issuer/controller state;
- issue a certificate;
- mutate DNS or nginx; or
- authorize production HTTPS.

Those remain separately owned native gates.
