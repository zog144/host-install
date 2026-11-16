# Combined issuer controller selection — November 16, 2026

## Scope and immutable source selection

This is **host-install Regular source preparation**, not a repeat of the
already completed root-control/box-control issuer-function restoration.
[host-install issue #2](https://github.com/zog144/host-install/issues/2#issuecomment-6917604121)
reports four outdated installed issuer module blob pins and an ambiguous
Python importer.

The selected package is a **single distribution named `zog`** containing
the actual issuer-capable and inherited-user-capable controller sources:

| Component | Original reviewed commit | Checked modules |
|---|---|---|
| box-control PR #21 | `c886e7a90bb4ea74e771a6c5dcefaa2069539ec7` | 10 |
| root-control PR #51 | `d9dfd6c02a5a96750f1213bf663cdceab72f1efd` | 5 |

The exact original source blob pins are taken from image-build PR #24
`project/host/resident-b-aggregate-installed-source-pins-v1.json`
(source revision `77a5e3c13e1c41582b3278941fb4b1f5e2f16678`).
Of the fifteen selected imported modules, only these four changed since
the earlier host-install issuer selection:

- `zog.box_control.issuer_lifecycle_broker`: `fc32e0c42fd97cdadefa197f9a0bfdc2beacc7c9`
- `zog.box_control.issuer_lifecycle_client`: `3168d674963259aadacfed05c91cec765928f094`
- `zog.root_control.daemon`: `e5f6b8d15a8cb9cf9aeed7658a2d01271be380ab`
- `zog.root_control.systemd`: `0f0e78c50ed5f517d30f63cb56471138319df7c2`

The remaining eleven original module blobs were checked against the same
new aggregate selection and kept. Neither component source is rewritten,
and the historical alternate account/UID selector is not restored.

## Importer and distribution layout

The reviewed image-build Resident B source selects:

- **Interpreter:** `/usr/bin/python3.12`, actual CPython 3.12;
- **Install location:** `/usr/lib/python3.12/site-packages`;
- **Distribution:** the **one aggregate** `zog`, with matching selected
  modules and a real installed `zog-<actual-version>.dist-info/RECORD`.

This is **not** the Host's possibly Python 3.15 `/usr/bin/python3`, nor
separately installed `box-control`/`root-control` wheels. The
`certify-manage-controller-attest-installed` CLI now defaults to the
explicit 3.12 interpreter and refuses a different resolved executable,
runtime Python version or site-packages root. It still requires root and
rejects `PYTHONPATH`/`PYTHONHOME`. All fifteen controller imports must
come from protected root-owned files inside the selected aggregate and
match the original Git blob pins, installed RECORD SHA-256 and **byte size**.
The nonactivating lifecycle broker unit is explicitly rendered with
`ExecStart=/usr/bin/python3.12 -m
zog.box_control.issuer_lifecycle_broker ...`. Its installation plan
records the controller interpreter, site-packages and distribution.

The current attestor requires that its *own running process* use this
selected 3.12 importer; do not call its CLI through a Host 3.15
`host-install` console-script or try to make it work with `PYTHONPATH`.
The actual aggregate from image-build task 1 must provide an importable
`zog.host_install` under this same interpreter and retain its own exact
installed RECORD; if the required selected package is absent there, **HOLD**
rather than importing the wrong wheel. The supported invocation after
native installation/packaging identity readback is:

```sh
# READ ONLY. Invoke the genuine selected interpreter, not /usr/bin/python3.
env -u PYTHONPATH -u PYTHONHOME /usr/bin/python3.12 -I \
  -m zog.host_install certify-manage-controller-attest-installed \
  --python-executable /usr/bin/python3.12
```

The additional image-build full aggregate verifier must first establish
the actual wheel's canonical source selection, all installed RECORD
members, metadata and console scripts. The host-install attestor
independently checks its fifteen issuer-critical modules under the
same selected interpreter. Neither checker issues an approval, creates a
rootfs generation or substitutes a source-only synthetic RECORD for real
installed bytes. No fixed `zog==0.1.0` wheel is silently overwritten:
the actual distinct artifact/version must come from the producer.

## Native follow-on and authority boundaries

1. image-build Work completes task 1: pins the remaining `zog` aggregate
   source/rights/toolchain closure, builds a **real distinct** aggregate,
   returns wheel hash, installed RECORD hash, actual interpreter path,
   package prefix, rootfs generation, installer receipt and provenance.
   Source-only CI fixtures are not native installed evidence.
2. host-install Work independently reopens and attests the installed
   package and checks rendered issuer broker and root-controller service
   selections before any controller-selected `prepare` or
   `inspect`/`observe` operation. A module import or successful
   service restart is not issuer readiness.
3. **Separate station authority:** the original station issuer must
   approve the *fresh* managed DNS-01 assignment for the exact existing
   Host/installation/hostname/Cloudflare zone/ACME staging policy and
   current revision. Host-install cannot invent the signature or reuse
   a superseded grant.
4. Only then use the existing protected purpose-scoped HTTPS/anonymous-FD
   credential delivery and authenticated preparation/inspection. Maintain
   the original Host identity, protected STATE, issuer grant/storage and
   certificate lineage, and reconcile the prior uncertain attempt and
   durable ledger before retrying. No token in argv, environment, SSM,
   logs or source. No DNS mutation, ACME issuance, public certificate
   deployment or process-account switch in this source task.

## Source acceptance

`.github/workflows/certify-combined-controller-selection.yml` checks
the exact PR #21 and PR #51 Git checkouts, the reviewed image-build
aggregate source manifest, and the separate historical image-build and
certify-manage application source pins. It retains the issuer staging,
policy, prepared storage and native-installed attestation source tests,
including actual root-owned disposable staging, and adds negative
wrong-interpreter, ABI, package root, changed module and tampered RECORD
tests under Python 3.12 and Python 3.13. The installed RECORD fixtures
remain explicitly synthetic.

**Status:** host-install issuer source selection prepared; actual aggregate
wheel/RECORD and native authenticated `inspect` remain pending image-build
task 1 and subsequent Work acceptance.
