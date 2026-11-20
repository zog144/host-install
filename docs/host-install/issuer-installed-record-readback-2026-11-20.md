# Nonresident issuer aggregate RECORD readback — November 20 source diagnosis

**Owner:** host-install Regular. **Scope:** source-only correction to the
read-only `certify-manage-controller-attest-installed` command. **Explicit
restriction:** do **not** run another Host command, SSM request, package
reinstallation, pip install, issuer mutation, ACME action or service restart
under this handoff.

## Retained evidence

The retained Library report `host-install-attestor-report.json`, dated
November 19, 2026, records **failed** SSM operation
`39a3cdc0-23bf-4bdb-a2b2-d9f42c45beeb` on
`i-00ad300038a599044` in `us-east-1`, response code **2**.
The exact command used `env -u PYTHONPATH -u PYTHONHOME` and
`/usr/bin/python3.12 -I -m zog.host_install
certify-manage-controller-attest-installed
--python-executable /usr/bin/python3.12`.
The only attestor result was:

```text
certify-installed: aggregate RECORD absent or differs from installed bytes
```

The report did **not** include the actual RECORD path, its byte length,
physical SHA-256, the Python metadata-view length/hash or CSV row counts.
It cannot establish which side of this combined boolean failed.

Separately, the previous image-build Work records for the same accepted
nonresident aggregate `zog==0.1.1.dev20261117` state:
- root-owned installed Python 3.12 package under
  `/usr/lib/python3.12/site-packages`;
- **509** original verified RECORD members, **16** original Python 3.12
  console launchers;
- accepted original *Host-installed* RECORD SHA-256
  `8a4428184d096a1f24e68b394b6dcd26a23cf345fe59d7e74ce18c57493e6d30`.
  This differs from disposable runner RECORD
  `b4aea0184dcd267f1070bcc6b72e8ab3d85d714b5d2031e2eabe12463108d8a3`
  because final native installation output paths and generated launchers
  need not be identical to the runner's layout. Do not substitute the CI
  hash for the actual installed record.

**Reconciliation, not an invented native finding:** The selected attestor
in host-install PR #44 obtains the Python 3.12 distribution via
`importlib.metadata.distribution("zog")`, enumerates a single
`zog-<version>.dist-info/RECORD`, then compares
`distribution.read_text("RECORD").encode("utf-8")` directly against
`record_path.read_bytes()`. Python's metadata text API uses universal
newline translation and may return LF for a physically installed CSV
`RECORD` whose bytes use CRLF. A real-distribution disposable test confirms
this precise distinction. **It is a plausible explanation for the Host
failure, not proof**: the retained SSM result provides no before/after
raw bytes or metadata-view hash.

## Corrected source behavior

New `certify_record_readback.verify_record` is used by the unchanged
Python 3.12 attestation entrypoint.

- Select exactly the same root-owned, protected site-packages root,
  canonical distribution identity/version, actual dist-info directory,
  and member enumeration. **No** Python 3.15 fallback, PYTHONPATH,
  alternate wheel, synthetic distribution or installation command.
- Read the original installed `RECORD` through `O_NOFOLLOW`, with
  protected ancestry and opened-fd identity/size checks. The root-owned
  on-disk raw **SHA-256 remains the final `record_sha256`**, and its
  original bytes (not a normalized file) drive installed row parsing and
  each of the existing **15** exact controller-module source Git-blob,
  imported-path, RECORD digest and byte-size checks.
- Require the text returned by `distribution.read_text("RECORD")` to
  match **exactly** the raw decoded bytes after *only* Python's specified
  universal newline conversion (`CRLF → LF`, `CR → LF`). The
  metadata-backed distribution's actual `_path` directory must match
  the package's located original RECORD directory. Any other view
  divergence, foreign path, missing/duplicate recorded member or
  malformed data remains **HOLD**.
- Separate statuses:
  `missing_installed_record`, `empty_installed_record`,
  `oversized_installed_record`, `missing_metadata_record`,
  `empty_metadata_record`, `oversized_metadata_record`,
  `differing_record_views`, `metadata_directory_mismatch`,
  `record_listing_missing_or_ambiguous`, and unsafe/unreadable cases.
  An invalid or overlong Python `dist.files` CSV cannot abort the
  attestation before the protected raw-record diagnostics are produced.
- Return/report a **nonsecret diagnostic only**:
  `installed_record_path`, `metadata_record_path`, the two byte
  lengths and SHA-256 values where they can be safely computed,
  `listed_record_matches`, `installed_entry_count`,
  `metadata_entry_count`, `matching_entry_count`,
  `newline_translation_only`, and the exact status.
  The diagnostic contains no RECORD text/rows, Python source, secrets,
  credential paths/values, or env/argv dumps. The byte digest of an
  unexpectedly larger-than-16-MiB RECORD is omitted explicitly to
  avoid unbounded diagnostic reads; the size and failure status remain.
- The successful read-only attestation still returns
  `production_activation_authorized=false`. The unchanged source
  pins, interpreter/ABI, protected root ownership, one-distribution
  metadata requirements and all 15 module verification gates still apply.

## Source-test selection and acceptance boundary

`tests/test_certify_record_readback.py` constructs an **actual**
`importlib.metadata.PathDistribution` from disposable package
directories (not just a fake `Distribution.read_text`). It verifies
real LF, CRLF and CR text-view transformations; exact raw SHA-256/row
counts; missing, empty and oversize physical RECORD; independently
missing/empty/oversize metadata view; altered CSV rows and matching-entry
counts; a metadata-directory substitution; unlisted/corrupt data; and
bounded diagnostic hashing. The original issuer attestor tests cover
complete 15-module verification on a CRLF-installed RECORD, rejection of
different metadata, and safe handling of a real oversized
`PathDistribution.files` parser error.

The dedicated existing
`.github/workflows/certify-combined-controller-selection.yml` checks
these along with **all retained** issuer/profile tests on Python 3.12
and 3.13 using original reviewed box-control/root-control sources. The
obsolete signed-storage v4 workflow remains a separate historical
failure, not evidence against this selected read-only correction.

**No native classification yet.** Compare a future independently
authorized read-only result's *raw* `installed_sha256` with the
retained Host hash `8a4428184d096a1f24e68b394b6dcd26a23cf345fe59d7e74ce18c57493e6d30`;
compare metadata-view SHA only with that view. A successful local
disposable test or a matching RECORD row count is never an installed
Host acceptance. Preserve the failed SSM operation and existing wheel,
all 24 dependencies, root-owned files, Host/STATE and issuer lineage;
hold any new native command until **separate authorization** and exact
source/reviewed installation selection.
