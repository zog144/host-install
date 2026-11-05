# Task C retained original S3 checkpoint — host-install PR #30 correction

2026-11-05 · Source-only installer correction. Native retained installation acceptance remains Work-only.

## Exact immutable checkpoint origin

The first authorized installation must durably select and record the following **original** S3 checkpoint fields and never derive a replacement from current gateway input:

- AWS account ID, region, S3 bucket and prefix
- Independently selected root-control checkpoint scope SHA-256
- Original S3 genesis SHA-256 and owner-exclusive checkpoint role ARN
- Host ID, installation ID, STATE volume ID and selected root-control source revision

These values are taken from host-install PR #30's exact disabled installation manifest plus the separately protected owner-selected original scope, not a caller's incoming IPC request. `graphical_original_checkpoint_record.py` defines a canonical bounded JSON record, protected 0700 directories and 0600 regular files, no symlinks/hardlinks, `O_EXCL` and fsync for files and directory entries. It separates one-time reservation from read-only continuation:

1. **First install, explicitly authorized only:** reserve an original identity commitment first in an independently retained anchor directory, fsync it, reserve the same commitment in the owner ledger, fsync it, then publish and fsync the original checkpoint record. Any interrupted stage leaves an ambiguity that **holds**, not a retry-to-initialize. `explicit_first_install=True` is a source fixture switch, **not independent operator authorization**; native Work must authenticate original external approval and fresh installation independently.
2. **Retained installation:** `graphical_native_owner_install.verify_retained_original_checkpoint` calls the read-only checker. It requires all three existing and exact canonical records, compares the original Host/installation/STATE/account/region/bucket/prefix/scope/genesis/role and source with the independent originally approved inputs, and returns only `ORIGINAL_CHECKPOINT_CONTINUATION_MATCH_UNACCEPTED`. The normal continuation never creates a directory, record, anchor, AWS checkpoint or service.
3. **No reinitialization:** removing the installed ledger-side record and/or its local reservation still leaves the independent anchor, preventing even an explicitly invoked first-install call from reusing the origin. Substitution of any exact policy field, changing the original scope, replacing files with unsafe links or noncanonical JSON, or a missing/corrupt independent anchor denies. Never select a new bucket, prefix, genesis or role just because old record is absent.

**Important native storage boundary:** Tests use two synthetic directories under one temporary filesystem; that is *not* independently durable protection. Work must locate and authenticate the original independently retained anchor / monotonic checkpoint from the existing installation, verify its physical storage/ownership identity and non-replacement across reboot, and refuse any automatic creation of a missing anchor. If the independent anchor and local record are *both* erased by an administrator, these local bytes alone cannot prove history: the external originally approved S3 genesis and installer-native authority must deny rebootstrap. A file-only record is not a proof of remote S3 durability, bucket retention/Object Lock, IAM exclusivity or a current authority grant.

## Work verification on retained installation

Before any activation or send: capture original registered Host/installation/STATE source identities, root-control scope, AWS account/region/bucket/prefix/genesis/checkpoint role from independently pinned installation and existing external checkpoint. Confirm exact three-way comparison and same-byte read-only continuation. In a disposable clone of the protected record, test each changed field and missing local record, then test interruption after external anchor and after local reservation, without deleting or reinitializing production originals. Verify independent anchor storage identity and reboot persistence. Owner-exclusive checkpoint session/SSM session, gateway IAM denial and signed-v2 observation remain separate native GO gates. **Do not create a new genesis or switch original S3 role to make this test pass.**

Source tests: `tests/test_graphical_original_checkpoint_record.py`, integrated into PR #30's pinned three-owner GitHub Actions workflow on Python 3.12/3.13. No AWS, SSM, STATE or native installation changes in this Regular correction.
