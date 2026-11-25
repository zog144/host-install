# Prepared first-Fonts Project: reconcile the original source manifest

**Source-only candidate; no native authorization.** This procedure applies to
the existing initialized destination
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`.
Its original `.first-fonts-initialization-v1.json` records **image-build**
`620378bdd8075daeb5eaad45eedea4af7db36423`, box-control
`fdafbfb3032847b73c77abd9d90d769e43fddf85` and build-record
`a866c9c4b0dd385045f00ce2de7d809f5b67c104`. A later clean
`source` checkout at a different image-build HEAD is **not** the source
recorded by that manifest. The existing initializer `--verify` must continue
to refuse that mismatch; do not relax `SOURCES`, overwrite the manifest,
`git checkout` in the live Project, or re-run `--stage/--commit`.

## Supported path A — restore the exactly recorded source tree

Use `host-install-fonts-source-reconcile --reconcile-plan --source-checkout
<absolute-clean-original-image-build-checkout>` with the *external* checkout
at the exact historical commit `620378bdd...`. This read-only plan authenticates
the original canonical manifest, expected original source hash, unchanged
box-control and build-record Git provenance, observed clean but different
image-build checkout, source origin, and Project/state inode identities. Unknown
root entries, controllers, nonempty/foreign runtime layout, unsafe paths, dirty
Git checkout, unexpected companions, noncanonical manifest or unsupported
source revision fail closed. The returned `plan_sha256` binds the exact
observed/reviewed source pair and physical destination identities.

Have the separate source/native owners **independently review and approve the
exact plan digest** before considering a mutating action. During a separately
approved exclusive inactive maintenance window, with the same existing effective
process identity, use:

```sh
host-install-fonts-source-reconcile --restore-reviewed-source \
  --source-checkout /reviewed/image-build-original-exact \
  --expected-plan-sha256 <independently-reviewed-64-hex-plan-digest>
host-install-fonts-project-init --verify
```

The restoration command rechecks the plan under a durable locked path and
creates a **new private staging checkout outside the Project**. It verifies
the exact recorded source revision/tree and copies it with no unexpected files,
then fsyncs it and creates a 0600/fsynced, create-only plan receipt. It
performs Linux `renameat2(RENAME_EXCHANGE)` between the existing
`Project/source` and this reviewed staging tree. This single atomic exchange
leaves the displaced (newer) checkout at the fixed protected sibling path
`.gateway-first-fonts-runtime.source-recovery`; no source is deleted.
The original manifest and `Project/state` are untouched. The initializer's
unchanged `--verify` must pass after the exchange with the original manifest
SHA and the expected original source/companion Git tree digests.

An interrupted staging *without* a complete retained receipt is a HOLD; do
not delete/recreate the staging path or invent a receipt. If the receipt exists
and the source exchange has not yet happened, a retry revalidates **all** exact
plan/checkout bytes and will not overwrite or adopt conflicting staging.
If the exchange already happened, use **read-only** initializer `--verify`
and verify the preserved older checkout/receipt; do not initiate a second
exchange. A remaining conflict or unexpected object requires source-owner
reconciliation, never a manual shortcut.

## Complete read-only verification after an atomic exchange

If the process was interrupted **after** the directory exchange, the original
initializer `--verify` alone is insufficient: it does not authenticate the
immutable source-recovery receipt or the displaced previous checkout. The
source-owned verification command is:

```sh
host-install-fonts-source-reconcile --verify-recovery \\
  --expected-plan-sha256 <independently-approved-64-hex-plan-digest>
```

This operation **does not** require the external original checkout; it reads
the durable plan receipt, checks its exact canonical bytes, known schema and
approved digest, and binds the unchanged original initializer manifest
(bytes and digest), frozen destination/state identities, completed original
source and retained displaced checkout at the fixed protected sibling path.
It revalidates actual clean Git worktree bytes, Git origin/revision/tree,
complete physical inventory, and unexpected file rejection for **both**
source trees. The initializer's original source/companions, empty runtime
layout and no-controller assertions still apply. A missing lock, torn or
substituted receipt, missing or changed displaced checkout, Git-ignored
content, changed state inode, missing manifest or incomplete exchange is a
HOLD; this command neither creates a lock nor retries an exchange. The
command sets `mutation=false` and `compilation_authorized=false` in its
readback result.

## Complete checkout integrity and Git metadata

A clean `git status --porcelain=v1 --untracked-files=all` **does not**
exclude ignored payloads. The reviewed source and both source trees are
therefore independently checked with both
`git ls-files --others --exclude-standard -z` and
`git ls-files --others --ignored --exclude-standard -z`.
Neither ordinary untracked nor Git-ignored worktree objects may enter the
privileged Project. The reconciliation plan also binds a canonical physical
file/mode/symlink inventory covering the entire checkout **including Git
metadata**, and repeated inspection verifies unchanged bytes/modes before
the final swap. Volatile directory/file mtimes are excluded, and
`.git/index` is checked as a protected ordinary index plus verified
Git logical HEAD/index consistency rather than binding its self-refreshing
stat-cache bytes, which change when Git refreshes a copied checkout.

A file introduced after approval, an ignored payload introduced into
receipt-backed staging or changed Git metadata is never silently adopted
under an unchanged `HEAD^{tree}` hash. Any such change makes the original
approved plan ineligible; start a new independently reviewed plan only
after resolving the source discrepancy **without overwriting history**.

## Native execution identity prerequisite

**HOLD unless the same installed root execution identity owns the already
retained Project, source, state, receipt and private parent paths.** Native
reconciliation planning now requires `euid=0`, and the protected directory
checks require exact effective UID/GID custody; restoration itself also
requires root. If the existing Project is instead owned by UID 24201,
the current native contract is **not satisfiable**. Do not chown/move the
Project, switch to a spare account or waive ownership checks to make it pass.
Work must read back the actual ownership, decide whether an alternate
source-reviewed contract is needed and obtain a fresh approval before any
native restore.

## Supported path B — new intended image-build revision

If the goal is to **adopt** the newer image-build HEAD rather than restore the
recorded original, the existing manifest cannot authorize that selection.
First publish and independently review a **distinct manifest/source revision**
with exact image-build commit, clean Git tree digest, original manifest and
historical state binding, plus host-deploy lane consumer and pin compatibility.
No current initializer operation may label the old manifest as approving a new
tree. Do not manufacture new `source_tree_sha256`, overwrite the original
manifest, destroy historical receipts or activate the consumer based on a
source-only candidate. This is a separate source-selection change, not a
flag to `--verify`.

## Safety and acceptance boundaries

The existing prepared-init destination and state are never recreated or
deleted, no alternate user/group is selected, and neither path authorizes a
controller launch, Task C webhook submission, Fonts compilation or SSM action.
The original lane and accepted compiler generation are retained. Work must
attest actual installed host-install package/RECORD, physical Project paths,
permissions, source Git objects, original manifest hash (historically
`535c0c283599c8ad3e256d4cdf8db5bb4b16bf1350dfec59de10ebde52d79cb7`),
independently reviewed plan and any existing recovery sibling before mutation.
Keep the destination isolated from automatic source updates until this
reconciliation is explicitly accepted and independently verified.
