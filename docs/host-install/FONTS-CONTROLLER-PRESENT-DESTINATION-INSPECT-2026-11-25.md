# Read-only controller-present first-Fonts destination inspection

**Status: source-only diagnostic; native HOLD until independent source/identity acceptance.**

This addresses the missing host-install companion to
[host-deploy PR #59](https://github.com/zog144/host-deploy/pull/59).
The November 14 prepared destination is
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`, which
retains its original `.first-fonts-initialization-v1.json` manifest
(`535c0c283599c8ad3e256d4cdf8db5bb4b16bf1350dfec59de10ebde52d79cb7`,
**canonical manifest-object SHA**). That manifest records image-build
`620378bdd8075daeb5eaad45eedea4af7db36423`, box-control
`fdafbfb3032847b73c77abd9d90d769e43fddf85`, and build-record
`a866c9c4b0dd385045f00ce2de7d809f5b67c104`. The actual Project
may now contain an `controller-inherited-v1.json` and a different
image-build Git revision. Neither the original manifest nor the active,
**different** `/home/certbot-build-owner/certbot-seed` Project may be
rewritten to make this history look consistent.

## The supported command

```sh
host-install-fonts-controller-present-inspect --inspect
```

The command has **no** alternate root, user, UID/GID, source-pin, controller,
manifest or output-path options. It uses the currently installed read-only
root process and reads the already retained historical Project. In native
mode it requires `euid=0`, but the original destination must independently
be owned by its existing **UID 24201** with private mode 0700. It does not
switch effective identity, chown anything, issue SSM, acquire an active
controller permission, alter a running service, or create a lock or receipt.

The inspector walks the **entire fixed path from /** using anchored
`dir_fd` and `O_DIRECTORY|O_NOFOLLOW`, and checks symlink ancestry,
owners, writable modes and pre/post directory inodes. It performs bounded
`O_NOFOLLOW` reads for the existing controller and immutable original
manifest, verifies their content and owner/mode/link/size/inode stability,
checks the original canonical manifest SHA and source revision selections,
and records the controller SHA and inode. It opens the retained **STATE**
directory and reports only its inode, owner and mode without modifying or
exposing private identity data.

The existing source and two companion checkouts are opened via anchored
directory file descriptors; Git `rev-parse HEAD`, `HEAD^{tree}` and
`remote get-url origin` run against `/proc/self/fd/<source-fd>` with
`pass_fds` and `GIT_OPTIONAL_LOCKS=0`, with global/system Git
configuration disabled. Git metadata directories must be real nonlinked
directories. This is an **observed Git HEAD/tree diagnostic**, *not* a full
physical inventory or an attestation of every Git-ignored file. The report
explicitly sets `full_checkout_contents_authenticated=false`. A source
revision different from the original manifest is **reported** as such,
never silently repinned or treated as verified initialization. Companion
differences are likewise reported without inferring authority.

Only the original known Project-root entries, original manifest and exactly
one original inherited controller are admitted; unknown root contents,
unknown controller, missing/altered manifest, extra controller, foreign or
symlinked paths, hardlinks, writable evidence and changed STATE inode HOLD.
Existing application/runtime directory contents are not inspected or
removed. The report is `status=controller-present-unresolved`, with
`initialized_controller_authority=false`,
`historical_writer_authenticated=false`, `mutation=false`,
`ssm_send_authorized=false`, `execution_authorized=false` and
`compilation_authorized=false` in every successful observation.

## Distinct, unsupported operations

**Do not** run the old controller-free
`host-install-fonts-project-init --verify` and claim success while the
inherited controller is present or source revision differs. The PR #50
`--restore-reviewed-source` is a separate authorized source transition
with a strict controller-free precondition, not a repair shortcut for this
historical destination. This inspector never performs or authorizes
either transition.

Source CI uses a disposable initialized Git Project, deliberately adds the
controller and advances image-build Git HEAD, preserves original manifest
and STATE bytes/inodes and checks that a read-only observation reports the
discrepancy. Negative tests cover missing, symlinked, hardlinked, malformed
or writable controllers, altered manifest, foreign Project entries, missing
or symlinked state/source, redirected .git and changed origin, plus no
fallback to mutating initialization/restoration.

## Handoffs

**Host-install Regular:** independent source review and exact-head CI
acceptance of this diagnostic revision, including native identity handling.
**Host-install Work:** read-only verify installed package/RECORD, existing
Project controller, original manifest and actual UID/GID without changing
owners. Stop if Project identity or unexpected contents differ.

**Host-deploy Regular:** after this source contract is accepted, bind
a separately reviewed *protected historical-command readback* to the
**actual two November 14 SSM CommandIds**, root-control journal, fixed
instance/account/region, original approval, controller and Project history.
The registry PR #59 report remains `supersession-unproven` until those
facts are authenticated. Any future fixed read-only compiler command
requires an independent protected sender review; PR #59's offline pair
candidate does not constitute SSM send authority.

**No native Host/SSM mutation, original command replay, Project or manifest
rewrite, controller activation, Gateway start, Fonts build, or new lane
admission is authorized by this source-only diagnostic.**
