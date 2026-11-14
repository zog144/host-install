# Initializing the first Fonts Project that was prepared but never created

This is **not** the legacy copy migration. Use this operation only after
host-deploy has authenticated the original `prepared` schema-4 record and the
compiler Host has verified that both the old and new Project directories are
absent. A lane previously `active`, or a lost/unavailable old Project that once
existed, requires recovery and must not be reinitialized.

Exact selected source inputs (stage clean detached clones with ordinary source
acquisition; they are genuine immutable revisions, never fabricated project
contents):

- image-build: `620378bdd8075daeb5eaad45eedea4af7db36423`
- box-control: `fdafbfb3032847b73c77abd9d90d769e43fddf85`
- build-record: `a866c9c4b0dd385045f00ce2de7d809f5b67c104`

All source checkouts must be complete, locally readable, clean, independent Git
worktrees with matching GitHub origin URLs. The initializer does not download
unspecified software, impersonate another user, or run a compiler. It copies
verified source checkouts directly into a private unpublished tree below
`/var/lib/zog/image-build/projects` and atomically publishes the actual
corrected Project. There is **no old source tree created** and **no copy
receipt**; a separate `zog-fonts-project-first-initialization-v1` observation
is produced by the owner. No `controller.json` or controller facts are
fabricated. No UID/GID value is selected.

Under an approved existing installer process, while the gateway is inactive:

```sh
host-install-fonts-project-init --inspect
host-install-fonts-project-init --stage \
  --source-checkout /reviewed/image-build \
  --box-control-checkout /reviewed/box-control \
  --build-record-checkout /reviewed/build-record
host-install-fonts-project-init --commit
host-install-fonts-project-init --verify
```

This sequence requires source owner review and original lane-prepared proof from
host-deploy; invoking the installer alone cannot authorize or manufacture a
lane. `--commit` uses Linux `renameat2(RENAME_NOREPLACE)` and refuses an
existing target. After an interrupted `--stage`, inspect the pending tree and
its manifest; it is never removed or overwritten automatically. An interrupted
`--commit` is reconciled by read-only `--verify`, not by another write.

The historical October pin is deliberately **not in the new image-build
checkout**. host-deploy's separately reviewed provenance-object retention
command obtains it from original `image-build@1f07e83d...` Git objects; it
verifies the genuine bytes, schema, original repository path and exact
SHA-256 before storing them under the new Project state directory. Do not
create a dummy old project or manually write the pin artifact.

Next, host-deploy's explicitly authorized prepared-lane initialization stage
accepts the *real* `host-install-fonts-project-init --verify` result instead of
requiring `host-install-fonts-project-migrate --verify`. The old schema-4
record and digest are archived verbatim; the new schema-5 digest is computed
from that actual record. The native controller must be installed via its
source-owned operation and verified before any catalogue rebinding.

The existing copy-only `host-install-fonts-project-migrate` commands remain
unchanged and apply ONLY when the old Project genuinely exists. The historical
account data must not be regenerated or deleted to make either path pass.

This is a source contract and recovery procedure, not authorization to start
the gateway, submit to FIFO or compile Fonts.

## November 14 — complete the genuine already committed initialization

The compiler Host has **already** committed and verified this initializer at
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime`, but the old
initializer created only `source`, `companions` and `state`. It omitted
the `package`, `application` and `catalogue` root-level directories
required by `host-deploy.fonts_lane_runtime._SUBDIRS`. Host-deploy correctly
reported `status=partial` and blocked activation. This is **not** a failed
source initialization, an old-Project copy, or permission to reinterpret
`partial` generically.

The **existing** authenticated initialization manifest must remain byte-for-byte
unchanged. The native Work report observed its canonical SHA-256 as
`535c0c283599c8ad3e256d4cdf8db5bb4b16bf1350dfec59de10ebde52d79cb7`.
The corrected initializer now creates all three private (0700) directories
when staging *new* Projects; for the already committed one, a separate
explicit `--complete-layout` command provides idempotent recovery:

```sh
# Work must first install the reviewed corrected host-install wheel in the
# existing trusted compiler maintenance environment, verify RECORD/SHA and
# its selected PATH entrypoint. Do not reuse the older PR38 wheel.
host-install-fonts-project-init --verify
# Verify the original manifest_sha256 and source_tree_sha256 values match
# the retained Work report and no controller file is present.
host-install-fonts-project-init --complete-layout
host-install-fonts-project-init --verify
```

`--complete-layout` reauthenticates the exact source, box-control and
build-record Git revisions and the *original* manifest before writes. It checks
the current process identity, requires each existing runtime directory to be a
private mode-0700 directory and rejects foreign/symlink/incorrect-owner or
nonempty pre-existing directories and any installed controller. It creates only
the **missing** directories through the existing process context and fsyncs
their entries. A subsequent invocation is read-only when all are present.
It does not regenerate checkouts, modify state or manifest, overwrite a
controller, select an account, change accepted compiler evidence or mark the
lane active. On a crash after creating only some directories, repeat
`--verify` and then `--complete-layout` only if the preserved source and
existing directory evidence match exactly.

The resulting verified report contains
`runtime_layout.status=ready`, `layout_complete=true`,
`missing_layout_directories=[]`, `controllers_present=[]`, unchanged
`manifest_sha256`, and the three unchanged source tree identifiers.
host-deploy's reviewed `--prepared-initialize` stage must refuse any other
layout status. It may then proceed through its existing *separate* reviewed
controller installation/activation lifecycle with the generic partial-state
guard intact. In the final controller lifecycle, only host-deploy creates
`controller-inherited-v1.json` after durable intent.

**Native boundary:** the old `--stage`/`--commit` must NOT be repeated on
the existing Project. No manual mkdir, reinitialization, controller JSON edit,
old-account creation, gateway start, SSM submission or compilation is
authorized by this source recovery. The original `kind=image` compiler
generation, signed receipt, schema-4 lane and independently retained October
pin remain unchanged. The real root-control service/socket identity still
needs separately reviewed Work installation and kernel credential acceptance.
