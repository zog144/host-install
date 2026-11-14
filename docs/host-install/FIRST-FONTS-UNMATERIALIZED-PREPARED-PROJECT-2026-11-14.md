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
