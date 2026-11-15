# Existing image-build Project: source-verified, layout-only completion

**host-install Regular · 2026-11-15 · source-only**. This is *not* the
first-Fonts initializer, the historical private-home-to-app-data migrator,
a Project creation, or a catalogue compiler-origin selection.

The November 15 read-only compiler-Host inventory established that the
original accepted compiler receipt identifies:

- Project: `/home/certbot-build-owner/certbot-seed`.
- Compiler generation: `3805294fc8ccd9589aa75d3a6c5cb9367b7baf84b6ce131a84adafed7d34f9dc`;
  kind `image`; accepted receipt
  `a205c07bde4e6cf61e48061affd9a0b40c3a101e18dff67a9871995a3a2afafc`.
- Five retained generation directories, multiple derivation records, prior
  build jobs/resources, source provenance and accepted outputs.

The newer, **already active** Fonts Project at
`/var/lib/zog/image-build/projects/gateway-first-fonts-runtime` is a
different Project and remains untouched. The native report did **not**
establish a single latest usable rootfs or a compatible same-Project
origin/execution lane. **Neither a generation ID nor directory mtime is a
selection criterion.** The existing controller source owner must select
and authenticate generation/derivation/receipt separately.

## Explicit existing-Project command

`host-install-existing-project-layout --inspect|--complete-layout|--verify`

This is included in the same host-install wheel as the normal Task C and Fonts
initialization/copy-migration commands. It is a **different** explicit
operation that never creates or replaces the Project and does not require
the host-install first-initialization manifest. Its only possible mutations
are creation of missing top-level `package`, `application`, `catalogue`
and `state` directories. It makes no new controller, source checkout,
Git commit, journal, old-Project migration receipt or build attempt.

The caller must explicitly select all of these using **facts reviewed outside
this command**:
- Original existing Project's absolute canonical root, including its private
  home (not a guessed newest directory).
- Existing, independent image-build Git checkout **relative** to that root.
  The checkout must already exist. Nothing will be cloned or copied.
- Exact reviewed `zog144/image-build` Git commit ID **and** tree object ID.
  The actual `HEAD`, tree, repository remote, tracked worktree/index and
  Git refs are independently inspected. An untracked file is *not* approved
  source and is never touched.
- For completion, device and inode returned by the **read-only** inspection.
  The command refuses substitutions between selection and mutation.

The existing Project must be a real directory, not a link, under a reviewed
local Project-storage root (`/home/`, `/var/lib/zog/image-build/` or
`/var/lib/zog/image-build-lanes/`). Every ancestor is checked for symlinks;
the Project must be accessible and not group/world-writable. Existing
`package`, `application`, `catalogue` and `state` must be real
directories, owned by the observed Project owner/group, owner-accessible
and not group/world writable. They **may contain retained files**; their
contents are not rewritten or removed. Other pre-existing Project entries
(including controller configuration, Git, manifests and generations) remain
untouched. Unexpected symlink, file, owner, source revision, worktree or
target inode causes HOLD before any mkdir.

Completion uses the existing process identity without `su`, `runuser`,
sudo-to-another-user, account provisioning or a numeric execution UID/GID.
If root already performs the installer, only new directories are assigned
the **observed existing Project owner/group** with `fchown`; no original
object is chowned. A non-root installer must already be the Project's
effective owner/group. Every created directory is private mode 0700 and
fsynced, along with its Project parent. Root directory `flock` serializes
this installer without adding any lock file. The operation observes the
existing top-level metadata and Git HEAD/tree/refs before and after; it
refuses changes to anything other than the requested missing directories.
Read-only `--verify` and repeat completion are supported after an
interrupted creation. No pre-existing directory is chmodded or emptied.

## Native Work procedure — no Host mutation from source task

1. Quiesce any potentially conflicting compiler operation. Read the existing
   approved compiler receipt and inspect its Project claim. Identify the
   *actual current* Git checkout under this Project, its selected origin and
   independently approved revision/tree. **Do not** infer source from any
   generation timestamp, unrelated new Fonts checkout, or the record's
   mere presence.
2. Select exact installed host-install source and package wheel bytes from
   this reviewed PR. Inspect before any mutation. For example:

```sh
PROJECT=/home/certbot-build-owner/certbot-seed
# Operator reviews the actual repo location and source selection.
SOURCE_REL=source
APPROVED_COMMIT=<full-reviewed-source-git-commit>
APPROVED_TREE=<full-reviewed-source-git-tree>
host-install-existing-project-layout --inspect \
  --project-root "$PROJECT" \
  --source-relative "$SOURCE_REL" \
  --expected-source-revision "$APPROVED_COMMIT" \
  --expected-source-tree "$APPROVED_TREE"
```

3. Record exact selected `project_identity.device`, `inode`, owner/group
   and mode, observed `source.revision`, `source.tree`,
   `source.refs_sha256`, present and missing top-level layout, and metadata
   observation. Review any existing nonempty directories and ensure no
   conflicting build process is touching this Project.
4. Only if a concrete missing layout is independently approved, run
   **the same command under the already authorized process identity** with
   `--complete-layout` replacing `--inspect`, and add
   `--expected-project-device <inspected-device>` and
   `--expected-project-inode <inspected-inode>`. The command uses the
   inspected owner IDs, not an account selector. Then run read-only
   `--verify` using the same arguments and require complete layout,
   unchanged source and existing-entry metadata, and only the explicitly
   reported `created_directories`. On uncertain SSM acknowledgement,
   read back the original command and inspect before any retry.
5. **Separately**, have image-build + host-deploy verify the retained
   accepted-generation manifest and origin-lane compatibility, decide the
   intended usable rootfs through authenticated derivation/selection
   records, and establish any same-Project origin/execution compatibility
   required by box-control/root-control. This directory operation is
   **not** proof that the retained compiler image is the chosen latest
   rootfs; it does not edit the accepted origin, current Fonts lane,
   October pin, signed receipt or protected catalogue.

### Source tests

`tests/test_existing_project_layout.py` uses a disposable real Git
repository with two commits, a tag, preserved Git history, a retained
generation manifest, derivation, controller configuration, a binary pin,
symbolic link and nonempty application state. It verifies that creation
changes only missing top-level directories. Negative tests reject changed
Git/tree/origin, dirty tracked files, wrong root inode, symlink/foreign
layout, permission drift and replacement of an existing Project. Crash
recovery leaves a first successful mkdir intact and creates only remaining
directories on the next explicitly selected completion. The combined
wheel still contains Task C, first-Fonts initialization and copy migration.

**Outcome:** source-supported explicit existing-Project layout completion;
no selected latest rootfs, catalogue installation, new Project, account
creation/deletion, live Host write, SSM, compilation or gateway activation.
