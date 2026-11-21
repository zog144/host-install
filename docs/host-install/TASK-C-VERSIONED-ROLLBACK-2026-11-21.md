# Versioned Task C runtime with protected rollback — source candidate, November 21

This candidate is stacked on host-install PR #46. It does not replace or mutate the
existing installed root venv until reviewed native acceptance. Never stage directly
through the historical in-place `--stage` action when versioned deployment is intended.

## Source selection

- host-install: PR #46 plus this separate draft.
- host-deploy PR #53: `5d7960e55454f88dbc85c3a6ce9c6a972ee31f23`.
- root-control: `b655b0a2b2ba7abb5fddbdaadae01ef6e34bcb56`.
- box-control: `c886e7a90bb4ea74e771a6c5dcefaa2069539ec7`.
- image-build: `77a5e3c13e1c41582b3278941fb4b1f5e2f16678`.

The new versioned installer is a separate opt-in selection, preserving the original
Task C installer for historical readback. No versioned action authorizes Gateway
activation, SSM submission, a Fonts build, replay, or owner-journal mutation.

## Layout and transitions

- The **original unchanged** `/opt/zog/task-c/venv` is retained.
- Preparation creates `/opt/zog/task-c/versions/<release>/venv`, runs ordinary
  five-source pip installation, `pip check`, selected module imports, and the
  exact retained root-control journal Git-blob check.
- Preparation freezes a file-tree SHA-256 and gateway executable SHA-256
  in the release's `preparation.json`; it does not publish a systemd unit.
- Protected rollback custody is under
  `/var/lib/zog-task-c/runtime-rollback`. A locked, root-owned transaction
  saves the original unit bytes as `previous-unit` and verifies a full
  additional copy of the original venv as `original-venv`, while keeping
  the original runtime at its prior path. Missing or foreign protected
  data is a HOLD, never silently replaced.
- On selection, while the Gateway is confirmed inactive, the checked systemd
  unit is generated from the original reviewed unit by replacing exactly its
  `ExecStart` interpreter/entrypoint path with the fixed release path.
  A same-directory, fsynced `os.replace` atomically switches the one
  unit file, followed by systemd daemon-reload and another inactive check.
- On restore, the previous unit SHA-256 must match the retained transaction;
  the currently selected unit must match either the original or selected
  digest. A second atomic `os.replace` restores original unit bytes.
  The original venv and protected copy are retained unchanged.
- A pending transaction after interruption is not automatically replayed
  or overwritten. It may be explicitly restored after an administrator
  checks the record and verifies the service remains inactive. A second
  selection is refused until the protected record is reconciled.

## Entry points

Use the existing `host-install-task-c` program with:

- `--prepare-version RELEASE`, together with the exact five source flags
  and `--python`, to stage *only* an isolated version.
- `--select-version RELEASE` without source flags, to switch an already
  prepared, digest-matching release while inactive.
- `--restore-version` to restore the protected original selection while
  inactive.

No `--stage` request is implied. These are proposed source entry points,
not authorization to run them against the retained Host.

## Native admission still required

Before selecting a live release, Work must independently validate exact
source checkout identities, installed module bytes and complete pip RECORDs,
the prepared release's full file tree, the original Host unit and venv
including symlinks/permissions, protected storage ownership, free space,
and the stopped Gateway. Test normal selection, interruption after writing
the pending record, rollback, daemon-reload failure, reboot readback,
preservation of the original send-once journal and retained requests,
and a non-root compilation child under the selected controller separately.

The source-level fixture tests cover exact unit round-trip, second
selection refusal, missing release, escaping release name, tampering of
both protected unit and prepared executable, and explicit pending recovery.
They are not a substitute for an installed immutable-runtime acceptance.
