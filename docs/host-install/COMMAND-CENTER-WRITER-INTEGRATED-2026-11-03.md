# Command-Center protected writer: integrated source candidate (2026-11-03)

**Disposition:** source-only, draft, no authority installation or STATE mutation. The only proposed combined descendant is [host-install PR #20](https://github.com/zog144/host-install/pull/20), stacked on [PR #18](https://github.com/zog144/host-install/pull/18) (exact original writer-lock head `19ad364313dca2dee79e39ad247dd9a784b3dc23`) and ultimately [PR #8](https://github.com/zog144/host-install/pull/8) (`5f7d690933a6354087eebde60d3d79212ef979bf`). [PR #19](https://github.com/zog144/host-install/pull/19) at `e6341e37cd8209998986bf89effc97f865f1d266` provided the *staged-child entry checks* but diverged from the latest PR #18 source because it was based on the earlier `52952406…` commit. PR #19 is historical correction provenance, **not** an alternative acceptable standalone final head.

## Actual composition

The integrated branch **starts from the exact final PR #18 source**. It keeps the original lock+marker provisioning and the existing root-directory flock then original lock-inode flock; selected root pathname `lstat` device/inode checks; original lock and marker inode, owner, mode and link checks; no automatic bootstrap/adoption of lost original identity; and the no-replacement material/receipt state machine. Both `stage_offline` and `inspect_offline` provide the exact configured offline root pathname to the guard.

From PR #19 it adds `_assert_original_child(root_fd,child_fd)` comparing the opened protected staged-child device/inode to the parent directory's *current named child*. The guard is invoked before and after each material publication, hard-link/rename checkpoint, receipt, `fsync`, and finally before the stage returns. Protected **inspection** additionally checks the original child before and after *each raw material read*, after final receipt verification, and before returning a retained-authority status.

The initial root directory and its original lock+marker must still be separately provisioned by a duly authorized native owner. The source test helper simulates this under ephemeral temporary directories only. It neither names a production alternative lock, rewrites a lost marker, repairs conflicting receipt bytes, creates STATE, nor authorizes staged private keys to become live.

## Negative and recovery matrix

- Original lock missing, renamed, hard-linked, symlinked or recreated: HOLD, never adopt a new inode.
- Marker missing after initial provisioning, first-bootstrap interruption, re-created **with identical JSON bytes** during stage or inspection, hardlinked or replaced: HOLD.
- Offline root directory renamed or replaced, including by renaming its parent while the original root flock is held: HOLD, never report success through detached original fd.
- Staged authority directory unlinked, renamed and replaced during material publication or inspection: HOLD, never issue a final accepted receipt for a new name while reading the detached child fd.
- Crash after a durable material link but before final receipt, followed by a **same-byte retry with unchanged original directory/lock/marker**: preserve inode and resume; incomplete, early or corrupted receipt: HOLD, never replace.
- Root-owned synthetic actual stage/readback checks still bind the expected protected station database identity, roles and signed materials; they are not a native AWS identity or operator-pin attestation.

Source CI is [integrated protected writer workflow](https://github.com/zog144/host-install/actions/workflows/command-center-writer-integrated-source.yml) for Python 3.12 and 3.13, running both unprivileged original writer-lock tests and ephemeral **root-owned** publication, inspection and interruption tests. Any changes require rechecking the **exact** PR #20 head; historical green runs on PRs #18 or #19 cannot stand in for the combined head.

## Remaining authorization and security limits

This source evidence is not an independent human security signoff or rights permission. A malicious privileged writer that bypasses these functions, filesystem rollback, races replacing the entire trusted mount outside the configured path, physical disk or mount identity, reboot persistence, original root/marker custody, source-to-installed wheel attestation, real signer provenance, AWS IID, root grant, operator approval, and genuine STATION/STATE identity still require separately authorized verification. Real Credential Authority / certificate assignment / administrator-password delivery remains disabled; no production companion repin.


## Independent follow-up: complete path and original permissions

An additional source review of the consolidated PR #20 found two cases where checking only the final leaf inode was insufficient:

1. The protected *ancestor directory* might be renamed, then replaced at the configured pathname by a symlink back to the original directory. The selected offline root would still have the same `st_dev` and `st_ino`, and the original lock would still be held, but the configured parent entry would no longer be the original protected path. The writer now pins the device/inode identities of **every original parent component** and rejects a changed or symlinked ancestor at each guard invocation. The configured leaf identity and existing separately checked DAC remain required. A regression deliberately gives the same root two paths through such an alias and verifies that protected staging and inspection cannot return success after the alias is substituted.
2. The root-only **staged child directory** could change ownership, group or mode to become less restrictive while preserving its inode. The previous child-name check rejected renamed children but did not continuously recheck the original `root:root 0700` protection during material and receipt operations. The child guard now enforces its original owner/group/mode and same-device constraint at every staging and inspection readback checkpoint. New tests relax the child to 0755 during the protected material link and during an inspection read and require a hard failure before accepting the receipt.

These are fail-closed source checks, not a guarantee against arbitrary activity by an already malicious privileged process between checkpoints, rollback of protected storage, inode reuse across host restarts or mount namespace substitution. The tests still use temporary synthetic roots and do not open a native Command-Center installation.

## One source-selection rule

**Select PR #20 as the only integrated protected writer source candidate.** Its parent is the final PR #18 original-lock candidate, with original host-install PR #8 beneath that; **PR #19 is a superseded and closed divergent ancestor candidate, not an acceptable installation source or production pin**. The source workflow verifies the exact current checkout, both original ancestor commits, the non-ancestry of the superseded PR #19 head, unchanged generic `state_io.py` and packaging, and this explicit source-selection statement.

This does not repin an accepted station-access production companion or replace any currently staged Work venv. The independent protected installation owner must still approve the *specific installed bytes* and exact original offline directory/lock/marker identities before any native authority operation.
