"""Source and installed-package test: one host-install supports both operations."""
import importlib.metadata as metadata
import inspect
from pathlib import Path

from zog.host_install import task_c_local_install as task_c
from zog.host_install import fonts_project_migration as fonts


def test_one_checkout_contains_both_capabilities():
    assert callable(task_c.stage) and callable(task_c.source_plan)
    assert callable(fonts.operation) and callable(fonts.main)
    assert task_c.SCHEMA
    assert fonts.NEW == "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
    assert Path(inspect.getfile(task_c)).parents[0] == Path(inspect.getfile(fonts)).parents[0]
    assert task_c.os.geteuid is fonts.os.geteuid


def test_distribution_installs_both_commands_from_one_wheel():
    ep={item.name: item.value
        for item in metadata.distribution("host-install").entry_points
        if item.group == "console_scripts"}
    assert ep["host-install-task-c"] == "zog.host_install.task_c_local_install:main"
    assert ep["host-install-fonts-project-migrate"] == "zog.host_install.fonts_project_migration:main"
    assert ep["host-install-fonts-source-reconcile"] == (
        "zog.host_install.fonts_project_source_reconcile_cli:main")


# Keep the historical first-Fonts initializer intact. These regressions exercise
# an explicit, independent recovery, never an overwrite of its recorded manifest.
import json
import pytest

from zog.host_install import fonts_project_initialization as prepared
from zog.host_install import fonts_project_source_reconciliation as reconcile
from zog.host_install import fonts_project_source_restore as recovery


def _divergent_prepared(tmp_path, monkeypatch):
    import test_fonts_project_initialization as fixtures

    root, checkouts = fixtures.setup(tmp_path, monkeypatch)
    prepared.operation("stage", root=root, source_checkouts=checkouts)
    prepared.operation("commit", root=root)
    project = fonts._map(root, fonts.NEW)
    manifest = (project / prepared.MANIFEST).read_bytes()
    state = project / "state"
    (state / "retained-result").write_bytes(b"historical state must survive")
    inode = state.stat().st_ino
    worktree = project / "source"
    (worktree / "tracked.txt").write_text("newer, clean, but not approved")
    fixtures.git(worktree, "add", "tracked.txt")
    fixtures.git(worktree, "commit", "-qm", "new unselected producer revision")
    with pytest.raises(fonts.MigrationHold, match="revision differs"):
        prepared.operation("verify", root=root)
    return root, checkouts, project, manifest, inode


def test_plan_and_restore_exact_manifest_source_preserves_state_and_history(
        tmp_path, monkeypatch):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    old_revision = reconcile.source(project / "source")["revision"]
    original_receipt = (project / prepared.MANIFEST).stat().st_ino
    plan = reconcile.plan(root, checkouts["source"])
    assert plan["observed_source"]["revision"] == old_revision
    assert plan["replacement_source"]["revision"] == prepared.SOURCES["source"][1]
    assert not fonts._map(root, reconcile.RECEIPT).exists()
    answer = recovery.restore(
        root=root, reviewed_checkout=checkouts["source"],
        expected_plan_sha256=plan["plan_sha256"])
    assert answer["restored_source_verified"] is True
    assert answer["compilation_authorized"] is False
    assert prepared.operation("verify", root=root)["manifest_sha256"] == (
        plan["manifest_sha256"])
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert (project / prepared.MANIFEST).stat().st_ino == original_receipt
    assert (project / "state").stat().st_ino == inode
    assert (project / "state/retained-result").read_bytes() == (
        b"historical state must survive")
    displaced = fonts._map(root, reconcile.PENDING)
    assert reconcile.source(displaced)["revision"] == old_revision
    assert fonts._map(root, reconcile.RECEIPT).is_file()
    with pytest.raises(fonts.MigrationHold, match="already matches"):
        reconcile.plan(root, checkouts["source"])


def test_reconciliation_requires_independently_pinned_current_plan(
        tmp_path, monkeypatch):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    with pytest.raises(fonts.MigrationHold, match="plan differs"):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256="f" * 64)
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert not fonts._map(root, reconcile.PENDING).exists()


def test_recovery_resumes_only_matching_receipt_and_complete_staging(
        tmp_path, monkeypatch):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    plan = reconcile.plan(root, checkouts["source"])
    actual = recovery._exchange

    def stop_before_swap(*args):
        raise KeyboardInterrupt("source exchange deliberately interrupted")

    monkeypatch.setattr(recovery, "_exchange", stop_before_swap)
    with pytest.raises(KeyboardInterrupt, match="deliberately interrupted"):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256=plan["plan_sha256"])
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert fonts._map(root, reconcile.RECEIPT).is_file()
    assert fonts._map(root, reconcile.PENDING).is_dir()
    monkeypatch.setattr(recovery, "_exchange", actual)
    answer = recovery.restore(
        root=root, reviewed_checkout=checkouts["source"],
        expected_plan_sha256=plan["plan_sha256"])
    assert answer["restored_source_verified"]
    assert prepared.operation("verify", root=root)["initialized_source_verified"]


@pytest.mark.parametrize("foreign", [
    "dirty-current", "unknown-root-entry", "linked-state", "changed-source-approval",
    "controller-present", "nonempty-package",
])
def test_source_reconciliation_refuses_foreign_project_or_source(
        tmp_path, monkeypatch, foreign):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    if foreign == "dirty-current":
        (project / "source/untracked").write_bytes(b"foreign")
    elif foreign == "unknown-root-entry":
        (project / "foreign-dir").mkdir()
    elif foreign == "linked-state":
        state = project / "state"
        state.rename(project / "retained-state")
        state.symlink_to(project / "retained-state")
    elif foreign == "changed-source-approval":
        import test_fonts_project_initialization as fixtures
        checkout = checkouts["source"]
        (checkout / "tracked.txt").write_text("different approved candidate")
        fixtures.git(checkout, "add", "tracked.txt")
        fixtures.git(checkout, "commit", "-qm", "not manifest-selected")
    elif foreign == "controller-present":
        (project / "controller.json").write_bytes(b"{}")
    else:
        (project / "package/artifact").write_bytes(b"foreign")
    with pytest.raises(fonts.MigrationHold):
        reconcile.plan(root, checkouts["source"])
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert not fonts._map(root, reconcile.RECEIPT).exists()


def test_unknown_prepared_source_recovery_staging_is_not_adopted(
        tmp_path, monkeypatch):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    plan = reconcile.plan(root, checkouts["source"])
    pending = fonts._map(root, reconcile.PENDING)
    pending.symlink_to(checkouts["source"])
    with pytest.raises(fonts.MigrationHold, match="unknown partial"):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256=plan["plan_sha256"])
    assert pending.is_symlink()
    assert not fonts._map(root, reconcile.RECEIPT).exists()
    assert (project / prepared.MANIFEST).read_bytes() == manifest


def test_recovery_rejects_tampered_content_addressed_staging_receipt(
        tmp_path, monkeypatch):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    plan = reconcile.plan(root, checkouts["source"])
    actual = recovery._exchange
    monkeypatch.setattr(recovery, "_exchange",
                        lambda *args: (_ for _ in ()).throw(
                            KeyboardInterrupt("interrupt after durable receipt")))
    with pytest.raises(KeyboardInterrupt):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256=plan["plan_sha256"])
    monkeypatch.setattr(recovery, "_exchange", actual)
    retained = fonts._map(root, reconcile.RECEIPT)
    retained.write_bytes(b"foreign receipt")
    with pytest.raises(fonts.MigrationHold, match="receipt/staging differs"):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256=plan["plan_sha256"])
    assert retained.read_bytes() == b"foreign receipt"
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert (project / "state").stat().st_ino == inode


def test_interrupted_after_atomic_swap_is_read_only_verifiable(
        tmp_path, monkeypatch):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    plan = reconcile.plan(root, checkouts["source"])
    original_verify = prepared._verify
    monkeypatch.setattr(prepared, "_verify",
                        lambda *args, **kwargs: (_ for _ in ()).throw(
                            KeyboardInterrupt("interrupt after atomic swap")))
    with pytest.raises(KeyboardInterrupt):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256=plan["plan_sha256"])
    monkeypatch.setattr(prepared, "_verify", original_verify)
    assert prepared.operation("verify", root=root)["initialized_source_verified"]
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert (project / "state").stat().st_ino == inode
    assert fonts._map(root, reconcile.RECEIPT).is_file()
    assert reconcile.source(fonts._map(root, reconcile.PENDING))[
        "revision"] == plan["observed_source"]["revision"]
    with pytest.raises(fonts.MigrationHold, match="already matches"):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256=plan["plan_sha256"])


def _ignore_payload(checkout):
    """Git status ignores this payload even with --untracked-files=all."""
    import test_fonts_project_initialization as fixture_git
    with (checkout / ".git/info/exclude").open("a") as output:
        output.write("\n*.unreviewed\n")
    assert not fixture_git.git(checkout, "status", "--porcelain=v1",
                               "--untracked-files=all")


@pytest.mark.parametrize("location", ["reviewed", "selected"])
def test_ignored_worktree_payload_rejected_before_approval(tmp_path, monkeypatch, location):
    import test_fonts_project_initialization as fixture_git
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    tree = (checkouts["source"] if location == "reviewed"
            else project / "source")
    _ignore_payload(tree)
    (tree / "attacker.unreviewed").write_text("disallowed ignored payload")
    assert fixture_git.git(tree, "status", "--porcelain=v1",
                           "--untracked-files=all") == ""
    with pytest.raises(fonts.MigrationHold, match="Git-ignored"):
        reconcile.plan(root, checkouts["source"])
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert not fonts._map(root, reconcile.RECEIPT).exists()


def test_ignored_payload_added_after_approval_refuses_restore(tmp_path, monkeypatch):
    import test_fonts_project_initialization as fixture_git
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    checkout = checkouts["source"]
    _ignore_payload(checkout)
    approved = reconcile.plan(root, checkout)
    (checkout / "unreviewed.unreviewed").write_text("added after plan")
    assert fixture_git.git(checkout, "status", "--porcelain=v1",
                           "--untracked-files=all") == ""
    with pytest.raises(fonts.MigrationHold, match="Git-ignored"):
        recovery.restore(root=root, reviewed_checkout=checkout,
                         expected_plan_sha256=approved["plan_sha256"])
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert not fonts._map(root, reconcile.RECEIPT).exists()


def test_receipt_backed_staging_rejects_later_git_ignored_payload(tmp_path, monkeypatch):
    import test_fonts_project_initialization as fixture_git
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    checkout = checkouts["source"]
    _ignore_payload(checkout)
    approved = reconcile.plan(root, checkout)
    actual = recovery._exchange
    monkeypatch.setattr(recovery, "_exchange",
                        lambda *args: (_ for _ in ()).throw(
                            KeyboardInterrupt("durable receipt published")))
    with pytest.raises(KeyboardInterrupt):
        recovery.restore(root=root, reviewed_checkout=checkout,
                         expected_plan_sha256=approved["plan_sha256"])
    monkeypatch.setattr(recovery, "_exchange", actual)
    pending = fonts._map(root, reconcile.PENDING)
    (pending / "late.unreviewed").write_bytes(b"no post-approval injection")
    assert fixture_git.git(pending, "status", "--porcelain=v1",
                           "--untracked-files=all") == ""
    with pytest.raises(fonts.MigrationHold, match="Git-ignored"):
        recovery.restore(root=root, reviewed_checkout=checkout,
                         expected_plan_sha256=approved["plan_sha256"])
    assert fonts._map(root, reconcile.RECEIPT).is_file()
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert (project / "state").stat().st_ino == inode


def test_git_metadata_mutated_after_approval_changes_plan(tmp_path, monkeypatch):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    approved = reconcile.plan(root, checkouts["source"])
    (checkouts["source"] / ".git/description").write_text("changed after approval")
    observed = reconcile.plan(root, checkouts["source"])
    assert observed["replacement_source"]["tree_sha256"] == (
        approved["replacement_source"]["tree_sha256"])
    assert observed["replacement_source"]["physical_tree_sha256"] != (
        approved["replacement_source"]["physical_tree_sha256"])
    with pytest.raises(fonts.MigrationHold, match="plan differs"):
        recovery.restore(root=root, reviewed_checkout=checkouts["source"],
                         expected_plan_sha256=approved["plan_sha256"])
    assert (project / prepared.MANIFEST).read_bytes() == manifest


def _crash_after_recovery_swap(root, checkout, monkeypatch):
    plan = reconcile.plan(root, checkout)
    original_verify = prepared._verify
    monkeypatch.setattr(prepared, "_verify",
                        lambda *args, **kwargs: (_ for _ in ()).throw(
                            KeyboardInterrupt("after source exchange")))
    with pytest.raises(KeyboardInterrupt):
        recovery.restore(root=root, reviewed_checkout=checkout,
                         expected_plan_sha256=plan["plan_sha256"])
    monkeypatch.setattr(prepared, "_verify", original_verify)
    return plan


def _cli_read_only_verify(root, plan_sha, monkeypatch, capsys):
    from zog.host_install import fonts_project_source_reconcile_cli as cli
    real_path = Path
    monkeypatch.setattr(cli, "Path",
                        lambda value: root if value == "/" else real_path(value))
    assert cli.main(["--verify-recovery", "--expected-plan-sha256",
                     plan_sha]) == 0
    return json.loads(capsys.readouterr().out)


def test_real_cli_verifies_retained_receipt_and_both_sources_after_crash(
        tmp_path, monkeypatch, capsys):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    old_manifest_inode = (project / prepared.MANIFEST).stat().st_ino
    plan = _crash_after_recovery_swap(root, checkouts["source"], monkeypatch)
    proof = _cli_read_only_verify(root, plan["plan_sha256"], monkeypatch, capsys)
    assert proof["action"] == "verify-recovery"
    assert proof["recovered_source_verified"] is True
    assert proof["displaced_source_verified"] is True
    assert proof["receipt_verified"] is True
    assert proof["state_inode_preserved"] is True
    assert proof["mutation"] is False
    assert proof["compilation_authorized"] is False
    assert (project / prepared.MANIFEST).read_bytes() == manifest
    assert (project / prepared.MANIFEST).stat().st_ino == old_manifest_inode
    assert (project / "state").stat().st_ino == inode
    with pytest.raises(fonts.MigrationHold, match="already matches"):
        reconcile.plan(root, checkouts["source"])


@pytest.mark.parametrize("damage", [
    "receipt", "displaced-tracked", "displaced-ignored", "restored-ignored",
    "state-inode", "manifest",
])
def test_actual_cli_recovery_verifier_fails_closed_on_history_tampering(
        tmp_path, monkeypatch, capsys, damage):
    root, checkouts, project, manifest, inode = _divergent_prepared(
        tmp_path, monkeypatch)
    plan = _crash_after_recovery_swap(root, checkouts["source"], monkeypatch)
    pending = fonts._map(root, reconcile.PENDING)
    receipt = fonts._map(root, reconcile.RECEIPT)
    if damage == "receipt":
        receipt.write_bytes(b"{}\\n")
    elif damage == "displaced-tracked":
        (pending / "tracked.txt").write_text("forged history")
    elif damage == "displaced-ignored":
        _ignore_payload(pending)
        (pending / "hidden.unreviewed").write_text("forged history")
    elif damage == "restored-ignored":
        _ignore_payload(project / "source")
        (project / "source/hidden.unreviewed").write_text("forged replacement")
    elif damage == "state-inode":
        state = project / "state"
        state.rename(project / "state-before-replace")
        state.mkdir(mode=0o700)
    else:
        (project / prepared.MANIFEST).write_text("{}\\n")
    with pytest.raises((fonts.MigrationHold, ValueError)):
        _cli_read_only_verify(root, plan["plan_sha256"], monkeypatch, capsys)
    assert receipt.exists()
