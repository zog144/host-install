"""Read-only controller-present original Fonts destination regression tests."""
import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

from test_fonts_project_initialization import setup as init_fixture
from test_fonts_project_initialization import git
from zog.host_install import fonts_project_controller_present_inspect as view
from zog.host_install import fonts_project_initialization as init
from zog.host_install import fonts_project_migration as migration


def prepared(tmp_path, monkeypatch):
    root, checkouts = init_fixture(tmp_path, monkeypatch)
    init.operation("stage", root=root, source_checkouts=checkouts)
    init.operation("commit", root=root)
    project = migration._map(root, migration.NEW)
    manifest = project / init.MANIFEST
    data = json.loads(manifest.read_bytes())
    monkeypatch.setattr(view, "EXPECTED_MANIFEST_SHA256", hashlib.sha256(
        init._canonical(data)).hexdigest())
    controller = project / "controller-inherited-v1.json"
    controller.write_bytes(b'{"schema":"historical-controller","selected":false}\n')
    state = project / "state"
    (state / "retained-identity.json").write_text('{"identity":"unchanged"}')
    source = project / "source"
    (source / "tracked.txt").write_text("new checkout, distinct from original revision")
    git(source, "add", "tracked.txt")
    git(source, "commit", "-qm", "a later, unselected image-build revision")
    with pytest.raises(migration.MigrationHold, match="revision differs"):
        init.operation("verify", root=root)
    return root, project, controller, manifest, state, checkouts


def snapshot(project):
    """Compare bytes, inode and mode including protected Git metadata."""
    observed = {}
    for item in sorted(project.rglob("*")):
        rel = str(item.relative_to(project))
        metadata = item.lstat()
        if item.is_symlink():
            value = ("symlink", os.readlink(item))
        elif item.is_file():
            value = ("file", item.read_bytes())
        else:
            value = ("dir",)
        observed[rel] = (value, metadata.st_ino, stat.S_IMODE(metadata.st_mode))
    return observed


def test_controller_present_mismatch_is_reported_without_claiming_initialization(
        tmp_path, monkeypatch):
    root, project, controller, manifest, state, checkouts = prepared(
        tmp_path, monkeypatch)
    before = snapshot(project)
    result = view.inspect(root=root)
    assert snapshot(project) == before
    assert result["schema"] == view.SCHEMA
    assert result["status"] == "controller-present-unresolved"
    assert result["controller_present"] is True
    assert result["controller_sha256"] == hashlib.sha256(
        controller.read_bytes()).hexdigest()
    assert result["controller"]["inode"] == controller.stat().st_ino
    assert result["manifest_inode"] == manifest.stat().st_ino
    assert result["manifest_sha256"] == view.EXPECTED_MANIFEST_SHA256
    assert result["state"]["inode"] == state.stat().st_ino
    assert result["observed_source"]["revision"] == git(
        project / "source", "rev-parse", "HEAD")
    assert result["source_revision_matches_manifest"] is False
    assert result["source_tree_matches_manifest"] is False
    assert result["historical_source_revision"] == init.SOURCES["source"][1]
    assert result["initialized_controller_authority"] is False
    assert result["historical_writer_authenticated"] is False
    assert result["manifest_replaced"] is False
    assert result["state_modified"] is False
    for name in ("mutation", "ssm_send_authorized", "execution_authorized",
                 "compilation_authorized"):
        assert result[name] is False


def test_inspector_does_not_fall_back_to_mutating_or_controller_free_paths(
        tmp_path, monkeypatch):
    root, project, controller, manifest, state, checkouts = prepared(
        tmp_path, monkeypatch)

    def forbidden(*args, **kwargs):
        pytest.fail("controller-present inspection used a source-mutating path")
    from zog.host_install import fonts_project_source_restore
    from zog.host_install import fonts_project_source_reconciliation
    monkeypatch.setattr(init, "_verify", forbidden)
    monkeypatch.setattr(init, "_complete_layout", forbidden)
    monkeypatch.setattr(fonts_project_source_restore, "restore", forbidden)
    monkeypatch.setattr(fonts_project_source_reconciliation, "plan", forbidden)
    prior = snapshot(project)
    assert view.inspect(root=root)["status"] == "controller-present-unresolved"
    assert prior == snapshot(project)


@pytest.mark.parametrize("damage", [
    "missing-controller", "symlink-controller", "foreign-controller-content",
    "duplicate-controller-json", "writable-controller", "hardlinked-controller",
    "changed-manifest", "noncanonical-manifest", "missing-state",
    "symlink-state", "foreign-root-entry", "extra-controller",
    "symlink-source", "symlink-git", "foreign-git-origin",
])
def test_inspector_rejects_foreign_controller_manifest_state_or_source(
        tmp_path, monkeypatch, damage):
    root, project, controller, manifest, state, checkouts = prepared(
        tmp_path, monkeypatch)
    if damage == "missing-controller":
        controller.unlink()
    elif damage == "symlink-controller":
        backup = controller.with_suffix(".bak")
        controller.rename(backup)
        controller.symlink_to(backup)
    elif damage == "foreign-controller-content":
        controller.write_bytes(b"not-json")
    elif damage == "duplicate-controller-json":
        controller.write_bytes(b'{"schema":1,"schema":2}')
    elif damage == "writable-controller":
        controller.chmod(0o666)
    elif damage == "hardlinked-controller":
        os.link(controller, root / "linked-controller.json")
    elif damage == "changed-manifest":
        manifest.write_text(manifest.read_text().replace(
            '"controller_installed":false', '"controller_installed":true'))
    elif damage == "noncanonical-manifest":
        manifest.write_text(json.dumps(json.loads(manifest.read_bytes()),
                                       indent=2))
    elif damage == "missing-state":
        state.rename(project / "old-state")
    elif damage == "symlink-state":
        state.rename(project / "old-state")
        state.symlink_to(project / "old-state")
    elif damage == "foreign-root-entry":
        (project / "unexpected.json").write_text("{}")
    elif damage == "extra-controller":
        (project / "controller.json").write_text("{}")
    elif damage == "symlink-source":
        source = project / "source"
        source.rename(project / "unselected-source")
        source.symlink_to(project / "unselected-source")
    elif damage == "symlink-git":
        git_dir = project / "source/.git"
        git_dir.rename(project / "source/git-original")
        git_dir.symlink_to("git-original")
    else:
        git(project / "source", "remote", "set-url", "origin",
            "https://github.com/foreign/project.git")
    original = snapshot(project)
    with pytest.raises((view.InspectionHold, OSError)):
        view.inspect(root=root)
    assert snapshot(project) == original


def test_companion_mismatch_is_diagnostic_and_never_authorizing(
        tmp_path, monkeypatch):
    root, project, controller, manifest, state, checkouts = prepared(
        tmp_path, monkeypatch)
    companion = project / "companions/box-control"
    (companion / "tracked.txt").write_text("different companion revision")
    git(companion, "add", "tracked.txt")
    git(companion, "commit", "-qm", "changed companion")
    original = snapshot(project)
    result = view.inspect(root=root)
    assert result["companions"]["companions/box-control"][
        "revision_matches_manifest"] is False
    assert result["companions"]["companions/box-control"][
        "tree_matches_manifest"] is False
    assert result["compilation_authorized"] is False
    assert result["historical_writer_authenticated"] is False
    assert snapshot(project) == original


def test_read_only_cli_exposes_no_destination_or_uid_overrides(
        tmp_path, monkeypatch, capsys):
    root, project, controller, manifest, state, checkouts = prepared(
        tmp_path, monkeypatch)
    before = snapshot(project)
    real_inspect = view.inspect
    monkeypatch.setattr(view, "inspect", lambda: real_inspect(root=root))
    assert view.main(["--inspect"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "controller-present-unresolved"
    with pytest.raises(SystemExit):
        view.main(["--inspect", "--root", str(root)])
    with pytest.raises(SystemExit):
        view.main(["--inspect", "--uid", "24201"])
    assert snapshot(project) == before
