"""Source-owned initialization of a prepared, never-materialized Fonts Project."""
import json
import os
from pathlib import Path
import subprocess

import pytest

from zog.host_install import fonts_project_initialization as init
from zog.host_install import fonts_project_migration as copy


def git(directory, *args):
    run = subprocess.run(["git", "-C", str(directory), *args], check=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return run.stdout.strip()


def setup(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "var/lib").mkdir(parents=True)
    repos = {}
    refs = {}
    for idx, name in enumerate(init.SOURCES):
        repository = "zog144/" + ("image-build" if name == "source" else
                                    "box-control" if "box-control" in name else "build-record")
        path = tmp_path / ("checkout" + str(idx))
        path.mkdir()
        subprocess.run(["git", "init", "-q", str(path)], check=True)
        git(path, "config", "user.email", "fixture@example.org")
        git(path, "config", "user.name", "Fixture")
        git(path, "remote", "add", "origin", "https://github.com/" + repository + ".git")
        (path / "tracked.txt").write_text("source-" + str(idx))
        git(path, "add", "tracked.txt")
        git(path, "commit", "-qm", "fixture")
        revision = git(path, "rev-parse", "HEAD")
        refs[name] = (repository, revision)
        repos[name] = path
    monkeypatch.setattr(init, "SOURCES", refs)
    return root, repos


def test_initialization_from_real_checkouts_with_no_historical_project(tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    stage = init.operation("stage", root=root, source_checkouts=repos)
    assert stage["schema"] == init.SCHEMA
    assert stage["copy_performed"] is False
    assert stage["historical_project_materialized"] is False
    assert stage["initialized_source_verified"] is True
    assert not copy._map(root, copy.OLD).exists()
    assert not copy._map(root, copy.NEW).exists()
    assert (copy._map(root, init.PENDING) / "source/.git").is_dir()
    assert not (copy._map(root, init.PENDING) / "controller.json").exists()
    assert not (copy._map(root, init.PENDING) / "controller-inherited-v1.json").exists()
    result = init.operation("commit", root=root)
    assert result["initialized_source_verified"] is True
    assert init.operation("verify", root=root)["manifest_sha256"] == result["manifest_sha256"]
    assert (copy._map(root, copy.NEW) / "source/tracked.txt").read_text() == "source-0"
    assert not copy._map(root, copy.OLD).exists()
    assert not copy._map(root, copy.PENDING).exists()
    assert not (copy._map(root, copy.NEW) / "controller.json").exists()
    assert not (copy._map(root, copy.NEW) / "controller-inherited-v1.json").exists()


def test_absent_existing_or_half_finished_projects_must_not_be_replaced(tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    old = copy._map(root, copy.OLD)
    old.parent.mkdir(parents=True)
    old.mkdir()
    with pytest.raises(copy.MigrationHold, match="historical Project exists"):
        init.operation("stage", root=root, source_checkouts=repos)
    old.rmdir()
    init.operation("stage", root=root, source_checkouts=repos)
    with pytest.raises(copy.MigrationHold, match="initialization already present"):
        init.operation("stage", root=root, source_checkouts=repos)
    init.operation("commit", root=root)
    with pytest.raises(copy.MigrationHold, match="already exists"):
        init.operation("commit", root=root)


def test_foreign_revision_and_modified_checkout_fail_before_project_creation(tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    (repos["source"] / "untracked").write_text("injected")
    with pytest.raises(copy.MigrationHold, match="has modifications"):
        init.operation("stage", root=root, source_checkouts=repos)
    assert not copy._map(root, init.PENDING).exists()
    (repos["source"] / "untracked").unlink()
    refs = dict(init.SOURCES)
    repo, _ = refs["source"]
    refs["source"] = (repo, "0" * 40)
    monkeypatch.setattr(init, "SOURCES", refs)
    with pytest.raises(copy.MigrationHold, match="revision differs"):
        init.operation("stage", root=root, source_checkouts=repos)
    assert not copy._map(root, init.PENDING).exists()


def test_tampered_staged_source_and_manifest_fail_closed(tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    init.operation("stage", root=root, source_checkouts=repos)
    pending = copy._map(root, init.PENDING)
    (pending / "source/tracked.txt").write_text("corrupt")
    with pytest.raises(copy.MigrationHold):
        init.operation("commit", root=root)
    assert not copy._map(root, copy.NEW).exists()


def test_initialization_refuses_symlink_destination(tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    copy._prepare_parent(root)
    target = copy._map(root, copy.NEW)
    target.symlink_to(tmp_path / "other")
    with pytest.raises(copy.MigrationHold, match="already present"):
        init.operation("stage", root=root, source_checkouts=repos)
    assert target.is_symlink()


def test_initializer_prepares_all_runtime_controller_directories(tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    staged = init.operation("stage", root=root, source_checkouts=repos)
    assert staged["layout_complete"] is True
    assert staged["missing_layout_directories"] == []
    pending = copy._map(root, init.PENDING)
    for name in init.LAYOUT_DIRECTORIES:
        item = pending / name
        assert item.is_dir() and not item.is_symlink()
        assert item.stat().st_mode & 0o777 == 0o755
        assert list(item.iterdir()) == []
    committed = init.operation("commit", root=root)
    assert committed["layout_complete"] is True
    assert init.operation("verify", root=root)["layout_complete"] is True


def test_repair_already_committed_verified_native_project_without_changing_manifest(
        tmp_path, monkeypatch):
    """Reproduce actual native case: committed source/state but three absent."""
    import hashlib
    root, repos = setup(tmp_path, monkeypatch)
    init.operation("stage", root=root, source_checkouts=repos)
    init.operation("commit", root=root)
    project = copy._map(root, copy.NEW)
    for name in init.LAYOUT_DIRECTORIES:
        (project / name).rmdir()
    manifest = project / init.MANIFEST
    original = manifest.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    before = init.operation("verify", root=root)
    assert before["layout_complete"] is False
    assert before["missing_layout_directories"] == list(init.LAYOUT_DIRECTORIES)
    assert before["controller_installed"] is False
    assert before["copy_performed"] is False

    result = init.operation("complete-layout", root=root)
    assert result["layout_complete"] is True
    assert result["manifest_sha256"] == before["manifest_sha256"]
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == original_hash
    assert manifest.read_bytes() == original
    assert result["source_tree_sha256"] == before["source_tree_sha256"]
    assert init.operation("complete-layout", root=root) == result
    assert init.operation("verify", root=root)["layout_complete"] is True
    assert not (project / "controller-inherited-v1.json").exists()
    assert not (project / "controller.json").exists()
    assert not copy._map(root, copy.OLD).exists()


def test_resume_interrupted_layout_completion_without_overwriting_existing(
        tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    init.operation("stage", root=root, source_checkouts=repos)
    init.operation("commit", root=root)
    target = copy._map(root, copy.NEW)
    for name in init.LAYOUT_DIRECTORIES:
        (target / name).rmdir()
    (target / "package").mkdir(mode=0o755)
    missing = init.operation("verify", root=root)["missing_layout_directories"]
    assert missing == ["application", "catalogue"]
    result = init.operation("complete-layout", root=root)
    assert result["layout_complete"] is True
    assert list((target / "package").iterdir()) == []


@pytest.mark.parametrize("foreign", (
    "unexpected-package-content", "controller-present", "linked-catalogue",
    "wrong-permissions",
))
def test_layout_completion_rejects_foreign_and_conflicting_state(
        tmp_path, monkeypatch, foreign):
    root, repos = setup(tmp_path, monkeypatch)
    init.operation("stage", root=root, source_checkouts=repos)
    init.operation("commit", root=root)
    target = copy._map(root, copy.NEW)
    for name in init.LAYOUT_DIRECTORIES:
        (target / name).rmdir()
    if foreign == "unexpected-package-content":
        (target / "package").mkdir(mode=0o755)
        (target / "package" / "artifact").write_text("foreign")
    elif foreign == "controller-present":
        (target / "controller-inherited-v1.json").write_text("{}")
    elif foreign == "linked-catalogue":
        (target / "catalogue").symlink_to(target / "state")
    else:
        (target / "package").mkdir(mode=0o700)
    with pytest.raises(copy.MigrationHold):
        init.operation("complete-layout", root=root)
    assert not (target / "application").exists()
    assert (target / init.MANIFEST).is_file()


def test_recovery_rejects_mutated_source_tree_and_manifest(tmp_path, monkeypatch):
    root, repos = setup(tmp_path, monkeypatch)
    init.operation("stage", root=root, source_checkouts=repos)
    init.operation("commit", root=root)
    target = copy._map(root, copy.NEW)
    for name in init.LAYOUT_DIRECTORIES:
        (target / name).rmdir()
    (target / "source/tracked.txt").write_text("changed")
    with pytest.raises(copy.MigrationHold):
        init.operation("complete-layout", root=root)
    assert not (target / "package").exists()
