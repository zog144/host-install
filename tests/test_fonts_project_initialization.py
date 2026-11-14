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
