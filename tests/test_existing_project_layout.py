"""Existing compiler Project layout: no replacement and no Git/state mutation."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from zog.host_install import existing_project_layout as existing
from zog.host_install import fonts_project_migration as storage


def git(directory, *args):
    done = subprocess.run(["git", "-C", str(directory), *args],
                          capture_output=True, text=True, check=True)
    return done.stdout.strip()


def fixture(tmp_path):
    root = tmp_path / "disposable"
    project = root / "home/certbot-build-owner/certbot-seed"
    project.mkdir(parents=True)
    project.parent.chmod(0o700)
    project.chmod(0o700)
    source = project / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    git(source, "config", "user.email", "fixture@example.org")
    git(source, "config", "user.name", "Fixture")
    git(source, "remote", "add", "origin",
        "https://github.com/zog144/image-build.git")
    (source / "version.py").write_text("ORIGINAL = 1\n")
    git(source, "add", "version.py")
    git(source, "commit", "-qm", "original")
    (source / "version.py").write_text("ORIGINAL = 2\n")
    git(source, "commit", "-qam", "retained second history")
    git(source, "tag", "retained-producer")
    state = project / "state/image-build/generations"
    state.mkdir(parents=True)
    record = state / ("3805294f" + "a" * 56) / "manifest.json"
    record.parent.mkdir()
    record.write_bytes(b'{"generation":"retained-original","kind":"image"}\n')
    (project / "state/image-build/derivations").mkdir()
    (project / "state/image-build/derivations/result.json").write_bytes(
        b"accepted archival provenance\n")
    (project / "controller.json").write_bytes(b"legacy config stays put\n")
    (project / "historical-pin.bin").write_bytes(b"\x00retained original pin\xff")
    (project / "historic-symlink").symlink_to("state/image-build/generations")
    selected = {"root": root, "project": project, "source": source,
                "record": record, "project_root": "/home/certbot-build-owner/certbot-seed",
                "source_relative": "source",
                "expected_repository": existing.APPROVED_REPOSITORY,
                "expected_revision": git(source, "rev-parse", "HEAD"),
                "expected_tree": git(source, "rev-parse", "HEAD^{tree}")}
    return selected


def params(selected, **changes):
    out = {k: selected[k] for k in (
        "project_root", "source_relative", "expected_repository",
        "expected_revision", "expected_tree", "root")}
    out.update(changes)
    return out


def digest_tree(path):
    """Test-only full content snapshot, including .git and historic artifacts."""
    rows = []
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs.sort()
        files.sort()
        root = Path(root)
        for name in dirs + files:
            p = root / name
            rel = str(p.relative_to(path))
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                body = ["symlink", os.readlink(p)]
            elif stat.S_ISREG(st.st_mode):
                body = ["file", hashlib.sha256(p.read_bytes()).hexdigest()]
            else:
                body = ["dir"]
            rows.append([rel, stat.S_IMODE(st.st_mode), body])
    return rows


def test_actual_existing_project_preserves_history_and_artifacts(tmp_path):
    selected = fixture(tmp_path)
    original = digest_tree(selected["project"])
    history = git(selected["source"], "log", "--format=%H")
    initial = existing.operation("inspect", **params(selected))
    assert initial["source"]["revision"] == selected["expected_revision"]
    assert initial["source"]["tree"] == selected["expected_tree"]
    assert initial["layout"]["missing"] == ["package", "application", "catalogue"]
    assert initial["layout"]["present"] == ["state"]
    assert initial["generation_selection"] == "NOT_PERFORMED"
    assert initial["new_project_created"] is False
    assert initial["compilation_authorized"] is False
    assert initial["project_identity"]["uid"] == os.geteuid()

    result = existing.operation(
        "complete-layout", **params(
            selected, expected_device=initial["project_identity"]["device"],
            expected_inode=initial["project_identity"]["inode"]))
    assert result["created_directories"] == ["package", "application", "catalogue"]
    assert result["layout"]["complete"] is True
    assert result["source"] == initial["source"]
    assert result["existing_entries_preserved"] == initial["existing_entry_count"]
    after = digest_tree(selected["project"])
    # Drop ONLY the three newly created directories, then all content,
    # Git internals, source/branch/tag, generations and state are unchanged.
    assert [r for r in after if r[0] not in result["created_directories"]] == original
    assert selected["record"].read_bytes().startswith(b'{"generation"')
    assert git(selected["source"], "log", "--format=%H") == history
    assert git(selected["source"], "rev-parse", "retained-producer") == (
        selected["expected_revision"])
    for name in result["created_directories"]:
        p = selected["project"] / name
        assert stat.S_IMODE(p.stat().st_mode) == 0o700
        assert (p.stat().st_uid, p.stat().st_gid) == (
            selected["project"].stat().st_uid, selected["project"].stat().st_gid)
    assert existing.operation(
        "verify", **params(selected))["layout"]["complete"] is True
    again = existing.operation(
        "complete-layout", **params(
            selected, expected_device=initial["project_identity"]["device"],
            expected_inode=initial["project_identity"]["inode"]))
    assert again["created_directories"] == []
    assert digest_tree(selected["project"]) == after


def test_existing_nonempty_valid_layout_is_never_modified(tmp_path):
    selected = fixture(tmp_path)
    package = selected["project"] / "package"
    package.mkdir(mode=0o700)
    (package / "artifact").write_bytes(b"retained package contents")
    original = digest_tree(selected["project"])
    initial = existing.operation("inspect", **params(selected))
    assert initial["layout"]["present"] == ["package", "state"]
    result = existing.operation(
        "complete-layout", **params(
            selected, expected_device=initial["project_identity"]["device"],
            expected_inode=initial["project_identity"]["inode"]))
    assert result["created_directories"] == ["application", "catalogue"]
    assert (package / "artifact").read_bytes() == b"retained package contents"
    assert [r for r in digest_tree(selected["project"])
            if r[0] not in result["created_directories"]] == original


@pytest.mark.parametrize("override,message", [
    ({"expected_revision": "a" * 40}, "source commit or tree differs"),
    ({"expected_tree": "b" * 40}, "source commit or tree differs"),
    ({"expected_repository": "zog144/other"}, "reviewed image-build repository differs"),
    ({"project_root": "/home/../../root"}, "existing Project must be explicitly selected"),
    ({"source_relative": "../../external"}, "source must be a normalized relative checkout"),
    ({"source_relative": "/tmp/external"}, "source must be a normalized relative checkout"),
    ({"expected_device": 123, "expected_inode": 123}, "device/inode changed"),
])
def test_bad_selection_rejected_without_mutation(tmp_path, override, message):
    selected = fixture(tmp_path)
    before = digest_tree(selected["project"])
    with pytest.raises(storage.MigrationHold, match=message):
        existing.operation("inspect", **params(selected, **override))
    assert digest_tree(selected["project"]) == before


@pytest.mark.parametrize("corruption", (
    "symlink", "not-directory", "bad-mode", "wrong-source-remote",
    "dirty-tracked", "source-link", "source-head", "no-target",
))
def test_foreign_layout_or_source_holds_without_replacing_files(tmp_path, corruption):
    selected = fixture(tmp_path)
    project = selected["project"]
    if corruption == "symlink":
        (project / "catalogue").symlink_to(project / "state")
    elif corruption == "not-directory":
        (project / "catalogue").write_text("foreign")
    elif corruption == "bad-mode":
        (project / "catalogue").mkdir(mode=0o700)
        (project / "catalogue").chmod(0o777)
    elif corruption == "wrong-source-remote":
        git(selected["source"], "remote", "set-url", "origin",
            "https://github.com/other/producer.git")
    elif corruption == "dirty-tracked":
        (selected["source"] / "version.py").write_text("unapproved\n")
    elif corruption == "source-link":
        selected["source"].rename(project / "original-source")
        (project / "source").symlink_to("original-source")
    elif corruption == "source-head":
        (selected["source"] / "another").write_text("new unapproved\n")
        git(selected["source"], "add", "another")
        git(selected["source"], "commit", "-qm", "unreviewed")
    else:
        project.rename(project.with_name("unselected-project"))
    before = digest_tree(project) if project.exists() else None
    with pytest.raises((storage.MigrationHold, FileNotFoundError)):
        existing.operation("inspect", **params(selected))
    if before is not None:
        assert digest_tree(project) == before


def test_interrupted_layout_can_resume_without_deleting_existing(tmp_path, monkeypatch):
    selected = fixture(tmp_path)
    inspected = existing.operation("inspect", **params(selected))
    actual_mkdir = existing.os.mkdir
    count = {"called": 0}

    def interrupted(*args, **kwargs):
        count["called"] += 1
        if count["called"] == 2:
            raise OSError("injected loss of installer before next mkdir")
        return actual_mkdir(*args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(existing.os, "mkdir", interrupted)
        with pytest.raises(OSError, match="injected loss"):
            existing.operation("complete-layout", **params(
                selected, expected_device=inspected["project_identity"]["device"],
                expected_inode=inspected["project_identity"]["inode"]))
    intermediate = existing.operation("inspect", **params(selected))
    assert intermediate["layout"]["present"] == ["package", "state"]
    assert intermediate["layout"]["missing"] == ["application", "catalogue"]
    result = existing.operation("complete-layout", **params(
        selected, expected_device=inspected["project_identity"]["device"],
        expected_inode=inspected["project_identity"]["inode"]))
    assert result["created_directories"] == ["application", "catalogue"]
    assert result["layout"]["complete"] is True


def test_wrong_inode_refused_at_writable_boundary(tmp_path):
    selected = fixture(tmp_path)
    before = digest_tree(selected["project"])
    with pytest.raises(storage.MigrationHold, match="device/inode changed"):
        existing.operation("complete-layout", **params(
            selected, expected_device=selected["project"].stat().st_dev,
            expected_inode=selected["project"].stat().st_ino + 1))
    assert digest_tree(selected["project"]) == before


def test_approved_source_can_have_untracked_artifacts_without_mutating_them(tmp_path):
    selected = fixture(tmp_path)
    extra = selected["source"] / "new-output-without-Git-tracking"
    extra.write_bytes(b"existing untracked output, NOT approved as source")
    before = digest_tree(selected["project"])
    info = existing.operation("inspect", **params(selected))
    assert info["source"]["untracked_files_not_approved"] is True
    result = existing.operation("complete-layout", **params(
        selected, expected_device=info["project_identity"]["device"],
        expected_inode=info["project_identity"]["inode"]))
    assert result["layout"]["complete"] is True
    assert extra.read_bytes() == b"existing untracked output, NOT approved as source"
    assert [r for r in digest_tree(selected["project"])
            if r[0] not in result["created_directories"]] == before


def test_module_packaged_as_new_cli_in_same_existing_host_install_wheel():
    import tomllib
    meta = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    scripts = meta["project"]["scripts"]
    assert scripts["host-install-existing-project-layout"] == (
        "zog.host_install.existing_project_layout:main")
    assert "host-install-fonts-project-init" in scripts
    assert "host-install-task-c" in scripts
    assert "host-install-fonts-project-migrate" in scripts
    import inspect
    code = inspect.getsource(existing)
    for prohibited in ("useradd", "groupadd", "userdel", "subprocess.run(user=",
                       "shutil.copytree(", "shutil.rmtree(", "os.rename(",
                       "os.replace(", "os.chown(", "git checkout", "git reset",
                       "git clean", "os.environ['HOME']", "os.environ['USER']"):
        assert prohibited not in code
