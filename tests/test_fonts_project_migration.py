"""Disposable filesystem regressions for retained Fonts Project migration."""
import json
import os
from pathlib import Path
import stat

import pytest

from zog.host_install import fonts_project_migration as migration


def fixture(tmp_path):
    root = tmp_path / "host"
    root.mkdir()
    (root / "var/lib").mkdir(parents=True)
    home = root / "home/certbot-build-owner"
    home.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    old = root / migration.OLD.lstrip("/")
    old.mkdir(mode=0o750)
    for dirname in ("source", "state", "application", "catalogue",
                    "package", "companions"):
        (old / dirname).mkdir(mode=0o700)
    (old / "controller.json").write_bytes(
        b'{"project_root":"/home/certbot-build-owner/gateway-first-fonts-runtime",'
        b'"execution_user_id":24202}\n')
    original = b"source and compiler artifact bytes\x00\xff"
    (old / "state" / "artifact.bin").write_bytes(original)
    os.link(old / "state" / "artifact.bin",
            old / "state" / "artifact-hardlink.bin")
    (old / "state" / "artifact-link").symlink_to("artifact.bin")
    (old / "source" / "readme").write_text("original source provenance\n")
    target = root / migration.NEW.lstrip("/")
    return root, home, old, target, original


def test_non_destructive_project_stage_commit_and_access(tmp_path):
    root, home, old, target, original = fixture(tmp_path)
    previous_mode = stat.S_IMODE(home.stat().st_mode)
    previous_config = (old / "controller.json").read_bytes()
    initial = migration.operation("inspect", root=root)
    assert initial["source_project_owner"] == {
        "uid": os.geteuid(), "gid": os.getegid()}
    assert initial["source_bytes"] >= len(original)
    assert initial["accounts_deleted"] is False
    assert not target.exists()

    staged = migration.operation("stage", root=root)
    assert staged["staged"] is True
    assert not target.exists()
    pending = root / migration.PENDING.lstrip("/")
    assert (pending / "state/artifact.bin").read_bytes() == original
    assert (old / "state/artifact.bin").read_bytes() == original

    committed = migration.operation("commit", root=root)
    assert committed["data_verified"] is True
    assert committed["old_project_preserved"] is True
    assert committed["controller_rebound"] is False
    assert committed["source_tree_sha256"] == initial["source_tree_sha256"]
    assert committed["destination"]["owner_uid"] == os.geteuid()
    assert committed["destination"]["owner_gid"] == os.getegid()
    assert committed["destination"]["mode_octal"] == "0o700"
    assert committed["destination"]["read_write_traverse"] is True
    assert committed["destination"]["state_accessible"] is True

    assert not pending.exists()
    assert (target / "controller.json").read_bytes() == previous_config
    assert (target / "state/artifact.bin").read_bytes() == original
    assert (target / "state/artifact-link").is_symlink()
    assert os.readlink(target / "state/artifact-link") == "artifact.bin"
    assert (target / "state/artifact.bin").stat().st_ino == (
        target / "state/artifact-hardlink.bin").stat().st_ino
    assert (old / "controller.json").read_bytes() == previous_config
    assert stat.S_IMODE(home.stat().st_mode) == previous_mode
    assert migration.operation("verify", root=root)["data_verified"]
    assert migration.operation("verify-access", root=root)[
        "destination"]["read_write_traverse"]


def test_existing_destination_and_pending_never_overwritten(tmp_path):
    root, _, old, target, _ = fixture(tmp_path)
    migration._prepare_parent(root)
    target.mkdir()
    (target / "foreign").write_text("retained foreign")
    with pytest.raises(migration.MigrationHold, match="destination already exists"):
        migration.operation("stage", root=root)
    assert (target / "foreign").read_text() == "retained foreign"
    target.rename(target.with_name("renamed-foreign"))
    migration.operation("stage", root=root)
    with pytest.raises(migration.MigrationHold, match="pending Project already exists"):
        migration.operation("stage", root=root)
    assert old.is_dir()
    assert (root / migration.PENDING.lstrip("/")).is_dir()


def test_modified_retained_source_blocks_commit_and_preserves_staging(tmp_path):
    root, _, old, target, _ = fixture(tmp_path)
    migration.operation("stage", root=root)
    (old / "source/readme").write_text("new unapproved source\n")
    with pytest.raises(migration.MigrationHold, match="staged Project differs"):
        migration.operation("commit", root=root)
    assert not target.exists()
    assert (root / migration.PENDING.lstrip("/")).is_dir()


def test_outside_symlink_denied_before_copy(tmp_path):
    root, _, old, target, _ = fixture(tmp_path)
    (old / "source" / "danger").symlink_to("../../../../etc/shadow")
    with pytest.raises(migration.MigrationHold, match="symlink escapes"):
        migration.operation("stage", root=root)
    assert not target.exists()
    assert not (root / migration.PENDING.lstrip("/")).exists()


def test_external_hardlink_denied(tmp_path):
    root, _, old, target, _ = fixture(tmp_path)
    outside = root / "foreign-content"
    os.link(old / "source/readme", outside)
    with pytest.raises(migration.MigrationHold,
                       match="hardlink crosses the retained tree"):
        migration.operation("stage", root=root)
    assert outside.read_text() == "original source provenance\n"
    assert not target.exists()


def test_special_file_refusal_does_not_mutate_original(tmp_path):
    root, _, old, target, _ = fixture(tmp_path)
    os.mkfifo(old / "state" / "running-service.fifo")
    with pytest.raises(migration.MigrationHold,
                       match="socket, device, fifo"):
        migration.operation("inspect", root=root)
    assert not target.exists()
    assert (old / "state/running-service.fifo").exists()


def test_migrated_project_remains_distinct_from_legacy_specification(tmp_path):
    root, _, old, target, _ = fixture(tmp_path)
    migration.operation("stage", root=root)
    migration.operation("commit", root=root)
    old_config=json.loads((old / "controller.json").read_text())
    new_config=json.loads((target / "controller.json").read_text())
    assert old_config==new_config
    assert new_config["project_root"]==migration.OLD
    assert migration.NEW!=new_config["project_root"]
    # Content copying does NOT grant a new execution identity or silently
    # rewrite the source-bound Project specification.


def test_migration_cli_packaged_separately_from_task_c_gateway():
    import tomllib
    meta=tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    scripts=meta["project"]["scripts"]
    assert scripts["host-install-fonts-project-migrate"] == (
        "zog.host_install.fonts_project_migration:main")
    assert scripts["host-install-task-c"] != scripts[
        "host-install-fonts-project-migrate"]
    import inspect
    source=inspect.getsource(migration)
    for forbidden in (
        "os.chown(", "pwd.getpwuid(", "pwd.getpwnam(",
        "subprocess.Popen(", "subprocess.run(", "useradd ", "groupadd ",
        "shutil.rmtree("):
        assert forbidden not in source


def test_atomic_no_replace_directory_publication_refuses_conflict(tmp_path):
    staged = tmp_path / "pending"
    dest = tmp_path / "destination"
    staged.mkdir()
    dest.mkdir()
    (staged / "source").write_text("copy")
    (dest / "foreign").write_text("preserve")
    with pytest.raises(migration.MigrationHold, match="without replacement"):
        migration._publish_no_replace(staged, dest)
    assert (staged / "source").read_text() == "copy"
    assert (dest / "foreign").read_text() == "preserve"


def test_runtime_access_report_never_requires_opening_legacy_private_home(
        tmp_path):
    root, home, old, target, _ = fixture(tmp_path)
    migration.operation("stage", root=root)
    migration.operation("commit", root=root)
    # Simulate private legacy home unavailable to this different
    # process context. Only the separate native runtime's own EUID/EGID
    # and destination DAC matter to the read-only access probe.
    home.chmod(0o000)
    try:
        observed = migration.operation("verify-access", root=root)
        assert observed["new_project"] == migration.NEW
        assert observed["destination"]["effective_uid"] == os.geteuid()
        assert observed["destination"]["effective_gid"] == os.getegid()
        assert observed["destination"]["read_write_traverse"] is True
        assert "old_project" not in observed
    finally:
        home.chmod(0o700)
