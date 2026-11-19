"""Protected Task C journal directory creation and no-adoption acceptance.

All mutation tests run only as root on disposable paths. No SSM, gateway
activation, root-control LocalTaskCJournal or live Host path is mutated.
"""
import os
from pathlib import Path
import stat

import pytest

from zog.host_install import task_c_journal_directory as journal


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0, reason="root-owned 0700 directory requires native-root fixture"
)


def host(tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir(mode=0o700)
    return root


def stat_dir(path):
    s = path.lstat()
    return (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_dev, s.st_ino)


def test_fresh_preparation_has_root_owner_exact_0700_without_journal_files(tmp_path):
    root = host(tmp_path)
    expected = root / journal.DIRECTORY.lstrip("/")
    with pytest.raises(journal.TaskCJournalDirectoryError, match="not provisioned"):
        journal.ensure_operations(root, create=False)
    info = journal.ensure_operations(root)
    assert expected.is_dir() and not expected.is_symlink()
    assert stat_dir(expected)[:3] == (0, 0, 0o700)
    assert stat_dir(expected.parent)[:3] == (0, 0, 0o700)
    assert list(expected.iterdir()) == []
    assert info == {
        "directory": journal.DIRECTORY, "owner_uid": 0, "owner_gid": 0,
        "mode": "0700", "root_owned": True, "precreated_by_installer": True,
    }
    assert journal.ensure_operations(root, create=False) == info


def test_idempotent_preparation_preserves_existing_history_and_inode(tmp_path):
    root = host(tmp_path)
    journal.ensure_operations(root)
    path = root / journal.DIRECTORY.lstrip("/")
    original = stat_dir(path)
    # Installer must never create, remove, or rewrite existing durable intent.
    receipt = path / ("a" * 32 + ".intent.json")
    receipt.write_bytes(b"retained original journal, untouched")
    receipt.chmod(0o600)
    before = stat_dir(receipt)
    assert journal.ensure_operations(root) == journal.ensure_operations(root, create=False)
    assert stat_dir(path) == original
    assert stat_dir(receipt) == before
    assert receipt.read_bytes() == b"retained original journal, untouched"


@pytest.mark.parametrize("mode", (0o755, 0o750, 0o777, 0o600))
def test_wrong_existing_operations_mode_denied_without_fix(tmp_path, mode):
    root = host(tmp_path)
    journal.ensure_operations(root)
    path = root / journal.DIRECTORY.lstrip("/")
    path.chmod(mode)
    before = stat_dir(path)
    with pytest.raises(journal.TaskCJournalDirectoryError, match="unsafe mode|unsafe"):
        journal.ensure_operations(root)
    assert stat_dir(path) == before


@pytest.mark.parametrize("uid,gid", ((12345, 0), (0, 12345)))
def test_wrong_existing_owner_or_group_denied_without_chown(tmp_path, uid, gid):
    root = host(tmp_path)
    journal.ensure_operations(root)
    path = root / journal.DIRECTORY.lstrip("/")
    os.chown(path, uid, gid)
    before = stat_dir(path)
    with pytest.raises(journal.TaskCJournalDirectoryError, match="root:root"):
        journal.ensure_operations(root)
    assert stat_dir(path) == before


def test_symlinked_leaf_is_refused_without_following_target(tmp_path):
    root = host(tmp_path)
    base = root / "var/lib/zog-task-c"
    base.mkdir(parents=True, mode=0o700)
    destination = root / "real-protected"
    destination.mkdir(mode=0o700)
    (base / "operations").symlink_to(destination)
    with pytest.raises(journal.TaskCJournalDirectoryError, match="linked|unsafe"):
        journal.ensure_operations(root)
    assert not list(destination.iterdir())


def test_symlinked_parent_refused_without_creating_leaf(tmp_path):
    root = host(tmp_path)
    (root / "var/lib").mkdir(parents=True)
    other = root / "outside"
    other.mkdir(mode=0o700)
    (root / "var/lib/zog-task-c").symlink_to(other)
    with pytest.raises(journal.TaskCJournalDirectoryError, match="linked|unsafe"):
        journal.ensure_operations(root)
    assert not (other / "operations").exists()


def test_foreign_file_at_operations_path_denied_not_replaced(tmp_path):
    root = host(tmp_path)
    base = root / "var/lib/zog-task-c"
    base.mkdir(parents=True)
    foreign = base / "operations"
    foreign.write_bytes(b"foreign private state")
    with pytest.raises(journal.TaskCJournalDirectoryError, match="unsafe|linked"):
        journal.ensure_operations(root)
    assert foreign.read_bytes() == b"foreign private state"


def test_world_writable_parent_denied_without_chmod_or_new_child(tmp_path):
    root = host(tmp_path)
    base = root / "var/lib/zog-task-c"
    base.mkdir(parents=True)
    base.chmod(0o777)
    with pytest.raises(journal.TaskCJournalDirectoryError, match="unsafe mode"):
        journal.ensure_operations(root)
    assert not (base / "operations").exists()
    assert stat.S_IMODE(base.stat().st_mode) == 0o777


def test_nonroot_installation_root_rejected_before_any_creation(tmp_path):
    root = host(tmp_path)
    os.chown(root, 12345, 12345)
    with pytest.raises(journal.TaskCJournalDirectoryError, match="root:root"):
        journal.ensure_operations(root)
    assert not list(root.iterdir())
