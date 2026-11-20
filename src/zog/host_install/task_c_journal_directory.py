"""Fail-closed root-owned Task C operation journal directory provisioning.

This is an installer-only path. It creates ordinary root-owned directories
without a special storage authority, signer, dedicated account, or separate
filesystem. The root-control LocalTaskCJournal subsequently opens exactly
/var/lib/zog-task-c/operations itself; the gateway cannot create or repair it.

A preexisting path is accepted only if it already satisfies the required
ownership, mode, type and ancestry. No chmod/chown repair is performed.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

DIRECTORY = "/var/lib/zog-task-c/operations"
ROOT_UID = 0
ROOT_GID = 0
MODE = 0o700


class TaskCJournalDirectoryError(RuntimeError):
    pass


def _require(value, message):
    if not value:
        raise TaskCJournalDirectoryError(message)


def _checked(fd, name, *, leaf=False):
    """Verify the opened path, not a previously statted string path."""
    st = os.fstat(fd)
    mode = stat.S_IMODE(st.st_mode)
    _require(stat.S_ISDIR(st.st_mode), "Task C journal ancestor is not a directory: " + name)
    _require(st.st_uid == ROOT_UID and st.st_gid == ROOT_GID,
             "Task C journal path must be root:root: " + name)
    _require(mode == MODE if leaf else not (mode & 0o022),
             "Task C journal path has unsafe mode: " + name)
    return st


def ensure_operations(root=Path("/"), *, create=True):
    """Preflight and (optionally) create only missing root-owned journal path.

    The existing top-level installation root must already be a secure,
    root-owned real directory; this does not construct the target filesystem.
    Each path component is opened relative to an authenticated parent FD
    with O_NOFOLLOW. All created entries are fsynced, with no overwrites.
    """
    root = Path(root).absolute()
    _require(root.is_dir() and not root.is_symlink(),
             "Task C installation root must be a real directory")
    fds = []
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC)
        fds.append(fd)
        _checked(fd, str(root))
        parts = ("var", "lib", "zog-task-c", "operations")
        for index, name in enumerate(parts):
            parent = fds[-1]
            is_leaf = index == len(parts) - 1
            try:
                next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            except FileNotFoundError:
                _require(create, "Task C operation journal is not provisioned")
                # Both protected parent and final operations directory are
                # private 0700; conventional /var/lib ancestors use 0755.
                mode = MODE if index >= 2 else 0o755
                os.mkdir(name, mode=mode, dir_fd=parent)
                next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                os.fsync(parent)
            fds.append(next_fd)
            _checked(next_fd, name, leaf=is_leaf)
        st = os.fstat(fds[-1])
        # The journal runtime may already have created this lock during an
        # earlier authorized invocation. Never overwrite or adopt a foreign
        # lock: that would defeat its one-operation send fence.
        try:
            lock_fd = os.open(
                ".lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fds[-1])
        except FileNotFoundError:
            lock_fd = None
        if lock_fd is not None:
            try:
                lock_st = os.fstat(lock_fd)
                _require(stat.S_ISREG(lock_st.st_mode)
                         and lock_st.st_nlink == 1
                         and lock_st.st_uid == ROOT_UID
                         and lock_st.st_gid == ROOT_GID
                         and stat.S_IMODE(lock_st.st_mode) == 0o600,
                         "Task C journal retained lock is unsafe")
            finally:
                os.close(lock_fd)
        os.fsync(fds[-1])
        return {
            "directory": DIRECTORY,
            "owner_uid": st.st_uid,
            "owner_gid": st.st_gid,
            "mode": f"{stat.S_IMODE(st.st_mode):04o}",
            "root_owned": True,
            "precreated_by_installer": True,
        }
    except (OSError, TaskCJournalDirectoryError) as exc:
        if isinstance(exc, TaskCJournalDirectoryError):
            raise
        raise TaskCJournalDirectoryError(
            "Task C operation journal absent, linked, or unsafe: " +
            str(getattr(exc, "filename", "") or "filesystem operation")
        ) from exc
    finally:
        for fd in reversed(fds):
            os.close(fd)
