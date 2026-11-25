"""Source-owned read-only inspector for the *controller-present* Fonts destination.

This is NOT the controller-free prepared initializer, an approval to restore
the old Git revision, or a historical supersession receipt. It never creates
files, locks, Projects, SSM requests or execution identities.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from . import fonts_project_initialization as init
from . import fonts_project_migration as migration

SCHEMA = "zog-host-install-fonts-controller-present-inspection-v1"
EXPECTED_MANIFEST_SHA256 = "535c0c283599c8ad3e256d4cdf8db5bb4b16bf1350dfec59de10ebde52d79cb7"
NATIVE_PROJECT_UID = 24201
_HEX = re.compile(r"[0-9a-f]{64}\\Z")
_REV = re.compile(r"[0-9a-f]{40,64}\\Z")
_MAX = 1024 * 1024


class InspectionHold(RuntimeError):
    """Untrusted historical destination or evidence path; no repair attempted."""


def require(value, message):
    if not value:
        raise InspectionHold(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


def _object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate key in historical destination evidence")
        result[name] = value
    return result


def _json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_object,
                           parse_constant=lambda name: (_ for _ in ()).throw(
                               InspectionHold("nonfinite historical evidence")))
    except (ValueError, UnicodeError) as error:
        raise InspectionHold("invalid historical destination JSON evidence") from error
    require(type(value) is dict, "historical destination JSON is not an object")
    return value


def _folder(parent, name):
    """Bind lstat to O_NOFOLLOW directory inode; never open a link."""
    require(type(name) is str and name and name not in (".", "..") and
            "/" not in name, "invalid fixed destination path component")
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISDIR(before.st_mode), "foreign directory in destination ancestry")
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    found = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_uid, before.st_gid,
         before.st_mode) != (found.st_dev, found.st_ino, found.st_uid,
                            found.st_gid, found.st_mode)):
        os.close(fd)
        raise InspectionHold("destination directory replaced during readback")
    sticky_root = (found.st_uid == 0 and
                   stat.S_IMODE(found.st_mode) == 0o1777)
    if found.st_mode & 0o022 and not sticky_root:
        os.close(fd)
        raise InspectionHold("destination directory is group/other writable")
    return fd, found


def _absolute(path):
    """Walk from real filesystem root through fixed no-follow descriptors."""
    path = Path(path)
    require(path.is_absolute() and str(path) != "/" and
            os.path.normpath(str(path)) == str(path),
            "noncanonical absolute historical Project")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    ancestry = [os.fstat(fd)]
    try:
        for piece in path.parts[1:]:
            next_fd, info = _folder(fd, piece)
            os.close(fd)
            fd = next_fd
            ancestry.append(info)
        return fd, ancestry
    except BaseException:
        os.close(fd)
        raise


def _file(folder, name, *, owners, maximum=_MAX):
    """Read fixed basename by anchored inode and verify post-read stability."""
    require(type(name) is str and name not in ("", ".", "..") and
            "/" not in name, "invalid historical evidence filename")
    try:
        original = os.stat(name, dir_fd=folder, follow_symlinks=False)
    except FileNotFoundError:
        return None, None
    require(stat.S_ISREG(original.st_mode) and original.st_nlink == 1
            and original.st_uid in owners and not original.st_mode & 0o022
            and 0 < original.st_size <= maximum,
            "unsafe historical Project evidence: " + name)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=folder)
    try:
        before = os.fstat(fd)
        keys = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                "st_nlink", "st_size")
        require(tuple(getattr(before, k) for k in keys) ==
                tuple(getattr(original, k) for k in keys),
                "historical evidence inode replaced: " + name)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=folder, follow_symlinks=False)
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) and
                tuple(getattr(named, k) for k in keys) ==
                tuple(getattr(before, k) for k in keys),
                "historical evidence changed during read: " + name)
        return raw, before
    finally:
        os.close(fd)


def _identity(observed):
    return {"device": observed.st_dev, "inode": observed.st_ino,
            "owner_uid": observed.st_uid, "owner_gid": observed.st_gid,
            "mode": stat.S_IMODE(observed.st_mode)}


def _git(directory, *, expected_repo, owners):
    """Read HEAD/tree/origin via an opened source directory, never write."""
    gitfd, metadata = _folder(directory, ".git")
    os.close(gitfd)
    source = os.fstat(directory)
    require(source.st_uid in owners, "foreign source Git checkout owner")
    env = os.environ.copy()
    env.update({"PATH": "/usr/bin:/bin", "GIT_OPTIONAL_LOCKS": "0",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
    result = {}
    for key, argv in (
        ("revision", ("rev-parse", "--verify", "HEAD")),
        ("tree", ("rev-parse", "--verify", "HEAD^{tree}")),
        ("origin", ("remote", "get-url", "origin")),
    ):
        done = subprocess.run(
            ["/usr/bin/git", "-C", "/proc/self/fd/" + str(directory), *argv],
            pass_fds=(directory,), capture_output=True, text=True,
            timeout=20, check=False, env=env)
        require(done.returncode == 0, "selected source Git evidence unavailable")
        result[key] = done.stdout.strip()
    require(_REV.fullmatch(result["revision"]) is not None and
            _REV.fullmatch(result["tree"]) is not None,
            "source Git object identity is invalid")
    require(result["origin"] in ("https://github.com/" + expected_repo,
                                 "https://github.com/" + expected_repo + ".git"),
            "source Git origin differs from original manifest")
    require(os.fstat(directory).st_ino == source.st_ino,
            "selected source inode changed during Git readback")
    return {**result, "tree_sha256": hashlib.sha256(
        (result["tree"] + "\n").encode("ascii")).hexdigest(),
            "source_identity": _identity(source),
            "full_checkout_contents_authenticated": False}

