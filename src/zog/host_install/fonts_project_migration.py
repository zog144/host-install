"""Non-destructive migration of the retained first Fonts Project into app storage.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

Root administrator runs this one-time copy because the old parent is private.
Files in the new tree inherit the executing process's kernel UID/GID; no
alternate user, chown target, numeric UID, passwd-home or env selection exists.
The old Project remains intact. No controller specification is rewritten.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat

OLD = "/home/certbot-build-owner/gateway-first-fonts-runtime"
NEW = "/var/lib/zog/image-build/projects/gateway-first-fonts-runtime"
PENDING = "/var/lib/zog/image-build/projects/.gateway-first-fonts-runtime.pending"
SCHEMA = "zog-fonts-project-nondestructive-migration-v1"
SPECIAL = stat.S_ISREG, stat.S_ISDIR, stat.S_ISLNK


class MigrationHold(RuntimeError):
    pass


def require(ok, why):
    if not ok:
        raise MigrationHold(why)


def _map(root, path):
    require(type(path) is str and path.startswith("/") and ".." not in
            PurePosixPath(path).parts, "invalid fixed Project path")
    return root / path.lstrip("/")


def _parents_secure(root, path, *, require_leaf=False):
    cursor = root
    require(root.is_dir() and not root.is_symlink(),
            "migration filesystem root missing or linked")
    for part in PurePosixPath(path).parts[1:]:
        cursor = cursor / part
        if not cursor.exists() and not cursor.is_symlink():
            if require_leaf:
                raise MigrationHold("required Project ancestor absent: " + str(cursor))
            break
        require(not cursor.is_symlink() and cursor.is_dir(),
                "symlink or non-directory Project ancestor: " + str(cursor))


def _tree(path):
    """Closed, content-addressed Project snapshot; do not follow symlinks."""
    require(path.is_dir() and not path.is_symlink(),
            "retained Project must be a real directory")
    rows = []
    owner_counts = {}
    links = {}
    seen_count = {}

    def walk(p, rel):
        st = p.lstat()
        mode = stat.S_IMODE(st.st_mode)
        owner = f"{st.st_uid}:{st.st_gid}"
        owner_counts[owner] = owner_counts.get(owner, 0) + 1
        if stat.S_ISDIR(st.st_mode):
            rows.append({"path": rel, "type": "dir",
                         "mode": None if rel == "." else mode,
                         "mtime_ns": st.st_mtime_ns})
            for name in sorted(os.listdir(p)):
                require(name not in (".", "..") and "/" not in name,
                        "invalid directory entry")
                walk(p / name, name if rel == "." else rel + "/" + name)
        elif stat.S_ISREG(st.st_mode):
            require(not mode & 0o6000, "set-id Project file unsupported")
            # A hardlink outside the Project could silently retain unrelated
            # data/authority, so refuse before copying anything.
            identity = (st.st_dev, st.st_ino)
            first = links.setdefault(identity, (rel, st.st_nlink))
            require(first[1] == st.st_nlink,
                    "changing source hardlink count")
            seen_count[identity] = seen_count.get(identity, 0) + 1
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                observed = os.fstat(fd)
                require((observed.st_dev, observed.st_ino, observed.st_size,
                         observed.st_mtime_ns) ==
                        (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns),
                        "source replaced during inventory")
                digest = hashlib.sha256()
                with os.fdopen(fd, "rb") as stream:
                    fd = -1
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                require((p.lstat().st_ino, p.lstat().st_size,
                         p.lstat().st_mtime_ns) ==
                        (st.st_ino, st.st_size, st.st_mtime_ns),
                        "source modified during inventory")
            finally:
                if fd >= 0:
                    os.close(fd)
            rows.append({"path": rel, "type": "file", "mode": mode,
                         "size": st.st_size, "sha256": digest.hexdigest(),
                         "hardlink_first": first[0],
                         "mtime_ns": st.st_mtime_ns})
        elif stat.S_ISLNK(st.st_mode):
            target = os.readlink(p)
            # Preserve relative internal links unchanged; never copy an
            # escaping or absolute link into a privileged application tree.
            require(target and not target.startswith("/"),
                    "absolute or empty Project symlink unsupported")
            resolved = (PurePosixPath(rel).parent / target)
            parts = []
            for part in resolved.parts:
                if part == "..":
                    require(bool(parts), "symlink escapes Project")
                    parts.pop()
                elif part not in (".", ""):
                    parts.append(part)
            require(parts, "symlink to Project root unsupported")
            rows.append({"path": rel, "type": "symlink",
                         "target": target, "mtime_ns": st.st_mtime_ns})
        else:
            raise MigrationHold("socket, device, fifo or unusual Project object: " + rel)
    walk(path, ".")
    for identity, (_, links_count) in links.items():
        require(seen_count[identity] == links_count,
                "Project hardlink crosses the retained tree")
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"entries": len(rows),
            "regular_bytes": sum(x.get("size", 0) for x in rows),
            "content_tree_sha256": hashlib.sha256(payload).hexdigest(),
            "ownership_counts": owner_counts, "rows": rows}


def _copy(source, dest, snapshot):
    require(not dest.exists() and not dest.is_symlink(),
            "pending Project already exists; inspect, do not overwrite")
    first_copies = {}

    def walk(src, dst, rel):
        st = src.lstat()
        if stat.S_ISDIR(st.st_mode):
            dst.mkdir(mode=0o700)
            for name in sorted(os.listdir(src)):
                walk(src / name, dst / name,
                     name if rel == "." else rel + "/" + name)
            # Restore directory timestamps/ACL/xattrs after creating all
            # children; the Project root alone is additionally private 0700.
            shutil.copystat(src, dst, follow_symlinks=False)
            dst.chmod(0o700 if rel == "." else stat.S_IMODE(st.st_mode))
        elif stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(src), dst)
            shutil.copystat(src, dst, follow_symlinks=False)
        else:
            identity = (st.st_dev, st.st_ino)
            if identity in first_copies:
                os.link(first_copies[identity], dst, follow_symlinks=False)
            else:
                shutil.copy2(src, dst, follow_symlinks=False)
                first_copies[identity] = dst
    walk(source, dest, ".")
    copied = _tree(dest)
    require(copied["rows"] == snapshot["rows"],
            "staged Project content, mode or hardlink topology changed")
    require(copied["ownership_counts"] ==
            {f"{os.geteuid()}:{os.getegid()}": copied["entries"]},
            "staged Project not owned throughout by executing process")
    return copied


def _prepare_parent(root):
    # Never modify /home, legacy user ownership, or unrelated /var/lib data.
    for path, mode in (
        ("/var/lib/zog", 0o755),
        ("/var/lib/zog/image-build", 0o700),
        ("/var/lib/zog/image-build/projects", 0o700),
    ):
        dest = _map(root, path)
        _parents_secure(root, path)
        if not dest.exists() and not dest.is_symlink():
            dest.mkdir(mode=mode)
        st = dest.lstat()
        require(stat.S_ISDIR(st.st_mode) and not dest.is_symlink()
                and st.st_uid == os.geteuid() and st.st_gid == os.getegid()
                and not stat.S_IMODE(st.st_mode) & 0o022,
                "unsafe existing application storage parent")
        if mode == 0o700:
            require(stat.S_IMODE(st.st_mode) == mode,
                    "private application directory mode differs")


def _sync_tree(path):
    """Durably flush copied files and directory entries before publication."""
    for name in sorted(os.listdir(path)):
        child = path / name
        st = child.lstat()
        if stat.S_ISDIR(st.st_mode):
            _sync_tree(child)
        elif stat.S_ISREG(st.st_mode):
            fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_no_replace(pending, target):
    """Linux atomic directory rename that cannot replace an existing Project."""
    libc = ctypes.CDLL(None, use_errno=True)
    func = getattr(libc, "renameat2", None)
    require(func is not None, "Linux renameat2 required for safe publication")
    func.argtypes = [ctypes.c_int, ctypes.c_char_p,
                     ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    func.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = func(at_fdcwd, os.fsencode(pending), at_fdcwd,
                  os.fsencode(target), rename_noreplace)
    require(result == 0,
            "pending Project could not be published without replacement (errno " +
            str(ctypes.get_errno()) + ")")


def _access(dest):
    result = {"effective_uid": os.geteuid(), "effective_gid": os.getegid()}
    try:
        st = dest.lstat()
        result.update({"owner_uid": st.st_uid, "owner_gid": st.st_gid,
                       "mode_octal": oct(stat.S_IMODE(st.st_mode)),
                       "read_write_traverse": os.access(
                           dest, os.R_OK | os.W_OK | os.X_OK,
                           effective_ids=True)})
        for name in ("state", "source"):
            part = dest / name
            if part.exists() and part.is_dir() and not part.is_symlink():
                result[name + "_accessible"] = os.access(
                    part, (os.R_OK | os.W_OK | os.X_OK)
                    if name == "state" else (os.R_OK | os.X_OK),
                    effective_ids=True)
    except FileNotFoundError:
        result["present"] = False
    return result


def operation(action, *, root=Path("/")):
    """No root CLI override; disposable root is only a test API."""
    root = Path(root).absolute()
    if root == Path("/") and action in ("stage", "commit"):
        require(os.geteuid() == 0,
                "migration requires an existing privileged installer context")
    source = _map(root, OLD)
    target = _map(root, NEW)
    pending = _map(root, PENDING)
    if action == "verify-access":
        # This check runs IN the corrected controller/worker's existing
        # process context. Do not open its inaccessible legacy private home,
        # switch UID/GID, or trust $USER/$HOME.
        access = _access(target)
        require(access.get("read_write_traverse", False),
                "current process cannot access migrated application Project")
        require(access.get("state_accessible", True),
                "current process cannot write migrated Project state")
        require(access.get("source_accessible", True),
                "current process cannot read migrated Project source")
        return {"schema": SCHEMA, "action": action, "new_project": NEW,
                "destination": access, "ssm_authorized": False}
    _parents_secure(root, OLD, require_leaf=True)
    before = _tree(source)
    base = {"schema": SCHEMA, "action": action,
            "old_project": OLD, "new_project": NEW,
            "source_entries": before["entries"],
            "source_bytes": before["regular_bytes"],
            "source_tree_sha256": before["content_tree_sha256"],
            "source_owners": before["ownership_counts"],
            "source_project_owner": {
                "uid": source.stat().st_uid, "gid": source.stat().st_gid},
            "source_unchanged": True,
            "accounts_deleted": False, "controller_rebound": False,
            "ssm_authorized": False}
    if action == "inspect":
        base["destination"] = _access(target)
        base["pending"] = pending.exists() or pending.is_symlink()
        return base
    require(action in ("stage", "commit", "verify"),
            "unknown Project migration action")
    if action == "stage":
        require(not target.exists() and not target.is_symlink(),
                "destination already exists; cannot replace")
        _prepare_parent(root)
        _copy(source, pending, before)
        require(_tree(source)["rows"] == before["rows"],
                "retained source changed during migration")
        base["staged"] = True
        base["destination"] = _access(pending)
        return base
    if action == "commit":
        require(not target.exists() and not target.is_symlink(),
                "destination already exists; cannot replace")
        require(pending.is_dir() and not pending.is_symlink(),
                "no complete staged Project to publish")
        prepared = _tree(pending)
        require(prepared["rows"] == before["rows"],
                "staged Project differs from retained source")
        require(pending.stat().st_uid == os.geteuid()
                and pending.stat().st_gid == os.getegid()
                and stat.S_IMODE(pending.stat().st_mode) == 0o700,
                "staging ownership differs from executing context")
        # Verify and flush staged bytes/entries before the atomic rename.
        # The trusted administrator owns the parent; no existing destination
        # may be overwritten even across an interrupted migration.
        _sync_tree(pending)
        _publish_no_replace(pending, target)
        fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    require(target.is_dir() and not target.is_symlink(),
            "published Project missing")
    after = _tree(target)
    require(after["rows"] == before["rows"],
            "published Project differs from retained source")
    # No numeric user/worker binding is imported from the old controller.
    # Every copied inode inherits the actual privileged migration process
    # owner and group. Recheck after publication rather than asserting it.
    require(after["ownership_counts"] ==
            {f"{target.stat().st_uid}:{target.stat().st_gid}": after["entries"]},
            "mixed destination owners; inspect previous migration")
    base["destination_owners"] = after["ownership_counts"]
    require(_tree(source)["rows"] == before["rows"],
            "retained source changed since migration")
    base["destination"] = _access(target)
    base["data_verified"] = True
    base["old_project_preserved"] = True
    return base


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Non-destructive one-time Fonts Project storage migration")
    commands = parser.add_mutually_exclusive_group(required=True)
    for name in ("inspect", "stage", "commit", "verify", "verify-access"):
        commands.add_argument("--" + name, action="store_true")
    args = parser.parse_args(argv)
    action = next(name for name in ("inspect", "stage", "commit",
                                   "verify", "verify-access")
                  if getattr(args, name.replace("-", "_")))
    print(json.dumps(operation(action), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
