"""Complete only missing layout in an existing, explicitly selected image-build Project.

The original Project, Git repository, state/generations, manifests, controller,
applications and package files are never copied, edited, moved or deleted.
The source revision/tree and Project device/inode are operator-selected inputs
that MUST have been reviewed separately; this command authenticates them
against current local facts. It never selects a generation or a build account.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

from . import fonts_project_migration as migration

SCHEMA = "zog-host-install-existing-image-build-project-layout-v1"
APPROVED_REPOSITORY = "zog144/image-build"
LAYOUT = ("package", "application", "catalogue", "state")
ALLOWED_PARENTS = ("/home/", "/var/lib/zog/image-build/", "/var/lib/zog/image-build-lanes/")
_HEX = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _selection(project_root, source_relative, repository, revision, tree):
    migration.require(type(project_root) is str and project_root.startswith("/")
                      and project_root != "/" and project_root == str(PurePosixPath(project_root))
                      and ".." not in PurePosixPath(project_root).parts
                      and any(project_root.startswith(prefix) for prefix in ALLOWED_PARENTS),
                      "existing Project must be explicitly selected under reviewed project storage")
    migration.require(type(source_relative) is str
                      and source_relative not in ("", ".", "..")
                      and source_relative == str(PurePosixPath(source_relative))
                      and not source_relative.startswith("/")
                      and ".." not in PurePosixPath(source_relative).parts,
                      "source must be a normalized relative checkout within the existing Project")
    migration.require(repository == APPROVED_REPOSITORY,
                      "reviewed image-build repository differs")
    migration.require(type(revision) is str and _HEX.fullmatch(revision)
                      and type(tree) is str and _HEX.fullmatch(tree)
                      and len(revision) == len(tree),
                      "expected approved source commit and tree IDs are required")
    return {"project_root": project_root, "source_relative": source_relative,
            "repository": repository, "revision": revision, "tree": tree}


def _target(root, project_root):
    root = Path(root).absolute()
    migration.require(root.is_dir() and not root.is_symlink(),
                      "inspection filesystem root is absent or linked")
    migration._parents_secure(root, project_root, require_leaf=True)
    target = migration._map(root, project_root)
    st = target.lstat()
    migration.require(stat.S_ISDIR(st.st_mode) and not target.is_symlink(),
                      "selected existing Project must be a real directory")
    mode = stat.S_IMODE(st.st_mode)
    migration.require((mode & 0o700) == 0o700 and not mode & 0o022,
                      "existing Project permissions are unsafe or inaccessible")
    return target, st


def _git(directory, *args):
    # Never allow caller Git env overrides or optional index refresh writes.
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GIT_"):
            del env[key]
    env["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        run = subprocess.run(
            # Explicitly trust only this already validated checkout path for
            # read-only root inspection of an existing non-root-owned Project.
            # Never configure Git's global safe.directory or a wildcard.
            ["git", "-c", "safe.directory=" + str(directory),
             "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
             "-C", str(directory), *args],
            env=env, text=True, capture_output=True, check=False, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise migration.MigrationHold("existing Project Git source inspection failed") from exc
    migration.require(run.returncode == 0,
                      "existing Project Git source inspection failed")
    return run.stdout.strip()


def _source(target, selected):
    directory = target / selected["source_relative"]
    # No links in the ancestry; do not resolve a checked-out source outside
    # the original Project even if the selected path looks innocuous.
    cursor = target
    for component in PurePosixPath(selected["source_relative"]).parts:
        cursor = cursor / component
        migration.require(cursor.is_dir() and not cursor.is_symlink(),
                          "existing Project source ancestry is absent or linked")
    migration.require((directory / ".git").is_dir()
                      and not (directory / ".git").is_symlink(),
                      "existing Project has no independent Git history")
    migration.require(_git(directory, "rev-parse", "--show-toplevel") ==
                      str(directory), "reviewed checkout root differs from selected Project source")
    actual_rev = _git(directory, "rev-parse", "--verify", "HEAD^{commit}")
    actual_tree = _git(directory, "rev-parse", "--verify", "HEAD^{tree}")
    migration.require(actual_rev == selected["revision"]
                      and actual_tree == selected["tree"],
                      "existing Project source commit or tree differs from approved selection")
    origin = _git(directory, "remote", "get-url", "origin")
    migration.require(origin in (
        "https://github.com/" + APPROVED_REPOSITORY,
        "https://github.com/" + APPROVED_REPOSITORY + ".git"),
        "existing Project source remote differs from approved repository")
    migration.require(not _git(directory, "status", "--porcelain=v1",
                               "--untracked-files=no"),
                      "approved Project source tracked worktree/index is modified")
    refs = _git(directory, "for-each-ref",
                "--format=%(refname) %(objectname)")
    return {"repository": selected["repository"], "revision": actual_rev,
            "tree": actual_tree, "refs_sha256": hashlib.sha256(
                refs.encode()).hexdigest(), "root": selected["source_relative"],
            "untracked_files_not_approved": True}


def _entries(target):
    """Metadata for *existing top-level entries*, without traversing data.

    The operation never writes under these entries. Deep-root inventories
    could be multi-terabyte historical generations and are neither
    necessary nor an excuse to inspect private artifact bytes.
    """
    records = []
    for item in sorted(os.scandir(target), key=lambda item: item.name):
        st = item.stat(follow_symlinks=False)
        records.append({
            "name": item.name, "mode": stat.S_IMODE(st.st_mode),
            "type": stat.S_IFMT(st.st_mode), "device": st.st_dev,
            "inode": st.st_ino, "uid": st.st_uid, "gid": st.st_gid,
            "size": st.st_size if not stat.S_ISDIR(st.st_mode) else None,
            "mtime_ns": st.st_mtime_ns if not stat.S_ISDIR(st.st_mode) else None,
            "link_target": os.readlink(item.path) if stat.S_ISLNK(st.st_mode) else None,
        })
    return records


def _layout(target, owner_uid, owner_gid):
    missing, existing = [], []
    for name in LAYOUT:
        path = target / name
        if not path.exists() and not path.is_symlink():
            missing.append(name)
            continue
        st = path.lstat()
        mode = stat.S_IMODE(st.st_mode)
        migration.require(stat.S_ISDIR(st.st_mode) and not path.is_symlink(),
                          "existing Project layout entry is not a directory: " + name)
        migration.require(st.st_uid == owner_uid and st.st_gid == owner_gid
                          and mode & 0o700 == 0o700 and not mode & 0o022,
                          "existing Project layout directory ownership/mode differs: " + name)
        migration.require(os.access(path, os.R_OK | os.W_OK | os.X_OK,
                                    effective_ids=True),
                          "running installer cannot access existing Project layout directory: " + name)
        # Existing nonempty directories intentionally remain intact.
        existing.append(name)
    return {"present": existing, "missing": missing,
            "complete": len(missing) == 0}


def _inspect(root, selected, *, expected_device=None, expected_inode=None):
    target, st = _target(root, selected["project_root"])
    if expected_device is not None:
        migration.require(st.st_dev == expected_device and st.st_ino == expected_inode,
                          "existing Project device/inode changed since explicit selection")
    migration.require(os.access(target, os.R_OK | os.W_OK | os.X_OK,
                                effective_ids=True),
                      "existing Project is not writable/traversable under current process")
    return {
        "schema": SCHEMA, "project_root": selected["project_root"],
        "project_identity": {"device": st.st_dev, "inode": st.st_ino,
                             "uid": st.st_uid, "gid": st.st_gid,
                             "mode": f"{stat.S_IMODE(st.st_mode):04o}"},
        "source": _source(target, selected),
        "layout": _layout(target, st.st_uid, st.st_gid),
        "existing_entry_metadata_sha256": hashlib.sha256(
            _canonical(_entries(target))).hexdigest(),
        "existing_entry_count": len(os.listdir(target)),
        "generation_selection": "NOT_PERFORMED",
        "generation_files_modified": False,
        "controller_modified": False,
        "historical_files_modified": False,
        "new_project_created": False,
        "compilation_authorized": False,
        "effective_uid": os.geteuid(), "effective_gid": os.getegid(),
    }


def operation(action, *, project_root, source_relative, expected_repository,
              expected_revision, expected_tree, expected_device=None,
              expected_inode=None, root=Path("/")):
    selected = _selection(project_root, source_relative, expected_repository,
                          expected_revision, expected_tree)
    migration.require(action in {"inspect", "complete-layout", "verify"},
                      "unknown existing Project layout operation")
    if action == "complete-layout":
        migration.require(type(expected_device) is int and type(expected_inode) is int
                          and expected_device > 0 and expected_inode > 0,
                          "completion requires exact inspected Project device/inode")
    elif expected_device is not None or expected_inode is not None:
        migration.require(type(expected_device) is int and type(expected_inode) is int,
                          "both Project device and inode must be provided")
    target, _ = _target(root, project_root)
    directory_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        # Directory locking introduces no new file or Project metadata, and
        # serializes this installer with itself. Other writers are detected
        # by source and top-level metadata rechecks.
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        before = _inspect(root, selected, expected_device=expected_device,
                          expected_inode=expected_inode)
        if action != "complete-layout":
            return dict(before, action=action, created_directories=[])
        target_uid, target_gid = (before["project_identity"][k] for k in ("uid", "gid"))
        # The privileged root installer may preserve observed existing owner
        # on ONLY new directories; non-root installer must already be owner.
        migration.require(os.geteuid() == 0 or
                          (os.geteuid(), os.getegid()) == (target_uid, target_gid),
                          "cannot preserve Project ownership with current execution context")
        missing = before["layout"]["missing"]
        untouched = {r["name"]: r for r in _entries(target)}
        created = []
        for name in missing:
            # No recursive mkdir, chown -R, account selection, new Project,
            # controller write or existing file/mode correction.
            os.mkdir(name, 0o700, dir_fd=directory_fd)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=directory_fd)
            try:
                if os.geteuid() == 0:
                    os.fchown(fd, target_uid, target_gid)
                os.fchmod(fd, 0o700)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory_fd)
            created.append(name)
        after = _inspect(root, selected, expected_device=expected_device,
                         expected_inode=expected_inode)
        migration.require(after["layout"]["complete"] is True
                          and after["source"] == before["source"],
                          "existing Project source changed during layout completion")
        current = {r["name"]: r for r in _entries(target)}
        migration.require(all(current.get(name) == row for name, row in untouched.items())
                          and set(current) == set(untouched) | set(created),
                          "existing Project files/history changed during layout completion")
        return dict(after, action=action, created_directories=created,
                    existing_entries_preserved=len(untouched),
                    prior_metadata_sha256=before["existing_entry_metadata_sha256"])
    finally:
        os.close(directory_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    for cmd in ("inspect", "complete-layout", "verify"):
        action.add_argument("--" + cmd, action="store_true")
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--source-relative", required=True)
    parser.add_argument("--expected-source-repository",
                        default=APPROVED_REPOSITORY)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--expected-source-tree", required=True)
    parser.add_argument("--expected-project-device", type=int)
    parser.add_argument("--expected-project-inode", type=int)
    args = parser.parse_args(argv)
    name = next(cmd for cmd in ("inspect", "complete-layout", "verify")
                if getattr(args, cmd.replace("-", "_")))
    result = operation(
        name, project_root=args.project_root,
        source_relative=args.source_relative,
        expected_repository=args.expected_source_repository,
        expected_revision=args.expected_source_revision,
        expected_tree=args.expected_source_tree,
        expected_device=args.expected_project_device,
        expected_inode=args.expected_project_inode)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
