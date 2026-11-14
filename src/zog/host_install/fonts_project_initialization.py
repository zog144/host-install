"""Initial first-Fonts Project creation from actual immutable Git source checkouts.

Unlike fonts_project_migration, this contract applies ONLY when the retained
lane was prepared but its historical Project was never materialized. It does
not pretend to copy the old Project, provide a copy receipt, or create an old
source tree. The caller must supply the three reviewed, complete Git trees.
No alternate UID/GID is accepted or selected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from . import fonts_project_migration as migration

SCHEMA = "zog-fonts-project-first-initialization-v1"
MANIFEST = ".first-fonts-initialization-v1.json"
PENDING = "/var/lib/zog/image-build/projects/.gateway-first-fonts-runtime.initialize-pending"
# Root-level directories in host-deploy.fonts_lane_runtime._SUBDIRS.
LAYOUT_DIRECTORIES = ("package", "application", "catalogue")
CONTROLLER_FILES = ("controller-inherited-v1.json", "controller.json")
SOURCES = {
    "source": ("zog144/image-build", "620378bdd8075daeb5eaad45eedea4af7db36423"),
    "companions/box-control": ("zog144/box-control", "fdafbfb3032847b73c77abd9d90d769e43fddf85"),
    "companions/build-record": ("zog144/build-record", "a866c9c4b0dd385045f00ce2de7d809f5b67c104"),
}


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def _git(tree, *argv):
    done = subprocess.run(["git", "-C", str(tree), *argv], capture_output=True,
                          text=True, timeout=30, check=False)
    migration.require(done.returncode == 0, "reviewed Git checkout cannot be inspected")
    return done.stdout.strip()


def _source(tree, relative):
    repository, revision = SOURCES[relative]
    tree = Path(tree)
    migration.require(tree.is_absolute() and tree.is_dir() and not tree.is_symlink(),
                      "reviewed source checkout missing or linked: " + relative)
    migration.require(_git(tree, "rev-parse", "--show-toplevel") == str(tree.resolve()),
                      "reviewed source checkout root differs: " + relative)
    migration.require(_git(tree, "rev-parse", "--verify", "HEAD") == revision,
                      "reviewed source revision differs: " + relative)
    migration.require(not _git(tree, "status", "--porcelain=v1", "--untracked-files=all"),
                      "reviewed source has modifications: " + relative)
    origin = _git(tree, "remote", "get-url", "origin")
    migration.require(origin in ("https://github.com/" + repository,
                                 "https://github.com/" + repository + ".git"),
                      "reviewed source provenance repository differs: " + relative)
    migration.require((tree / ".git").is_dir() and not (tree / ".git").is_symlink(),
                      "reviewed source is not an independent Git checkout")
    # Git's authenticated tree object is stable across legitimate index mtime
    # refreshes. Full filesystem snapshots include .git/index timestamps,
    # which change during git status and therefore cannot be rechecked as a
    # durable source digest. Git status above rejects edited/untracked files.
    tree_id = _git(tree, "rev-parse", "HEAD^{tree}")
    migration.require(re.fullmatch(r"[a-f0-9]{40,64}", tree_id) is not None,
                      "invalid reviewed Git tree identity")
    return hashlib.sha256((tree_id + "\n").encode("ascii")).hexdigest()


def _absent_old(root):
    old = migration._map(root, migration.OLD)
    migration.require(not old.exists() and not old.is_symlink(),
                      "historical Project exists: initialization forbidden; use copy/recovery")
    migration.require(not migration._map(root, migration.PENDING).exists(),
                      "historical copy staging exists: inspect before initialization")


def _manifest(path):
    file = path / MANIFEST
    migration.require(not file.is_symlink() and file.is_file(),
                      "initialization manifest missing or linked")
    data = json.loads(file.read_bytes())
    migration.require(type(data) is dict and data.get("schema") == SCHEMA and
                      data.get("source_checkouts") == {
                          k: {"repository": repo, "revision": rev}
                          for k, (repo, rev) in SOURCES.items()},
                      "initialized Project provenance differs")
    return data


def _layout(path):
    """Classify only the three root-level, owner-controlled runtime directories.

    Never infer readiness from the retained manifest alone. An unexpected
    directory owner, permission, file, symlink or foreign controller is a HOLD,
    not a repairable missing directory.
    """
    for filename in CONTROLLER_FILES:
        item = path / filename
        migration.require(not item.exists() and not item.is_symlink(),
                          "controller already present; initialization completion forbidden")
    missing = []
    for name in LAYOUT_DIRECTORIES:
        item = path / name
        if not item.exists() and not item.is_symlink():
            missing.append(name)
            continue
        st = item.lstat()
        migration.require(stat.S_ISDIR(st.st_mode) and not item.is_symlink()
                          and st.st_uid == path.stat().st_uid
                          and st.st_gid == path.stat().st_gid
                          and stat.S_IMODE(st.st_mode) == 0o755
                          and not os.listdir(item),
                          "foreign or nonempty controller directory: " + name)
    return missing


def _complete_layout(root, target):
    """Idempotent source-owned recovery; no reinitialization or manifest edits."""
    prior = _verify(root, target, "verify")
    # Do not turn a copied/foreign project into this exact immutable
    # initialized one. _verify authenticated all three Git source trees.
    migration.require(prior["initialized_source_verified"] is True
                      and prior["controller_installed"] is False,
                      "only verified unactivated initialization can be completed")
    for name in _layout(target):
        item = target / name
        try:
            item.mkdir(mode=0o755)
        except FileExistsError:
            raise migration.MigrationHold("concurrent controller directory appeared: " + name)
        st = item.lstat()
        migration.require(stat.S_ISDIR(st.st_mode) and not item.is_symlink()
                          and st.st_uid == os.geteuid()
                          and st.st_gid == os.getegid()
                          and stat.S_IMODE(st.st_mode) == 0o755
                          and not os.listdir(item),
                          "new controller directory does not match execution context")
        _sync_directory(item)
        _sync_directory(target)
    verified = _verify(root, target, "complete-layout")
    migration.require(verified["layout_complete"] is True,
                      "controller directory layout recovery is incomplete")
    migration.require(verified["manifest_sha256"] == prior["manifest_sha256"],
                      "initialization provenance changed during layout completion")
    return verified


LAYOUT_DIRECTORIES = ("package", "application", "catalogue")
CONTROLLERS = ("controller.json", "controller-inherited-v1.json")


def _layout(path):
    """Inspect only the three runtime directories absent from the original init.

    Existing entries must be genuine directories owned and accessible by the
    current installer. An unknown entry is never repaired or replaced.
    """
    present = []
    absent = []
    for name in LAYOUT_DIRECTORIES:
        entry = path / name
        if not entry.exists() and not entry.is_symlink():
            absent.append(name)
            continue
        st = entry.lstat()
        migration.require(stat.S_ISDIR(st.st_mode) and not entry.is_symlink(),
                          "initialized runtime directory is foreign: " + name)
        migration.require(st.st_uid == os.geteuid() and st.st_gid == os.getegid()
                          and stat.S_IMODE(st.st_mode) == 0o700 and
                          os.access(entry, os.R_OK | os.W_OK | os.X_OK,
                                    effective_ids=True),
                          "initialized runtime directory identity or access differs: " + name)
        present.append(name)
    return {"status": "ready" if not absent else
            "initialized" if not present else "incomplete",
            "present": present, "missing": absent}


def _complete_layout(root, target):
    """Complete an already committed, authenticated initialization, without
    changing its original manifest or existing source/companion contents.

    A repeat after partial directory creation is safe *only* when all existing
    objects match the reviewed current-process ownership and access rules.
    """
    original = _verify(root, target, "verify")
    for name in CONTROLLERS:
        entry = target / name
        migration.require(not entry.exists() and not entry.is_symlink(),
                          "controller already present; inspect before layout completion")
    before = _layout(target)  # Reject every conflicting entry before writes.
    for name in before["missing"]:
        entry = target / name
        os.mkdir(entry, mode=0o700)
        # Creation must not depend on the caller's umask.
        os.chmod(entry, 0o700)
        _sync_directory(entry)
    _sync_directory(target)
    after = _verify(root, target, "complete-layout")
    migration.require(after["runtime_layout"]["status"] == "ready" and
                      after["manifest_sha256"] == original["manifest_sha256"] and
                      after["source_tree_sha256"] == original["source_tree_sha256"],
                      "initialized layout completion changed reviewed source evidence")
    return after


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify(root, path, action):
    _absent_old(root)
    migration.require(path.is_dir() and not path.is_symlink(),
                      "initialized Project missing or redirected")
    data = _manifest(path)
    migration.require(data.get("historical_project_materialized") is False and
                      data.get("copy_performed") is False and
                      data.get("account_selection") is False and
                      data.get("controller_installed") is False and
                      data.get("project_root") == migration.NEW,
                      "initialization manifest falsely claims copy or controller authority")
    for key in SOURCES:
        directory = path / key
        migration.require(directory.is_dir() and not directory.is_symlink(),
                          "initialized source checkout missing: " + key)
        expected = data.get("source_tree_sha256", {}).get(key)
        migration.require(type(expected) is str and re.fullmatch(r"[a-f0-9]{64}", expected)
                          and _source(directory, key) == expected,
                          "initialized checkout/source-tree differs: " + key)
    missing = _layout(path)
    state = path / "state"
    migration.require(state.is_dir() and not state.is_symlink(),
                      "initialized state root missing")
    controllers_present = []
    for name in CONTROLLERS:
        entry = path / name
        if entry.exists() or entry.is_symlink():
            st = entry.lstat()
            migration.require(stat.S_ISREG(st.st_mode) and not entry.is_symlink()
                              and st.st_nlink == 1 and not stat.S_IMODE(st.st_mode) & 0o022,
                              "initialized controller object is foreign: " + name)
            controllers_present.append(name)
    migration.require(path.stat().st_uid == os.geteuid()
                      and path.stat().st_gid == os.getegid(),
                      "initialization directory differs from executing identity")
    return {"schema": SCHEMA, "action": action,
            "new_project": migration.NEW,
            "old_project": migration.OLD,
            "historical_project_materialized": False,
            "copy_performed": False,
            "initialized_source_verified": True,
            "controller_installed": False,
            "layout_complete": not missing,
            "missing_layout_directories": missing,
            "source_checkouts": data["source_checkouts"],
            "source_tree_sha256": data["source_tree_sha256"],
            "manifest_sha256": hashlib.sha256(_canonical(data)).hexdigest(),
            "destination": migration._access(path),
            "runtime_layout": _layout(path),
            "controllers_present": controllers_present,
            "effective_uid": os.geteuid(), "effective_gid": os.getegid(),
            "compilation_authorized": False}


def operation(action, *, root=Path("/"), source_checkouts=None):
    """Explicit root-owned installer command; root is disposable test-only."""
    root = Path(root).absolute()
    migration.require(root.is_dir() and not root.is_symlink(), "filesystem root absent")
    if root == Path("/") and action in ("stage", "commit", "complete-layout"):
        migration.require(os.geteuid() == 0, "initialization requires installed administrator")
    target = migration._map(root, migration.NEW)
    pending = migration._map(root, PENDING)
    _absent_old(root)
    if action == "inspect":
        return {"schema": SCHEMA, "action": action, "new_project": migration.NEW,
                "old_project": migration.OLD, "copy_performed": False,
                "target_exists": target.exists() or target.is_symlink(),
                "pending_exists": pending.exists() or pending.is_symlink(),
                "historical_project_materialized": False,
                "compilation_authorized": False}
    migration.require(action in {"stage", "commit", "verify", "complete-layout"}, "unknown initialize operation")
    if action == "complete-layout":
        return _complete_layout(root, target)
    if action == "verify":
        return _verify(root, target, "verify")
    if action == "complete-layout":
        return _complete_layout(root, target)
    if action == "commit":
        migration.require(not target.exists() and not target.is_symlink(),
                          "initialized destination already exists; do not replace")
        result = _verify(root, pending, "commit")
        migration._sync_tree(pending)
        migration._publish_no_replace(pending, target)
        _sync_directory(target.parent)
        return _verify(root, target, "commit")
    migration.require(not target.exists() and not target.is_symlink()
                      and not pending.exists() and not pending.is_symlink(),
                      "initialization already present/pending; inspect, never overwrite")
    migration.require(type(source_checkouts) is dict and set(source_checkouts) == set(SOURCES),
                      "three reviewed source checkouts required to initialize")
    for key in SOURCES:
        _source(source_checkouts[key], key)  # preflight all before any writes
    migration._prepare_parent(root)
    pending.mkdir(mode=0o700)
    (pending / "companions").mkdir(mode=0o700)
    (pending / "state").mkdir(mode=0o700)
    for name in LAYOUT_DIRECTORIES:
        (pending / name).mkdir(mode=0o755)
    hashed = {}
    for key in SOURCES:
        src = Path(source_checkouts[key])
        snapshot = migration._tree(src)
        migration._copy(src, pending / key, snapshot)
        hashed[key] = _source(pending / key, key)
    migration.require(not (pending / "source" / "project/pins/2026-10-01/commit-pin.py").exists(),
                      "public producer contains prohibited historical pin")
    migration.require(not (pending / "source" / "controller.json").exists(),
                      "selected source contains foreign controller")
    data = {"schema": SCHEMA, "project_root": migration.NEW,
            "historical_project_materialized": False, "copy_performed": False,
            "account_selection": False, "controller_installed": False,
            "source_checkouts": {k: {"repository": repo, "revision": rev}
                                 for k, (repo, rev) in SOURCES.items()},
            "source_tree_sha256": hashed}
    fd = os.open(pending / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_canonical(data) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return _verify(root, pending, "stage")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    for key in ("inspect", "stage", "commit", "verify", "complete-layout"):
        action.add_argument("--" + key, action="store_true")
    parser.add_argument("--source-checkout", type=Path)
    parser.add_argument("--box-control-checkout", type=Path)
    parser.add_argument("--build-record-checkout", type=Path)
    args = parser.parse_args(argv)
    selected = {"source": args.source_checkout,
                "companions/box-control": args.box_control_checkout,
                "companions/build-record": args.build_record_checkout}
    name = next(key for key in ("inspect", "stage", "commit", "verify", "complete-layout")
                if getattr(args, key.replace("-", "_")))
    if name == "stage" and any(v is None for v in selected.values()):
        parser.error("--stage requires all three explicitly reviewed checkouts")
    print(json.dumps(operation(name, source_checkouts=selected if name == "stage" else None),
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
