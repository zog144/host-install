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
    return migration._tree(tree)["content_tree_sha256"]


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
    state = path / "state"
    migration.require(state.is_dir() and not state.is_symlink(),
                      "initialized state root missing")
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
            "source_checkouts": data["source_checkouts"],
            "source_tree_sha256": data["source_tree_sha256"],
            "manifest_sha256": hashlib.sha256(_canonical(data)).hexdigest(),
            "destination": migration._access(path),
            "effective_uid": os.geteuid(), "effective_gid": os.getegid(),
            "compilation_authorized": False}


def operation(action, *, root=Path("/"), source_checkouts=None):
    """Explicit root-owned installer command; root is disposable test-only."""
    root = Path(root).absolute()
    migration.require(root.is_dir() and not root.is_symlink(), "filesystem root absent")
    if root == Path("/") and action in ("stage", "commit"):
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
    migration.require(action in {"stage", "commit", "verify"}, "unknown initialize operation")
    if action == "verify":
        return _verify(root, target, "verify")
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
    for key in ("inspect", "stage", "commit", "verify"):
        action.add_argument("--" + key, action="store_true")
    parser.add_argument("--source-checkout", type=Path)
    parser.add_argument("--box-control-checkout", type=Path)
    parser.add_argument("--build-record-checkout", type=Path)
    args = parser.parse_args(argv)
    selected = {"source": args.source_checkout,
                "companions/box-control": args.box_control_checkout,
                "companions/build-record": args.build_record_checkout}
    name = next(key for key in ("inspect", "stage", "commit", "verify") if getattr(args, key))
    if name == "stage" and any(v is None for v in selected.values()):
        parser.error("--stage requires all three explicitly reviewed checkouts")
    print(json.dumps(operation(name, source_checkouts=selected if name == "stage" else None),
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
