"""Read-only, fail-closed plan to restore a prepared Project's recorded Git source.

The manifest is authority for the *original* source, not an invitation to
repin it to whatever checkout happens to be on disk. No Host writes here.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import fonts_project_initialization as init
from . import fonts_project_migration as migration

SCHEMA = "zog-fonts-prepared-source-reconcile-v1"
PENDING = "/var/lib/zog/image-build/projects/.gateway-first-fonts-runtime.source-recovery"
RECEIPT = "/var/lib/zog/image-build/projects/.gateway-first-fonts-runtime.source-recovery.json"
LOCK = "/var/lib/zog/image-build/projects/.gateway-first-fonts-runtime.source-recovery.lock"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private(path):
    st = path.lstat()
    migration.require(stat.S_ISDIR(st.st_mode) and not path.is_symlink()
                      and st.st_uid == os.geteuid() and st.st_gid == os.getegid()
                      and stat.S_IMODE(st.st_mode) == 0o700,
                      "unsafe prepared-init directory")
    return st


def retained_file(path):
    st = path.lstat()
    migration.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                      and st.st_uid == os.geteuid() and st.st_gid == os.getegid()
                      and stat.S_IMODE(st.st_mode) == 0o600,
                      "unsafe prepared-init source evidence")
    raw = path.read_bytes()
    migration.require(path.lstat().st_ino == st.st_ino and len(raw) == st.st_size,
                      "prepared-init source evidence changed during read")
    return raw


def source(tree, *, selected=False):
    """Verify a real clean Git checkout, permitting a *reported* different HEAD."""
    tree = Path(tree)
    repository, _ = init.SOURCES["source"]
    migration.require(tree.is_absolute() and tree.is_dir() and
                      not tree.is_symlink(), "source checkout missing or linked")
    if selected:
        private(tree)
    migration.require((tree / ".git").is_dir() and
                      not (tree / ".git").is_symlink() and
                      init._git(tree, "rev-parse", "--show-toplevel") ==
                      str(tree.resolve()), "source is not an independent Git checkout")
    origin = init._git(tree, "remote", "get-url", "origin")
    migration.require(origin in ("https://github.com/" + repository,
                                 "https://github.com/" + repository + ".git"),
                      "source Git origin differs")
    commit = init._git(tree, "rev-parse", "--verify", "HEAD")
    migration.require(re.fullmatch(r"[a-f0-9]{40,64}", commit) is not None,
                      "invalid source Git commit")
    migration.require(not init._git(tree, "status", "--porcelain=v1",
                                   "--untracked-files=all"),
                      "source checkout contains unexpected modifications")
    migration._tree(tree)  # Reject special files, external links/hardlinks.
    migration.require(not init._git(tree, "status", "--porcelain=v1",
                                   "--untracked-files=all"),
                      "source checkout changed during inspection")
    tree_id = init._git(tree, "rev-parse", "HEAD^{tree}")
    migration.require(re.fullmatch(r"[a-f0-9]{40,64}", tree_id) is not None,
                      "invalid source Git tree")
    return {"revision": commit, "repository": repository,
            "tree_sha256": sha((tree_id + "\n").encode("ascii"))}


def plan(root, reviewed_checkout):
    root, checkout = Path(root).absolute(), Path(reviewed_checkout)
    migration.require(root.is_dir() and not root.is_symlink(), "filesystem root absent")
    init._absent_old(root)
    target = migration._map(root, migration.NEW)
    migration._parents_secure(root, migration.NEW, require_leaf=True)
    project = private(target)
    entries = set(os.listdir(target))
    migration.require({"source", "companions", "state", init.MANIFEST} <= entries
                      and entries <= {"source", "companions", "state",
                                      init.MANIFEST, *init.LAYOUT_DIRECTORIES},
                      "unknown prepared-init Project entries")
    state = private(target / "state")
    private(target / "companions")
    layout = init._layout(target)  # Conflicting/nonempty runtime dirs HOLD.
    raw = retained_file(target / init.MANIFEST)
    data = init._manifest(target)
    migration.require(raw == init._canonical(data) + b"\n"
                      and data.get("project_root") == migration.NEW
                      and data.get("historical_project_materialized") is False
                      and data.get("copy_performed") is False
                      and data.get("account_selection") is False
                      and data.get("controller_installed") is False
                      and type(data.get("source_tree_sha256")) is dict
                      and set(data["source_tree_sha256"]) == set(init.SOURCES),
                      "unexpected prepared-init source manifest")
    for key in init.SOURCES:
        digest = data["source_tree_sha256"][key]
        migration.require(type(digest) is str and
                          re.fullmatch(r"[a-f0-9]{64}", digest) is not None,
                          "invalid manifest source digest")
        if key != "source":
            migration.require(init._source(target / key, key) == digest,
                              "prepared companion differs from manifest: " + key)
    observed = source(target / "source", selected=True)
    replacement = source(checkout)
    migration.require(replacement["revision"] == init.SOURCES["source"][1]
                      and replacement["tree_sha256"] ==
                          data["source_tree_sha256"]["source"],
                      "replacement differs from original manifest source pin")
    migration.require(checkout.resolve() != (target / "source").resolve()
                      and not checkout.resolve().is_relative_to(target.resolve()),
                      "reviewed checkout aliases existing Project")
    migration.require(observed != replacement,
                      "recorded source already matches; use --verify")
    body = {"schema": SCHEMA, "project": migration.NEW,
            "manifest_sha256": sha(init._canonical(data)),
            "manifest_raw_sha256": sha(raw),
            "observed_source": observed, "replacement_source": replacement,
            "reviewed_checkout": str(checkout.resolve()),
            "project_inode": [project.st_dev, project.st_ino],
            "state_inode": [state.st_dev, state.st_ino],
            "layout_missing": layout["missing"],
            "manifest_replaced": False, "compilation_authorized": False}
    return {**body, "plan_sha256": sha(init._canonical(body))}
