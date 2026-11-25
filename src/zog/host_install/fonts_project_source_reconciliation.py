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


def _physical_source(tree):
    """Bind all checkout bytes/modes/links, including Git metadata.

    Git may refresh the *content* of .git/index while rebuilding its
    stat cache after a copied checkout changes inode/mtime. That file is
    therefore validated as a regular nonlinked file and its *logical*
    tracked index verified by Git status, rather than pinning transient
    index-cache bytes. Every other Git metadata and worktree entry is
    included in this canonical inventory, without volatile mtimes.
    """
    snapshot = migration._tree(tree)
    rows = []
    for original in snapshot["rows"]:
        row = {k: v for k, v in original.items() if k != "mtime_ns"}
        if row["path"] == ".git/index":
            migration.require(row["type"] == "file" and
                              not row["mode"] & 0o022,
                              "Git index is not a protected regular cache")
            # Index content changes on correct Git refresh after directory
            # exchange. Its actual tracked membership must match HEAD.
            row.pop("sha256", None)
            row.pop("size", None)
        rows.append(row)
    migration.require(any(x["path"] == ".git/index" for x in rows),
                      "Git checkout has no independent tracked index")
    raw = init._canonical(rows)
    return {"physical_tree_sha256": sha(raw),
            "physical_entries": len(rows)}


def source(tree, *, selected=False):
    """Check actual tracked bytes and *all* untracked/ignored entries."""
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
    # Porcelain ignores Git-ignored files. Such files are still copied by
    # migration._copy and therefore must never reach the privileged Project.
    migration.require(not init._git(tree, "ls-files", "--others",
                                   "--exclude-standard", "-z"),
                      "source checkout contains untracked worktree contents")
    migration.require(not init._git(tree, "ls-files", "--others", "--ignored",
                                   "--exclude-standard", "-z"),
                      "source checkout contains Git-ignored worktree contents")
    physical = _physical_source(tree)
    migration.require(not init._git(tree, "status", "--porcelain=v1",
                                   "--untracked-files=all")
                      and not init._git(tree, "ls-files", "--others",
                                        "--exclude-standard", "-z")
                      and not init._git(tree, "ls-files", "--others", "--ignored",
                                        "--exclude-standard", "-z"),
                      "source checkout changed during inspection")
    migration.require(_physical_source(tree) == physical,
                      "source checkout physical bytes changed during inspection")
    tree_id = init._git(tree, "rev-parse", "HEAD^{tree}")
    migration.require(re.fullmatch(r"[a-f0-9]{40,64}", tree_id) is not None,
                      "invalid source Git tree")
    return {"revision": commit, "repository": repository,
            "tree_sha256": sha((tree_id + "\n").encode("ascii")),
            **physical}


def plan(root, reviewed_checkout):
    root, checkout = Path(root).absolute(), Path(reviewed_checkout)
    if root == Path("/"):
        migration.require(os.geteuid() == 0,
                          "native source plan requires root; do not switch/chown existing Project")
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
