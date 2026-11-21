"""Versioned Task C runtime: isolated prepare, atomic unit selection and rollback.

Source candidate only. Never starts a service, sends SSM, or mutates journal.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import uuid

from . import task_c_local_install as legacy

SCHEMA = "zog-task-c-versioned-selection-v1"
BASE = "/opt/zog/task-c"
ROLLBACK = "/var/lib/zog-task-c/runtime-rollback"
UNIT = "/etc/systemd/system/zog-task-c-gateway.service"
HOST_DEPLOY_REVISION = "5d7960e55454f88dbc85c3a6ce9c6a972ee31f23"
VERSION = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}\Z")


class SelectionError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise SelectionError(message)


def where(root, path):
    return root / path.lstrip("/")


def directory(path, *, create=False, mode=0o700, root=Path("/")):
    root = Path(root).absolute()
    require(root.is_dir() and not root.is_symlink(), "untrusted filesystem root")
    require(path.is_relative_to(root), "path outside selected filesystem")
    cursor = root
    for part in path.relative_to(root).parts:
        cursor = cursor / part
        if create and not cursor.exists() and not cursor.is_symlink():
            cursor.mkdir(mode=mode if cursor == path else 0o755)
        info = cursor.lstat()
        require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022,
                "untrusted or group-writable runtime directory")
        if root == Path("/"):
            require(info.st_uid == 0, "runtime directory must be root-owned")
    return path


def regular(path, *, root):
    directory(path.parent, root=root)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not info.st_mode & 0o022, "untrusted selected file")
    if root == Path("/"):
        require(info.st_uid == 0, "selected file must be root-owned")
    return path.read_bytes()


def atomic(path, data, *, mode=0o600):
    pending = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if pending.exists():
            pending.unlink()


def _run(runner, argv):
    result = runner(list(map(str, argv)), check=False)
    require(result.returncode == 0, "versioned runtime command failed")


def _inactive(root, runner):
    if root == Path("/"):
        legacy._require_gateway_inactive(runner)


def _check_tree(path, root):
    """Reject special files, foreign ownership and writable runtime entries."""
    directory(path, root=root)
    for parent, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            child = Path(parent) / name
            info = child.lstat()
            require((stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
                     or stat.S_ISLNK(info.st_mode)), "special file in runtime")
            if not stat.S_ISLNK(info.st_mode):
                require(not info.st_mode & 0o022, "writable runtime entry")
                if root == Path("/"):
                    require(info.st_uid == 0, "runtime entry not root-owned")
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, "multiply linked runtime entry")


def _tree_digest(path):
    digest = hashlib.sha256()
    for parent, dirs, files in os.walk(path, followlinks=False):
        for name in sorted(dirs + files):
            child = Path(parent) / name
            rel = child.relative_to(path).as_posix().encode()
            info = child.lstat()
            if stat.S_ISREG(info.st_mode):
                kind = b"f"
                with child.open("rb") as source:
                    content = hashlib.sha256()
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        content.update(block)
                payload = content.digest()
            elif stat.S_ISLNK(info.st_mode):
                kind = b"l"
                payload = os.readlink(child).encode()
            else:
                kind = b"d"
                payload = b""
            digest.update(kind + len(rel).to_bytes(4, "big") + rel
                          + len(payload).to_bytes(8, "big") + payload)
    return digest.hexdigest()


@contextmanager
def _selection_lock(root):
    storage = where(root, ROLLBACK)
    directory(storage, create=True, root=root)
    lock = storage / "selection.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and not info.st_mode & 0o077
                and (root != Path("/") or info.st_uid == 0),
                "unsafe selection lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _archive_existing(root, storage):
    source = where(root, legacy.VENVDIR)
    saved = storage / "original-venv"
    if not source.exists():
        return None
    _check_tree(source, root)
    require(not saved.exists() and not saved.is_symlink(),
            "rollback archive already exists")
    tmp = storage / (".original-venv-" + uuid.uuid4().hex)
    shutil.copytree(source, tmp, symlinks=True)
    _check_tree(tmp, root)
    require(_tree_digest(source) == _tree_digest(tmp),
            "rollback copy differs from original runtime")
    os.replace(tmp, saved)
    fd = os.open(storage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return str(saved)


def prepare(plan, release, *, root=Path("/"), runner=subprocess.run):
    """Install isolated venv and record digest; no unit selection."""
    require(bool(VERSION.fullmatch(release)), "invalid immutable release ID")
    root = Path(root).absolute()
    require(os.geteuid() == 0 or root != Path("/"), "root required on Host")
    approved = legacy.source_plan(
        host_deploy=plan["host_deploy_source"], host_install=plan["host_install_source"],
        root_control=plan["root_control_source"], box_control=plan["box_control_source"],
        image_build=plan["image_build_source"], python=plan["python"])
    require(approved == plan, "source selection changed")
    legacy._reviewed_dependency(plan["host_deploy_source"], HOST_DEPLOY_REVISION,
                                "host-deploy")
    _inactive(root, runner)
    base = where(root, BASE + "/versions")
    directory(base, create=True, root=root)
    version = base / release
    require(not version.exists() and not version.is_symlink(), "release already exists")
    version.mkdir(mode=0o700)
    venv = version / "venv"
    _run(runner, (plan["python"], "-m", "venv", str(venv)))
    executable = venv / "bin" / "python"
    require(executable.is_file(), "versioned Python missing")
    _run(runner, (executable, "-m", "pip", "install", "--no-cache-dir",
                  *(plan[k] for k in ("host_install_source", "host_deploy_source",
                                       "root_control_source", "box_control_source",
                                       "image_build_source"))))
    _run(runner, (executable, "-m", "pip", "check"))
    check = (
        "import hashlib, importlib, pathlib; "
        + "; ".join("importlib.import_module(" + repr(m) + ")"
                    for m in legacy.MODULES)
        + "; from zog.root_control import task_c_trusted_host as j"
        + "; p=pathlib.Path(j.__file__); data=p.read_bytes()"
        + "; h=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\\0'+data).hexdigest()"
        + "; assert h==" + repr(legacy.ROOT_CONTROL_JOURNAL_GIT_BLOB)
        + "; assert j.DEFAULT_DIRECTORY==" + repr(legacy.JOURNAL_DIR)
        + "; assert getattr(j,'LocalTaskCJournal',None) is not None"
    )
    _run(runner, (executable, "-I", "-c", check))
    _check_tree(version, root)
    receipt = {"schema": SCHEMA, "release": release,
               "tree_sha256": _tree_digest(venv),
               "gateway_sha256": hashlib.sha256(
                   (venv / "bin/host-deploy-gateway").read_bytes()).hexdigest(),
               "status": "prepared-not-selected", "activation_authorized": False}
    atomic(version / "preparation.json", json.dumps(receipt, sort_keys=True).encode())
    return receipt


def _unit_for(release):
    old = legacy._units()[legacy.UNITS[0]]
    original = (legacy.VENVDIR + "/bin/host-deploy-gateway").encode()
    replacement = (BASE + "/versions/" + release + "/venv/bin/host-deploy-gateway").encode()
    require(old.count(original) == 1, "unit execution contract changed")
    return old.replace(original, replacement)


def _select(release, *, root=Path("/"), runner=subprocess.run):
    require(bool(VERSION.fullmatch(release)), "invalid immutable release ID")
    root = Path(root).absolute()
    require(os.geteuid() == 0 or root != Path("/"), "root required on Host")
    _inactive(root, runner)
    runtime = where(root, BASE + "/versions/" + release + "/venv")
    _check_tree(runtime, root)
    gateway = runtime / "bin/host-deploy-gateway"
    require(gateway.is_file() and not gateway.is_symlink(), "versioned gateway missing")
    receipt = json.loads(regular(runtime.parent / "preparation.json", root=root))
    require(receipt.get("schema") == SCHEMA and receipt.get("release") == release
            and receipt.get("status") == "prepared-not-selected"
            and receipt.get("activation_authorized") is False
            and receipt.get("gateway_sha256") == hashlib.sha256(gateway.read_bytes()).hexdigest()
            and receipt.get("tree_sha256") == _tree_digest(runtime),
            "unverified versioned runtime preparation")
    unit = where(root, UNIT)
    previous = regular(unit, root=root)
    storage = where(root, ROLLBACK)
    directory(storage, create=True, root=root)
    status = storage / "selection.json"
    require(not status.exists() and not status.is_symlink(),
            "previous selection or interrupted switch requires explicit recovery")
    old_unit = storage / "previous-unit"
    require(not old_unit.exists() and not old_unit.is_symlink(),
            "previous unit already preserved")
    atomic(old_unit, previous)
    archived = _archive_existing(root, storage)
    candidate = _unit_for(release)
    transaction = {"schema": SCHEMA, "release": release,
                   "old_unit_sha256": hashlib.sha256(previous).hexdigest(),
                   "new_unit_sha256": hashlib.sha256(candidate).hexdigest(),
                   "original_venv_copy": archived, "status": "pending"}
    atomic(status, json.dumps(transaction, sort_keys=True).encode())
    try:
        _inactive(root, runner)
        require(regular(unit, root=root) == previous, "unit changed during staging")
        atomic(unit, candidate, mode=0o644)
        if root == Path("/"):
            _run(runner, ("/usr/bin/systemctl", "daemon-reload"))
        _inactive(root, runner)
    except Exception:
        atomic(unit, previous, mode=0o644)
        if root == Path("/"):
            _run(runner, ("/usr/bin/systemctl", "daemon-reload"))
        raise
    transaction["status"] = "selected"
    atomic(status, json.dumps(transaction, sort_keys=True).encode())
    return transaction


def _restore(*, root=Path("/"), runner=subprocess.run):
    root = Path(root).absolute()
    require(os.geteuid() == 0 or root != Path("/"), "root required on Host")
    _inactive(root, runner)
    storage = where(root, ROLLBACK)
    directory(storage, root=root)
    record = json.loads(regular(storage / "selection.json", root=root))
    require(record.get("schema") == SCHEMA and record.get("status") in
            ("selected", "pending"), "unknown rollback transaction")
    saved = regular(storage / "previous-unit", root=root)
    require(hashlib.sha256(saved).hexdigest() == record["old_unit_sha256"],
            "rollback unit bytes differ")
    unit = where(root, UNIT)
    current = regular(unit, root=root)
    require(hashlib.sha256(current).hexdigest() in
            (record["new_unit_sha256"], record["old_unit_sha256"]),
            "current unit differs from retained transaction")
    atomic(unit, saved, mode=0o644)
    if root == Path("/"):
        _run(runner, ("/usr/bin/systemctl", "daemon-reload"))
    _inactive(root, runner)
    record["status"] = "restored"
    atomic(storage / "selection.json", json.dumps(record, sort_keys=True).encode())
    return record


def select(release, *, root=Path("/"), runner=subprocess.run):
    root = Path(root).absolute()
    with _selection_lock(root):
        return _select(release, root=root, runner=runner)


def restore(*, root=Path("/"), runner=subprocess.run):
    root = Path(root).absolute()
    with _selection_lock(root):
        return _restore(root=root, runner=runner)
