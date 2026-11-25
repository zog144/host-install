"""Guarded atomic restoration of an original manifest-pinned source checkout."""
import ctypes
import fcntl
import os
from pathlib import Path
import re
import stat
from contextlib import contextmanager

from . import fonts_project_initialization as init
from . import fonts_project_migration as migration
from . import fonts_project_source_reconciliation as evidence


def _save_once(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    init._sync_directory(path.parent)


@contextmanager
def _locked(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600)
    try:
        st = os.fstat(fd)
        migration.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                          and stat.S_IMODE(st.st_mode) == 0o600
                          and st.st_uid == os.geteuid()
                          and st.st_gid == os.getegid(),
                          "unsafe source reconciliation lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        named = path.lstat()
        migration.require((st.st_dev, st.st_ino) == (named.st_dev, named.st_ino),
                          "source reconciliation lock inode differs")
        yield
    finally:
        os.close(fd)


def _exchange(source, staged):
    migration.require(evidence.private(source).st_dev ==
                      evidence.private(staged).st_dev,
                      "cross-filesystem source exchange refused")
    fn = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    migration.require(fn is not None, "Linux renameat2 required")
    fn.argtypes = (ctypes.c_int, ctypes.c_char_p,
                   ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    fn.restype = ctypes.c_int
    migration.require(fn(-100, os.fsencode(source), -100,
                         os.fsencode(staged), 2) == 0,
                      "atomic source exchange failed (errno " +
                      str(ctypes.get_errno()) + ")")


def restore(*, root=Path("/"), reviewed_checkout, expected_plan_sha256):
    root = Path(root).absolute()
    migration.require(type(expected_plan_sha256) is str and
                      re.fullmatch(r"[0-9a-f]{64}", expected_plan_sha256) is not None,
                      "independently reviewed recovery plan SHA required")
    if root == Path("/"):
        migration.require(os.geteuid() == 0, "native recovery requires administrator")
    target = migration._map(root, migration.NEW)
    pending = migration._map(root, evidence.PENDING)
    receipt = migration._map(root, evidence.RECEIPT)
    evidence.private(target.parent)
    with _locked(migration._map(root, evidence.LOCK)):
        plan = evidence.plan(root, reviewed_checkout)
        migration.require(plan["plan_sha256"] == expected_plan_sha256,
                          "recovery plan differs from independent approval")
        raw = init._canonical(plan) + b"\n"
        if receipt.exists() or receipt.is_symlink():
            migration.require(evidence.retained_file(receipt) == raw and
                              pending.is_dir() and not pending.is_symlink(),
                              "source recovery receipt/staging differs")
            migration.require(init._source(pending, "source") ==
                              plan["replacement_source"]["tree_sha256"],
                              "retained reviewed source staging differs")
        else:
            migration.require(not pending.exists() and not pending.is_symlink(),
                              "unknown partial recovery staging")
            checkout = Path(reviewed_checkout)
            inventory = migration._tree(checkout)
            migration._copy(checkout, pending, inventory)
            migration.require(init._source(pending, "source") ==
                              plan["replacement_source"]["tree_sha256"],
                              "source staging differs from manifest")
            migration._sync_tree(pending)
            _save_once(receipt, raw)  # Durable before any live source mutation.
        migration.require(evidence.plan(root, reviewed_checkout) == plan,
                          "source or state changed before publication")
        _exchange(target / "source", pending)
        init._sync_directory(target)
        init._sync_directory(target.parent)
        final = init._verify(root, target, "verify")
        state = evidence.private(target / "state")
        migration.require(final["manifest_sha256"] == plan["manifest_sha256"]
                          and evidence.source(pending, selected=True) ==
                              plan["observed_source"]
                          and [state.st_dev, state.st_ino] == plan["state_inode"]
                          and evidence.retained_file(receipt) == raw,
                          "restored source or historical state differs")
        return {"schema": evidence.SCHEMA, "action": "restore-reviewed-source",
                "plan_sha256": expected_plan_sha256,
                "manifest_sha256": final["manifest_sha256"],
                "restored_source_verified": True,
                "displaced_source_retained_at": evidence.PENDING,
                "original_manifest_preserved": True, "state_preserved": True,
                "compilation_authorized": False}
