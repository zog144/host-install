"""Guarded atomic restoration of an original manifest-pinned source checkout."""
import ctypes
import json
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
        try:
            named = path.lstat()
            migration.require((st.st_dev, st.st_ino) ==
                              (named.st_dev, named.st_ino)
                              and named.st_nlink == 1
                              and stat.S_IMODE(named.st_mode) == 0o600,
                              "source reconciliation lock replaced during operation")
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



def _verify_recovery_unlocked(root, expected_plan_sha256):
    """Inspect the *completed exchange*, including displaced history.

    This does not require the original external reviewed checkout: durable
    immutable plan, original manifest, restored source and displaced source
    must all authenticate independently. It never repairs, stages or swaps.
    """
    migration.require(type(expected_plan_sha256) is str and
                      re.fullmatch(r"[0-9a-f]{64}", expected_plan_sha256) is not None,
                      "independently reviewed recovery plan SHA required")
    target = migration._map(root, migration.NEW)
    pending = migration._map(root, evidence.PENDING)
    receipt = migration._map(root, evidence.RECEIPT)
    migration._parents_secure(root, migration.NEW, require_leaf=True)
    evidence.private(target.parent)
    project = evidence.private(target)
    state = evidence.private(target / "state")
    evidence.private(pending)
    original_raw = evidence.retained_file(receipt)
    try:
        plan = json.loads(original_raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise migration.MigrationHold("invalid durable source recovery receipt") from error
    expected_keys = {"schema", "project", "manifest_sha256",
                     "manifest_raw_sha256", "observed_source",
                     "replacement_source", "reviewed_checkout",
                     "project_inode", "state_inode", "layout_missing",
                     "manifest_replaced", "compilation_authorized", "plan_sha256"}
    migration.require(type(plan) is dict and set(plan) == expected_keys
                      and original_raw == init._canonical(plan) + b"\n"
                      and plan["schema"] == evidence.SCHEMA
                      and plan["project"] == migration.NEW
                      and plan["manifest_replaced"] is False
                      and plan["compilation_authorized"] is False
                      and type(plan["reviewed_checkout"]) is str
                      and Path(plan["reviewed_checkout"]).is_absolute()
                      and plan["plan_sha256"] == expected_plan_sha256,
                      "durable recovery receipt differs from approved plan")
    body = {k: v for k, v in plan.items() if k != "plan_sha256"}
    migration.require(evidence.sha(init._canonical(body)) == expected_plan_sha256,
                      "durable recovery plan digest differs")
    migration.require(plan["project_inode"] == [project.st_dev, project.st_ino]
                      and plan["state_inode"] == [state.st_dev, state.st_ino],
                      "prepared Project or retained state identity differs")
    entries = set(os.listdir(target))
    migration.require({"source", "companions", "state", init.MANIFEST} <= entries
                      and entries <= {"source", "companions", "state",
                                      init.MANIFEST, *init.LAYOUT_DIRECTORIES},
                      "unexpected post-exchange Project contents")
    manifest_raw = evidence.retained_file(target / init.MANIFEST)
    manifest = init._manifest(target)
    migration.require(manifest_raw == init._canonical(manifest) + b"\n"
                      and evidence.sha(manifest_raw) ==
                          plan["manifest_raw_sha256"]
                      and evidence.sha(init._canonical(manifest)) ==
                          plan["manifest_sha256"]
                      and type(manifest.get("source_tree_sha256")) is dict
                      and set(manifest["source_tree_sha256"]) ==
                          set(init.SOURCES),
                      "restored Project manifest differs from original record")
    migration.require(type(plan["layout_missing"]) is list
                      and init._layout(target)["missing"] ==
                          plan["layout_missing"],
                      "restored Project runtime layout differs")
    original = plan["observed_source"]
    replacement = plan["replacement_source"]
    required_source = {"revision", "repository", "tree_sha256",
                       "physical_tree_sha256", "physical_entries"}
    migration.require(type(original) is dict and type(replacement) is dict
                      and set(original) == required_source
                      and set(replacement) == required_source
                      and original != replacement
                      and replacement["repository"] == init.SOURCES["source"][0]
                      and replacement["revision"] == init.SOURCES["source"][1]
                      and replacement["tree_sha256"] ==
                          manifest["source_tree_sha256"]["source"],
                      "recorded original and displaced source identities differ")
    final = init._verify(root, target, "verify")
    migration.require(final["manifest_sha256"] == plan["manifest_sha256"]
                      and final["source_tree_sha256"] ==
                          manifest["source_tree_sha256"]
                      and final["controllers_present"] == []
                      and final["compilation_authorized"] is False,
                      "restored original initializer verification differs")
    migration.require(evidence.source(target / "source", selected=True) == replacement,
                      "restored physical source differs from approved replacement")
    migration.require(evidence.source(pending, selected=True) == original,
                      "displaced physical source differs from approved history")
    migration.require(evidence.retained_file(receipt) == original_raw
                      and evidence.retained_file(target / init.MANIFEST) ==
                          manifest_raw,
                      "recovery receipt or original manifest changed during readback")
    latest_state = evidence.private(target / "state")
    migration.require([latest_state.st_dev, latest_state.st_ino] ==
                      plan["state_inode"],
                      "restored Project state changed during verification")
    return {"schema": evidence.SCHEMA, "action": "verify-recovery",
            "plan_sha256": expected_plan_sha256,
            "manifest_sha256": plan["manifest_sha256"],
            "recovered_source_verified": True,
            "displaced_source_verified": True,
            "receipt_verified": True, "state_inode_preserved": True,
            "displaced_source_retained_at": evidence.PENDING,
            "compilation_authorized": False, "mutation": False}


def verify_recovery(*, root=Path("/"), expected_plan_sha256):
    """Read-only CLI/API for a completed or interrupted-after-swap restore."""
    root = Path(root).absolute()
    lock = migration._map(root, evidence.LOCK)
    # Never create a lock or partial state in the *read-only* verifier.
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        migration.require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                          and stat.S_IMODE(st.st_mode) == 0o600
                          and st.st_uid == os.geteuid()
                          and st.st_gid == os.getegid(),
                          "read-only recovery lock custody differs")
        fcntl.flock(fd, fcntl.LOCK_SH)
        named = lock.lstat()
        migration.require((named.st_dev, named.st_ino) ==
                          (st.st_dev, st.st_ino),
                          "read-only recovery lock was replaced")
        result = _verify_recovery_unlocked(root, expected_plan_sha256)
        named = lock.lstat()
        migration.require((named.st_dev, named.st_ino) ==
                          (st.st_dev, st.st_ino),
                          "read-only recovery lock changed after observation")
        return result
    finally:
        os.close(fd)


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
        # The receipt-backed staging check above uses the historical
        # initializer's Git-only verifier. That is insufficient to protect
        # the atomic exchange from ignored files or unreviewed Git metadata.
        # Apply the complete reviewed physical inventory gate to BOTH new
        # staging and resumed staging before any live source replacement.
        migration.require(
            evidence.source(pending, selected=True) ==
                plan["replacement_source"],
            "staged source physical inventory differs before exchange")
        migration.require(
            evidence.source(target / "source", selected=True) ==
                plan["observed_source"],
            "selected source physical inventory changed before exchange")
        _exchange(target / "source", pending)
        init._sync_directory(target)
        init._sync_directory(target.parent)
        verified = _verify_recovery_unlocked(root, expected_plan_sha256)
        return {**verified, "action": "restore-reviewed-source",
                "restored_source_verified": True,
                "original_manifest_preserved": True, "state_preserved": True}
