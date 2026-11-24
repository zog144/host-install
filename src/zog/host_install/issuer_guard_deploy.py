"""Recoverable native issuer prestart helper replacement (not a Host activation).

The original 2026-10-23 guard remains captured byte-for-byte, while the
successor keeps every issuer snapshot and mount check. A new, root-owned
rollback record is create-only. Never update the original baseline.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

ORIGINAL_SHA256 = "990366a7e21dd89b1def0c1d9974c0e02586b8f5e2af32efa49874d926589d78"
SUCCESSOR_SHA256 = "313cb4d644b259ece175adea24f030d36c851c753f547288aad21359a8db686e"
POLICY_SHA256 = "26c286dc72d772b68dd7a942ba08a77d900b9ac844f9401bd7c642ffda729a38"
BASE = Path("/opt/zog/host-install-issuer-persistence-20261023")
ROLLBACK = Path("/opt/zog/compiler-runtime/issuer-helper-rollback-20261123")
SERVICE = "zog-certbot-seed-root.service"
UNIT = Path("/etc/systemd/system") / SERVICE
ORIGINAL_FILE = "issuer_guard_original_20261023.py"
REPLACEMENT_FILE = "issuer_guard_successor.py"
POLICY_FILE = "compiler_issuer_persistence_binding.py"


class HelperDeploymentHold(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise HelperDeploymentHold(message)


def _host(root, path):
    return Path(root) / Path(path).relative_to("/")


def _read(root, file, *, expected_mode=None):
    file = Path(file)
    require(file.is_absolute() and ".." not in file.parts,
            "issuer helper path is not absolute")
    parents = list(reversed(file.parents))
    for parent in parents:
        if not parent.exists():
            raise HelperDeploymentHold("issuer helper parent missing: " + str(parent))
        st = parent.lstat()
        require(stat.S_ISDIR(st.st_mode)
                and (root != Path("/") or (
                    not (st.st_mode & 0o022) and st.st_uid == st.st_gid == 0)),
                "issuer helper parent path is unsafe")
    st = file.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
            and not (st.st_mode & 0o022)
            and (root != Path("/") or st.st_uid == st.st_gid == 0)
            and (expected_mode is None or stat.S_IMODE(st.st_mode) == expected_mode),
            "issuer helper file ownership, mode or link differs")
    raw = file.read_bytes()
    require(len(raw) == st.st_size, "issuer helper file size changed")
    return raw


def _fsync(directory):
    fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _exclusive(file, content, mode):
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        _fsync(file.parent)
    except BaseException:
        try:
            file.unlink()
        except FileNotFoundError:
            pass
        raise


def _atomic(file, content, mode):
    temporary = file.with_name("." + file.name + "." + uuid.uuid4().hex)
    _exclusive(temporary, content, mode)
    try:
        os.replace(temporary, file)
        _fsync(file.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _sha(content):
    return hashlib.sha256(content).hexdigest()


def _source_file(name):
    path = Path(__file__).with_name(name)
    require(path.is_file() and not path.is_symlink(),
            "reviewed helper source missing: " + name)
    return path.read_bytes()


def _source_tuple():
    original = _source_file(ORIGINAL_FILE)
    successor = _source_file(REPLACEMENT_FILE)
    policy = _source_file(POLICY_FILE)
    require(len(original) == 3853 and _sha(original) == ORIGINAL_SHA256,
            "recovered original guard source does not match native evidence")
    require(_sha(successor) == SUCCESSOR_SHA256 and
            _sha(policy) == POLICY_SHA256,
            "reviewed issuer helper source or binding SHA-256 differs")
    return original, successor, policy


def _inactive(root, runner):
    """Require a loaded, stopped *specific* unit with no systemd job.

    `is-active` exit codes cannot distinguish missing units and transitional
    states. Read the manager's exact unit properties and deny any ambiguity.
    """
    if root != Path("/"):
        return  # Non-native fixture root: no systemd in disposable source CI.
    require(os.geteuid() == os.getegid() == 0, "helper installation requires root")
    response = runner([
        "/usr/bin/systemctl", "--no-pager", "--all", "show",
        "--property=Id,LoadState,ActiveState,SubState,Job", SERVICE,
    ], check=False, capture_output=True, text=True)
    require(response.returncode == 0, "systemd issuer unit status unavailable")
    require(type(response.stdout) is str, "invalid systemd issuer unit status")
    props = {}
    for line in response.stdout.splitlines():
        key, sep, value = line.partition("=")
        require(sep == "=" and key in
                ("Id", "LoadState", "ActiveState", "SubState", "Job")
                and key not in props, "malformed or duplicate systemd unit property")
        props[key] = value
    require(set(props) == {"Id", "LoadState", "ActiveState", "SubState", "Job"},
            "incomplete systemd issuer unit status")
    require(props["Id"] == SERVICE and props["LoadState"] == "loaded",
            "expected issuer controller unit is not loaded")
    require(props["ActiveState"] == "inactive" and props["SubState"] == "dead",
            "issuer controller must be fully stopped for helper replacement")
    # systemd 252 prints Job= for the zero-ID D-Bus job when --all is set;
    # also accept an explicit numeric zero. Reject every nonzero job ID.
    require(props["Job"] in ("0", ""),
            "issuer controller has an enqueued systemd job")


def _record(root):
    file = _host(root, ROLLBACK / "record.json")
    value = json.loads(_read(root, file, expected_mode=0o600))
    require(value.get("schema") == "zog-issuer-helper-replacement-v1"
            and value.get("original_sha256") == ORIGINAL_SHA256
            and value.get("service") == SERVICE,
            "issuer helper rollback metadata differs")
    return value


def _baseline_original_unit(root):
    baseline = json.loads(_read(root, _host(root, BASE / "baseline.json")))
    require(type(baseline) is dict and type(baseline.get("hashes")) is dict
            and type(baseline["hashes"].get(str(UNIT))) is str,
            "original issuer unit baseline is missing")
    actual = _read(root, _host(root, UNIT))
    require(_sha(actual) == baseline["hashes"][str(UNIT)],
            "original issuer unit has not been restored")
    return baseline


def _no_incomplete_compiler_transaction(root):
    backup = _host(root, Path("/opt/zog/compiler-runtime/rollback"))
    if not backup.exists():
        require(not backup.is_symlink(), "unsafe compiler transaction root")
        return
    require(backup.is_dir() and not backup.is_symlink(),
            "unsafe compiler transaction root")
    for directory in sorted(backup.iterdir()):
        if len(directory.name) not in (32, 64) or any(
                c not in "0123456789abcdef" for c in directory.name):
            continue
        require(directory.is_dir() and not directory.is_symlink(),
                "unsafe compiler release directory")
        item = directory / "selection-transaction.json"
        if not item.exists() and not item.is_symlink():
            continue
        tx = json.loads(_read(root, item, expected_mode=0o600))
        if tx.get("service") == SERVICE:
            require(tx.get("state") in ("restored", "aborted"),
                    "incomplete compiler selection prevents original helper rollback")


def _restage_after_restore(root, runner, directory, baseline, original,
                           successor, policy):
    """Rearm an existing restored helper without rewriting rollback evidence.

    Keep the immutable original helper and staged source copies, and retain
    each previous restored record as a create-only, fsynced receipt. Retrying
    after an interruption between receipt creation and record replacement is
    safe because the same saved record must match.
    """
    require(directory.is_dir() and not directory.is_symlink(),
            "issuer helper rollback directory is unsafe")
    prior_raw = _read(root, directory / "record.json", expected_mode=0o600)
    record, saved_original, saved_successor, saved_policy = _validate_staging(root)
    require(record.get("state") == "restored",
            "existing issuer helper rollback is not restored")
    require(saved_original == original and saved_successor == successor
            and saved_policy == policy,
            "restored helper source or protected rollback differs")
    require(record["baseline_sha256"] == _sha(baseline),
            "restored issuer baseline differs from protected rollback")
    installed_policy = _host(root, BASE / POLICY_FILE)
    require(not installed_policy.exists() and not installed_policy.is_symlink(),
            "issuer policy remains installed after restoration")
    _no_incomplete_compiler_transaction(root)
    count = record.get("restage_count", 0)
    require(type(count) is int and 0 <= count < 999999,
            "invalid issuer helper restage counter")
    receipt = directory / f"restored-before-restage-{count + 1:06d}.json"
    if receipt.exists() or receipt.is_symlink():
        require(_read(root, receipt, expected_mode=0o400) == prior_raw,
                "restored issuer history conflicts with protected record")
    else:
        _inactive(root, runner)
        _exclusive(receipt, prior_raw, 0o400)
    # The rollback copy, saved successor/policy and every historical receipt
    # remain untouched. Only the mutable state pointer is advanced atomically.
    _inactive(root, runner)
    record["state"] = "staged"
    record["restage_count"] = count + 1
    _atomic(directory / "record.json",
            (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)
    return record


def stage(*, root=Path("/"), runner=subprocess.run):
    """Create a recoverable original-helper copy, never replace live helper."""
    root = Path(root).absolute()
    _inactive(root, runner)
    source_original, source_new, source_policy = _source_tuple()
    existing = _read(root, _host(root, BASE / "guard.py"), expected_mode=0o444)
    require(existing == source_original and _sha(existing) == ORIGINAL_SHA256,
            "installed original guard is not the independently recovered file")
    baseline = _read(root, _host(root, BASE / "baseline.json"))
    _baseline_original_unit(root)
    directory = _host(root, ROLLBACK)
    if directory.exists() or directory.is_symlink():
        return _restage_after_restore(
            root, runner, directory, baseline, source_original,
            source_new, source_policy)
    require(directory.parent.is_dir() and not directory.parent.is_symlink(),
            "issuer rollback parent missing or unsafe")
    if root == Path("/"):
        _read(root, _host(root, BASE / "guard.py"), expected_mode=0o444)
    directory.mkdir(mode=0o700)
    _fsync(directory.parent)
    _exclusive(directory / "original-guard.py", existing, 0o400)
    _exclusive(directory / "approved-successor.py", source_new, 0o400)
    _exclusive(directory / "approved-binding.py", source_policy, 0o400)
    record = {
        "schema": "zog-issuer-helper-replacement-v1",
        "service": SERVICE,
        "original_sha256": ORIGINAL_SHA256,
        "replacement_sha256": _sha(source_new),
        "policy_sha256": _sha(source_policy),
        "baseline_sha256": _sha(baseline),
        "state": "staged",
        "native_issuer_accepted": False,
    }
    _exclusive(directory / "record.json", (json.dumps(record, sort_keys=True)+"\n").encode(), 0o600)
    return record


def _validate_staging(root):
    record = _record(root)
    original, new, policy = _source_tuple()
    directory = _host(root, ROLLBACK)
    require(_read(root, directory / "original-guard.py", expected_mode=0o400) == original
            and _read(root, directory / "approved-successor.py", expected_mode=0o400) == new
            and _read(root, directory / "approved-binding.py", expected_mode=0o400) == policy,
            "staged issuer helper source or original rollback differs")
    require(record["replacement_sha256"] == _sha(new)
            and record["policy_sha256"] == _sha(policy)
            and record["baseline_sha256"] == _sha(_read(root, _host(root, BASE / "baseline.json"))),
            "staged issuer helper hashes or preserved baseline differ")
    return record, original, new, policy


def activate(*, root=Path("/"), runner=subprocess.run):
    """Switch helper only, retaining old helper; never starts the service."""
    root = Path(root).absolute()
    _inactive(root, runner)
    record, original, new, policy = _validate_staging(root)
    require(record["state"] in ("staged", "active"),
            "issuer helper is not in a selectable state")
    live = _host(root, BASE / "guard.py")
    existing = _read(root, live, expected_mode=0o444)
    require(existing in (original, new),
            "unknown installed issuer helper, refusing replacement")
    installed_policy = _host(root, BASE / POLICY_FILE)
    if installed_policy.exists() or installed_policy.is_symlink():
        require(_read(root, installed_policy, expected_mode=0o444) == policy,
                "installed issuer policy differs")
    else:
        _exclusive(installed_policy, policy, 0o444)
    require(_read(root, installed_policy, expected_mode=0o444) == policy,
            "issuer policy did not survive installation")
    if existing == original:
        _inactive(root, runner)  # Recheck after staging, immediately before swap.
        _atomic(live, new, 0o444)
    require(_read(root, live, expected_mode=0o444) == new,
            "installed issuer helper differs from reviewed successor")
    record["state"] = "active"
    _atomic(_host(root, ROLLBACK / "record.json"),
            (json.dumps(record, sort_keys=True)+"\n").encode(), 0o600)
    return record


def restore(*, root=Path("/"), runner=subprocess.run):
    """Restore original helper ONLY after original main unit is restored."""
    root = Path(root).absolute()
    _inactive(root, runner)
    record, original, new, policy = _validate_staging(root)
    _baseline_original_unit(root)
    _no_incomplete_compiler_transaction(root)
    live = _host(root, BASE / "guard.py")
    existing = _read(root, live, expected_mode=0o444)
    require(existing in (original, new), "unreviewed helper cannot be restored")
    if existing == new:
        _inactive(root, runner)  # Recheck immediately before restoring old code.
        _atomic(live, original, 0o444)
    require(_read(root, live, expected_mode=0o444) == original,
            "original issuer helper was not restored")
    policy_path = _host(root, BASE / POLICY_FILE)
    if policy_path.exists() or policy_path.is_symlink():
        require(_read(root, policy_path, expected_mode=0o444) == policy,
                "issuer policy no longer matches protected copy")
        policy_path.unlink()
        _fsync(policy_path.parent)
    record["state"] = "restored"
    _atomic(_host(root, ROLLBACK / "record.json"),
            (json.dumps(record, sort_keys=True)+"\n").encode(), 0o600)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reversible issuer helper replacement")
    parser.add_argument("operation", choices=("stage", "activate", "restore"))
    args = parser.parse_args(argv)
    operation = {"stage": stage, "activate": activate, "restore": restore}[args.operation]
    print(json.dumps(operation(), sort_keys=True))


if __name__ == "__main__":
    main()
