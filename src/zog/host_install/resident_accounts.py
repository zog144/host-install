"""Offline resident-HOST service account materialization before rootfs publication.

Only the upstream systemd 261.2 and D-Bus 1.16.2 sysusers.d declarations
are selected. Existing root/Zog accounts remain unchanged. No compiler
account, personal login, UID selector, Host enrollment or running service.
The caller passes an *unpublished* assembled rootfs directory; never apply
to the live root or to an accepted immutable generation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

SCHEMA = "zog-host-install-resident-service-accounts-v1"
VENDOR = (
    ("usr/lib/sysusers.d/systemd-journal.conf", "g", "systemd-journal"),
    ("usr/lib/sysusers.d/dbus.conf", "u", "messagebus"),
)
PASSWD = "etc/passwd"
GROUP = "etc/group"
FORBIDDEN = frozenset(("certbot-build-owner", "certbot-build-worker"))


class AccountMaterializationHold(RuntimeError):
    """The offline root must be inspected, not changed automatically."""


def _require(condition, message):
    if not condition:
        raise AccountMaterializationHold(message)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _secure_path(path):
    path = Path(path).absolute()
    _require(path != Path("/") and path.is_absolute(),
             "resident accounts may not target live root")
    parts = [path, *path.parents]
    for directory in parts:
        st = directory.lstat()
        _require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
                 "rootfs path ancestry must contain no links: " + str(directory))
    return path


def _regular(root, relative, *, limit=1048576):
    """Open only ordinary files with no symlink/foreign ancestry."""
    current = root
    components = Path(relative).parts
    _require(len(components) > 0 and all(x not in (".", "..") for x in components),
             "invalid resident file path")
    for name in components[:-1]:
        current = current / name
        st = current.lstat()
        _require(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode),
                 "resident file parent is absent or linked: " + relative)
    leaf = current / components[-1]
    st = leaf.lstat()
    _require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
             and not stat.S_ISLNK(st.st_mode),
             "resident file is missing, linked or not regular: " + relative)
    _require(not stat.S_IMODE(st.st_mode) & 0o022,
             "resident file is group/world-writable: " + relative)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(leaf, flags)
    try:
        observed = os.fstat(fd)
        _require((observed.st_dev, observed.st_ino) == (st.st_dev, st.st_ino)
                 and observed.st_size <= limit,
                 "resident file changed or is too large: " + relative)
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            data = stream.read(limit + 1)
        _require(len(data) <= limit, "resident file too large: " + relative)
        return data
    finally:
        if fd >= 0:
            os.close(fd)


def _database(raw, kind):
    """Require clean unique named records and unique numeric IDs."""
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AccountMaterializationHold("invalid resident " + kind + " encoding") from exc
    by_name, by_id = {}, {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        columns = line.split(":")
        _require(len(columns) == (7 if kind == "passwd" else 4),
                 "malformed resident " + kind + " line")
        name = columns[0]
        _require(re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", name) is not None
                 and name not in by_name,
                 "duplicate or invalid resident " + kind + " name")
        try:
            ident = int(columns[2])
        except ValueError as exc:
            raise AccountMaterializationHold("non-numeric resident " + kind + " identity") from exc
        _require(ident >= 0 and ident not in by_id,
                 "duplicate/invalid numeric identity in resident " + kind)
        by_name[name] = line
        by_id[ident] = name
    _require("root" in by_name and by_name["root"].split(":")[2] == "0",
             "fixed resident root identity is absent or changed in " + kind)
    _require(not (FORBIDDEN & by_name.keys()),
             "rejected dedicated compiler accounts present in resident " + kind)
    return by_name


def _declarations(root):
    result = {}
    for path, kind, name in VENDOR:
        data = _regular(root, path, limit=16384)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AccountMaterializationHold("non-UTF8 vendor sysusers fragment") from exc
        entries = []
        for row in text.splitlines():
            stripped = row.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                columns = shlex.split(stripped, comments=True)
            except ValueError as exc:
                raise AccountMaterializationHold("invalid upstream sysusers syntax") from exc
            if columns:
                entries.append(columns)
        _require(len(entries) == 1 and len(entries[0]) >= 3
                 and entries[0][:3] == [kind, name, "-"],
                 "vendor sysusers directive differs from reviewed resident service")
        result[name] = {"fragment": "/" + path, "kind": kind,
                        "declaration_sha256": _digest(data)}
    return result


def _read(root):
    _require((root / "usr/lib/os-release").is_file()
             and not (root / "usr/lib/os-release").is_symlink(),
             "unpublished Zog resident OS-tree marker missing")
    _require((root / "usr/lib/systemd/systemd").is_file(),
             "resident systemd executable is absent")
    _require((root / "usr/bin/dbus-daemon").is_file(),
             "resident D-Bus executable is absent")
    passwd_raw = _regular(root, PASSWD)
    group_raw = _regular(root, GROUP)
    users = _database(passwd_raw, "passwd")
    groups = _database(group_raw, "group")
    declarations = _declarations(root)
    return {
        "users": users, "groups": groups, "declarations": declarations,
        "passwd_sha256": _digest(passwd_raw),
        "group_sha256": _digest(group_raw),
    }


def _verified(snapshot):
    users, groups = snapshot["users"], snapshot["groups"]
    _require("systemd-journal" in groups,
             "systemd-journal group is not materialized")
    _require("messagebus" in users and "messagebus" in groups,
             "messagebus user and primary group are not materialized")
    account = users["messagebus"].split(":")
    group = groups["messagebus"].split(":")
    _require(account[3] == group[2] and account[2] != "0"
             and account[3] != "0" and account[1] == "x"
             and account[6].endswith("/nologin"),
             "messagebus service identity must be non-root and non-login")
    _require(groups["systemd-journal"].split(":")[2] != "0",
             "systemd-journal cannot have root group ID")


def _executable(path):
    _require(type(path) is str and path.startswith("/"),
             "explicit absolute systemd-sysusers executable required")
    executable = Path(path).resolve(strict=True)
    st = executable.stat()
    _require(stat.S_ISREG(st.st_mode) and st.st_uid == 0
             and not stat.S_IMODE(st.st_mode) & 0o022
             and bool(stat.S_IMODE(st.st_mode) & 0o111),
             "systemd-sysusers executable must be an OS-managed root-owned binary")
    return executable


def operation(action, root, *, sysusers_executable=None):
    """A staged-root-only materializer, never a live Host account operation."""
    _require(action in ("inspect", "materialize", "verify"),
             "unsupported resident account operation")
    root = _secure_path(root)
    before = _read(root)
    result = {
        "schema": SCHEMA,
        "action": action,
        "rootfs": str(root),
        "vendor_declarations": before["declarations"],
        "before": {
            "passwd_sha256": before["passwd_sha256"],
            "group_sha256": before["group_sha256"],
            "systemd_journal_group": "systemd-journal" in before["groups"],
            "messagebus_user": "messagebus" in before["users"],
            "messagebus_group": "messagebus" in before["groups"],
        },
        "native_boot_accepted": False,
        "generation_published": False,
        "account_selection": False,
        "compiler_users_created": False,
    }
    if action == "inspect":
        result["materialized"] = all((
            "systemd-journal" in before["groups"],
            "messagebus" in before["users"],
            "messagebus" in before["groups"]))
        return result
    if action == "verify":
        _verified(before)
        result["materialized"] = True
        return result

    binary = _executable(sysusers_executable)
    _require(os.access(root / "etc", os.W_OK | os.X_OK, effective_ids=True),
             "unpublished resident account database is not writable")
    # Only the two named vendor fragments; never run default/global sysusers
    # fragments, never pass any compiler or account-selection data.
    cmd = [str(binary), "--root=" + str(root),
           *(fragment for fragment, _, _ in (
               ("/" + rel, kind, name) for rel, kind, name in VENDOR))]
    try:
        run = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=45,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_OFFLINE": "1"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AccountMaterializationHold("offline systemd-sysusers invocation failed") from exc
    _require(run.returncode == 0, "offline systemd-sysusers did not complete: " +
             run.stderr[-1024:])
    after = _read(root)
    _verified(after)
    _require(all(after["users"].get(name) == line for name, line in before["users"].items())
             and all(after["groups"].get(name) == line for name, line in before["groups"].items()),
             "existing resident accounts/groups were changed")
    _require(set(after["users"]) - set(before["users"]) <= {"messagebus"}
             and set(after["groups"]) - set(before["groups"]) <= {
                 "systemd-journal", "messagebus"},
             "offline sysusers created an unapproved additional account/group")
    _require(after["declarations"] == before["declarations"],
             "upstream sysusers declarations changed during materialization")
    result["materialized"] = True
    result["after"] = {
        "passwd_sha256": after["passwd_sha256"],
        "group_sha256": after["group_sha256"],
        "created_users": sorted(set(after["users"]) - set(before["users"])),
        "created_groups": sorted(set(after["groups"]) - set(before["groups"])),
        "messagebus_uid": int(after["users"]["messagebus"].split(":")[2]),
        "messagebus_gid": int(after["users"]["messagebus"].split(":")[3]),
        "systemd_journal_gid": int(after["groups"]["systemd-journal"].split(":")[2]),
        "all_preexisting_records_preserved": True,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    for name in ("inspect", "materialize", "verify"):
        action.add_argument("--" + name, action="store_true")
    parser.add_argument("--root", type=Path, required=True,
                        help="separate unpublished mounted/staged Zog rootfs; never /")
    parser.add_argument("--sysusers-executable",
                        help="existing OS-managed binary; required for --materialize")
    args = parser.parse_args(argv)
    selected = next(name for name in ("inspect", "materialize", "verify")
                    if getattr(args, name))
    if selected == "materialize" and not args.sysusers_executable:
        parser.error("--materialize requires --sysusers-executable")
    print(json.dumps(operation(selected, args.root,
                               sysusers_executable=args.sysusers_executable),
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
