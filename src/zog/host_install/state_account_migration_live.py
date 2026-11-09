"""Read-only Linux evidence for first registry directory-STATE migration.

No key bytes are opened here. Live evidence comes from independently opened
original Host descriptors, NSS, mounted root and effective systemd properties.
"""
import grp
import os
import pwd
import re
import stat
import subprocess
import hashlib
from pathlib import Path

from .state_account_migration import ALLOWED_IDENTITY_FILES, REQUIRED_IDENTITY_FILES
from .state_account_migration_completion import open_original_legacy_identity_fd
from .state_account_migration_admission import (
    CANDIDATE_EXECUTABLE, CANDIDATE_PYTHON, select_runtime,
)
from .state_account_migration_consumer import CONSUMER_SELECTION
from .state_contract import decode, digest, require
from .state_inspect import mounts, topology

OLD_EXE = ("/opt/host-discover/releases/"
           "registries-deployments-0.3.3-20260927/venv/bin/host-discover")
ENTRY_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


def _read_file(path, size_limit=65536):
    """Open through root-owned non-writable non-symlink ancestors."""
    segments = path.strip("/").split("/")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in segments[:-1]:
            s = os.fstat(fd)
            require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and
                    not s.st_mode & 0o022, "migration-input", "unsafe ancestor")
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                          os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        s = os.fstat(fd)
        require(s.st_uid == 0 and not s.st_mode & 0o022,
                "migration-input", "unsafe input parent")
        opened = os.open(segments[-1], os.O_RDONLY | os.O_NOFOLLOW |
                         os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(opened)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == 0 and not before.st_mode & 0o022
                    and 0 < before.st_size <= size_limit,
                    "migration-input", "unsafe source file")
            raw = os.read(opened, size_limit + 1)
            after = os.fstat(opened)
            require(len(raw) == before.st_size and
                    (before.st_dev, before.st_ino, before.st_mtime_ns) ==
                    (after.st_dev, after.st_ino, after.st_mtime_ns),
                    "migration-input", "changed file during read")
            return raw
        finally:
            os.close(opened)
    finally:
        os.close(fd)


def _systemctl(*args):
    proc = subprocess.run(("/usr/bin/systemctl", *args),
                          check=False, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=20,
                          env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    require(proc.returncode == 0 and 0 < len(proc.stdout) <= 65536,
            "migration-systemd", "systemd effective observation unavailable")
    return proc.stdout.decode("utf-8", "strict").strip()


def _service():
    fields = ("ActiveState", "UnitFileState", "User", "Group",
              "SupplementaryGroups", "ReadWritePaths", "DropInPaths",
              "ExecStart", "NeedDaemonReload")
    values = {name: _systemctl("show", "host-discover.service",
                               "--property=" + name, "--value")
              for name in fields}
    require(values["ActiveState"] == "active"
            and values["UnitFileState"] == "enabled"
            and values["User"] == values["Group"] == "host-discover"
            and values["SupplementaryGroups"] == "archive-consumers"
            and values["DropInPaths"] == ""
            and values["NeedDaemonReload"] == "no"
            and OLD_EXE in values["ExecStart"]
            and all(path in values["ReadWritePaths"] for path in
                    ("/var/lib/host-discover/identity",
                     "/var/lib/host-discover/credentials")),
            "migration-systemd", "retained service selection changed")
    return (_systemctl("cat", "host-discover.service").encode("utf-8"),
            {"active": True, "enabled": True})


def _accounts():
    users = {}
    members = grp.getgrall()
    people = pwd.getpwall()
    for u in people:
        if u.pw_name in ("host-discover", "box-control"):
            users[u.pw_name] = dict(
                uid=u.pw_uid, gid=u.pw_gid, home=u.pw_dir, shell=u.pw_shell,
                groups=sorted(g.gr_name for g in members
                              if u.pw_name in g.gr_mem))
    return {
        "users": users,
        "groups": {g.gr_name: g.gr_gid for g in members
                   if g.gr_name in ("host-discover", "archive-consumers",
                                     "host-control", "box-control")},
        "uid_index": {str(u.pw_uid): u.pw_name for u in people},
        "gid_index": {str(g.gr_gid): g.gr_name for g in members},
    }


def _stat_entry(directory_fd, name, uid, gid, mode, device):
    fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                and (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) ==
                    (uid, gid, mode) and st.st_dev == device,
                "migration-inventory", "legacy entry substituted")
        return st
    finally:
        os.close(fd)


def _inventory(identity_fd, device):
    names = set(os.listdir(identity_fd))
    require(REQUIRED_IDENTITY_FILES <= names and
            names <= ALLOWED_IDENTITY_FILES,
            "migration-inventory", "unexpected original identity name")
    files = {}
    identity_inodes = {
        "directory": [os.fstat(identity_fd).st_dev,
                      os.fstat(identity_fd).st_ino],
    }
    for name in sorted(ALLOWED_IDENTITY_FILES):
        if name not in names:
            files[name] = None
            continue
        s = _stat_entry(identity_fd, name, 991, 991, 0o600, device)
        require(s.st_size <= 32768, "migration-inventory", "oversized identity file")
        files[name] = dict(kind="file", uid=991, gid=991, mode=0o600,
                           links=1, dev=s.st_dev, inode=s.st_ino)
        identity_inodes[name] = [s.st_dev, s.st_ino]
    parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW, dir_fd=identity_fd)
    try:
        st = os.fstat(parent)
        require(st.st_uid == 0 and not st.st_mode & 0o022
                and st.st_dev == device, "migration-inventory",
                "untrusted legacy directory parent")
        credfd = os.open("credentials", os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW, dir_fd=parent)
        try:
            st = os.fstat(credfd)
            require((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) ==
                    (991, 990, 0o750) and st.st_dev == device,
                    "migration-inventory", "credential directory changed")
            names = os.listdir(credfd)
            require(0 < len(names) <= 128 and len(names) == len(set(names)),
                    "migration-inventory", "closed original credentials required")
            credential_inodes, credential_files = {}, {}
            for name in names:
                require(ENTRY_NAME.fullmatch(name) and name not in (".", ".."),
                        "migration-inventory", "unselected credential name")
                info = _stat_entry(credfd, name, 991, 990, 0o640, device)
                credential_inodes[name] = [info.st_dev, info.st_ino]
                credential_files[name] = dict(kind="file", uid=991, gid=990,
                                              mode=0o640, links=1)
        finally:
            os.close(credfd)
        dest = _stat_entry(parent, "beacon-destinations.json",
                           991, 991, 0o600, device)
        require(dest.st_size <= 65536, "migration-inventory",
                "destinations file too large")
        files["credential_files"] = credential_files
        files["destinations"] = dict(kind="file", uid=991, gid=991,
                                     mode=0o600, links=1)
    finally:
        os.close(parent)
    return files, identity_inodes, credential_inodes


def _binding(identity_fd):
    fd = os.open("binding.json", os.O_RDONLY | os.O_NOFOLLOW |
                 os.O_NONBLOCK, dir_fd=identity_fd)
    try:
        s = os.fstat(fd)
        require(s.st_uid == s.st_gid == 991
                and stat.S_IMODE(s.st_mode) == 0o600
                and 0 < s.st_size <= 8192,
                "migration-binding", "unrecognized public binding")
        raw = os.read(fd, 8193)
        require(len(raw) == s.st_size,
                "migration-binding", "binding changed")
        return decode(raw)
    finally:
        os.close(fd)


class LiveNativeMigrationEvidence:
    """Fixed original Host observations. No caller-injected native witness."""
    def inspect(self, selected):
        require(os.geteuid() == 0, "root-required", "root-only native witness")
        require(not os.path.lexists("/state")
                and not os.path.lexists("/etc/zog/host-install"),
                "migration-state", "original non-resident installation required")
        dev = os.stat("/").st_dev
        root = [r for r in mounts(Path("/proc/self/mountinfo").read_text())
                if r["target"] == "/"]
        require(len(root) == 1 and root[0]["device"] ==
                str(os.major(dev)) + ":" + str(os.minor(dev)),
                "migration-root", "original root device changed")
        rows = mounts(Path("/proc/self/mountinfo").read_text())
        disks = topology()
        observation = {
            "mounts": rows, "devices": disks,
            "root_device": root[0]["device"], "state_exists": False,
        }
        fd = open_original_legacy_identity_fd(
            selected["identity_inode"], expected_root_device=dev)
        try:
            files, identity_inodes, credential_inodes = _inventory(fd, dev)
            public = _binding(fd)
            require(public == {
                "host_id": selected["host_uuid"],
                "fingerprint": selected["fingerprint"],
            }, "migration-binding", "original Host binding changed")
        finally:
            os.close(fd)
        config = _read_file("/etc/host-discover/configuration.json")
        unit, service = _service()
        accounts = _accounts()
        runtime = select_runtime(
            CANDIDATE_EXECUTABLE, CANDIDATE_PYTHON,
            selected["candidate_executable_sha256"],
            selected["candidate_interpreter_sha256"])
        return {
            "source_inputs": {
                "migration_id": selected["migration_id"],
                "root_observation": observation,
                "account_snapshot": accounts,
                "file_inventory": files,
                "configuration_bytes": config,
                "binding": public,
                "public_identity_witness": selected["fingerprint"],
                "unit_bytes": unit,
                "service_snapshot": service,
                "consumer_contract": CONSUMER_SELECTION,
            },
            "runtime": runtime,
            "identity_inodes": identity_inodes,
            "credential_inodes": credential_inodes,
            "root_device": dev,
        }
