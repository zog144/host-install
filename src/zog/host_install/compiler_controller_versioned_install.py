"""Compiler-controller version staging, protected rollback and atomic selection.

Source-only candidate. The host-deploy reviewed *installed* selection remains
the admission authority; a source checkout or pip success never authorizes
compiler execution. Neither a build nor a service start is performed here.
"""
from __future__ import annotations

import argparse
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

SCHEMA = "zog-compiler-controller-versioned-installer-v1"
VERSIONS = Path("/opt/zog/compiler-runtime/versions")
BACKUPS = Path("/opt/zog/compiler-runtime/rollback")
UNIT_DIR = Path("/etc/systemd/system")
SOURCES = {
    "root-control": ("58b5a94311d771bb1c5f4c3e9c6191b44d6565c9",
                     "0ffddcfb39a9cc5295cc67196362e2dcb57301ed70199c502af1203e20c2d097"),
    "box-control": ("ad61fa6a4e9c3176149720868cb008e0512dbec9",
                    "9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00"),
    "image-build": ("ff968a431dd2067e7d0e1f17d6e547f2779f647a",
                    "e0aacfb08a8b0ef9b1883080ece7d93673906263bee30caa09a285e7a1466310"),
}
RELEASE_ID = re.compile(r"[0-9a-f]{32,64}\Z")
SERVICE_NAME = re.compile(r"zog-[a-z0-9-]+\.service\Z")
EXECUTABLE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


class CompilerInstallerHold(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise CompilerInstallerHold(reason)


def host_path(root, path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "noncanonical destination")
    return Path(root) / path.relative_to("/")


def _safe_directory(root, path, *, create=False):
    root = Path(root).absolute()
    require(root.is_dir() and not root.is_symlink(), "unsafe installation root")
    require(path.is_relative_to(root), "path escapes installation root")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if create and not current.exists() and not current.is_symlink():
            current.mkdir(mode=0o700 if current == path else 0o755)
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not (info.st_mode & 0o022),
                "unsafe runtime directory")
        if root == Path("/"):
            require(info.st_uid == 0 and info.st_gid == 0,
                    "runtime ancestor not root-owned")


def _inventory(root, path):
    """Complete no-link root-owned inventory of file bytes, path and mode."""
    _safe_directory(root, path)
    inventory = []
    for folder, dirs, files in os.walk(path, followlinks=False):
        dirs.sort()
        files.sort()
        for name in ["."] + dirs + files:
            item = Path(folder) if name == "." else Path(folder) / name
            st = item.lstat()
            require(stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode),
                    "linked or special runtime object")
            require(not st.st_mode & 0o022 and
                    (root != Path("/") or (st.st_uid == st.st_gid == 0)),
                    "mutable or foreign runtime object")
            relative = item.relative_to(path).as_posix()
            if stat.S_ISREG(st.st_mode):
                require(st.st_nlink == 1 and st.st_size <= 512 * 1024 * 1024,
                        "linked or oversized runtime file")
                digest = hashlib.sha256()
                length = 0
                with item.open("rb") as reader:
                    for block in iter(lambda: reader.read(1024 * 1024), b""):
                        length += len(block)
                        digest.update(block)
                require(length == st.st_size, "runtime changed during inventory")
                inventory.append(("f", relative, stat.S_IMODE(st.st_mode),
                                  length, digest.hexdigest()))
            else:
                inventory.append(("d", relative, stat.S_IMODE(st.st_mode)))
    require(any(e[0] == "f" for e in inventory), "empty runtime inventory")
    return hashlib.sha256(json.dumps(inventory, separators=(",", ":")).encode()).hexdigest()


def _regular(root, path):
    _safe_directory(root, path.parent)
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
            and not (st.st_mode & 0o022)
            and (root != Path("/") or st.st_uid == st.st_gid == 0),
            "unsafe selected unit or receipt")
    data = path.read_bytes()
    require(len(data) == st.st_size, "selected file changed during read")
    return data


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic(path, body, mode=0o600):
    pending = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        os.replace(pending, path)
        _fsync_directory(path.parent)
    finally:
        if pending.exists():
            pending.unlink()


def _json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _require_root(root):
    root = Path(root).absolute()
    require(root != Path("/") or (os.geteuid() == 0 and os.getegid() == 0),
            "compiler installer requires root")
    require(root.is_dir() and not root.is_symlink(), "invalid installation root")
    return root


def _inactive(root, service, runner):
    if root != Path("/"):
        return
    completed = runner(["/usr/bin/systemctl", "is-active", "--quiet", service], check=False)
    require(completed.returncode in (3, 4),
            "compiler-controller service is active or status is uncertain")


def _reload(root, runner):
    if root == Path("/"):
        completed = runner(["/usr/bin/systemctl", "daemon-reload"], check=False)
        require(completed.returncode == 0, "systemd daemon-reload failed")


@contextmanager
def _lock(root):
    base = host_path(root, BACKUPS)
    _safe_directory(root, base, create=True)
    lock = base / ".installer.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                and st.st_mode & 0o077 == 0
                and (root != Path("/") or st.st_uid == st.st_gid == 0),
                "unsafe compiler installer lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _check_id(release):
    require(type(release) is str and RELEASE_ID.fullmatch(release) is not None,
            "release must be new 32-64 lower-case hexadecimal identifier")


def _check_service(service):
    require(type(service) is str and SERVICE_NAME.fullmatch(service) is not None,
            "invalid compiler-controller service name")


def _source_inventory(path):
    """Same clean tracked Git inventory definition as host-deploy PR #35."""
    path = Path(path)
    require(path.is_dir() and not path.is_symlink(), "untrusted source checkout")
    def git(*args):
        return subprocess.check_output(["git", "-C", str(path), *args],
                                       stderr=subprocess.DEVNULL, timeout=30)
    revision = git("rev-parse", "--verify", "HEAD").decode("ascii").strip()
    require(not git("status", "--porcelain=v1", "--untracked-files=all"),
            "dirty controller source")
    inventory = []
    for raw in git("ls-files", "-z").split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8")
        require(relative and not relative.startswith("/")
                and all(part not in ("", ".", "..") for part in relative.split("/")),
                "unsafe tracked source name")
        file = path / relative
        require(not any(p.is_symlink() for p in [file, *file.parents]
                        if p != path.parent and p != path),
                "linked source path")
        st = file.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_size <= 512 * 1024 * 1024,
                "nonregular tracked source")
        data = file.read_bytes()
        require(len(data) == st.st_size, "changed tracked source")
        inventory.append({"path": relative, "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True,
                            ensure_ascii=True, separators=(",", ":"),
                            allow_nan=False).encode("ascii")).hexdigest()
    return revision, digest


def verify_sources(checkouts):
    require(type(checkouts) is dict and set(checkouts) == set(SOURCES),
            "three source checkouts required")
    require(len({str(Path(p).resolve()) for p in checkouts.values()}) == 3,
            "source checkouts alias")
    for role, (revision, digest) in SOURCES.items():
        require(_source_inventory(checkouts[role]) == (revision, digest),
                "compiler " + role + " checkout differs from pinned source")


def stage(release, checkouts, *, python, service, executable, unit_template,
          root=Path("/"), runner=subprocess.run):
    """Install isolated exact tuple. No selection, rollback, service or SSM."""
    root = _require_root(root)
    _check_id(release)
    _check_service(service)
    require(EXECUTABLE_NAME.fullmatch(executable) is not None,
            "invalid selected controller executable")
    verify_sources(checkouts)
    unit_template = bytes(unit_template)
    expected = (str(VERSIONS / release / "bin" / executable)).encode()
    require(unit_template.count(b"ExecStart=") == 1
            and b"ExecStart=" + expected in unit_template.splitlines()
            and b"[Install]" not in unit_template,
            "candidate controller unit must pin one exact release executable")
    directory = host_path(root, VERSIONS)
    _safe_directory(root, directory, create=True)
    dest = directory / release
    require(not dest.exists() and not dest.is_symlink(), "release already staged")
    _inactive(root, service, runner)
    dest.mkdir(mode=0o700)
    venv = dest / "venv"
    def invoke(args):
        result = runner(list(map(str, args)), check=False)
        require(result.returncode == 0, "isolated controller installation failed")
    invoke([python, "-m", "venv", "--copies", venv])
    venv_python = venv / "bin/python"
    require(venv_python.is_file(), "versioned interpreter absent")
    invoke([venv_python, "-m", "pip", "install", "--no-cache-dir",
            checkouts["root-control"], checkouts["box-control"],
            checkouts["image-build"]])
    invoke([venv_python, "-m", "pip", "check"])
    verify_sources(checkouts)
    launcher = venv / "bin" / executable
    require(launcher.is_file() and not launcher.is_symlink()
            and (launcher.stat().st_mode & stat.S_IXUSR),
            "selected installed controller launcher missing or not executable")
    bin_dir = dest / "bin"
    bin_dir.mkdir(mode=0o700)
    shutil.copy2(launcher, bin_dir / executable, follow_symlinks=False)
    unit_dir = dest / "systemd"
    unit_dir.mkdir(mode=0o700)
    _atomic(unit_dir / service, unit_template, 0o644)
    _inventory(root, dest)
    return {"schema": SCHEMA, "release_id": release, "service": service,
            "staged_unit_sha256": hashlib.sha256(unit_template).hexdigest(),
            "installed_selection_reviewed": False, "execution_authorized": False}


def preserve(release, *, service, original_runtime, root=Path("/"),
             runner=subprocess.run):
    """Copy complete existing runtime and unit before any selection.

    The actual old runtime is supplied from verified Host readback; never
    guess its path or overwrite it. Snapshot is immutable once committed.
    """
    root = _require_root(root)
    _check_id(release)
    _check_service(service)
    old = host_path(root, original_runtime)
    require(Path(original_runtime).is_absolute()
            and ".." not in Path(original_runtime).parts
            and not any(old == area or old in area.parents or area in old.parents
                        for area in (host_path(root, VERSIONS),
                                     host_path(root, BACKUPS))),
            "old runtime aliases selected or rollback location")
    with _lock(root):
        _inactive(root, service, runner)
        digest = _inventory(root, old)
        unit = host_path(root, UNIT_DIR / service)
        unit_body = _regular(root, unit)
        require(str(original_runtime).encode("utf-8") in unit_body,
                "original service does not reference selected old runtime")
        backup = host_path(root, BACKUPS / release)
        require(not backup.exists() and not backup.is_symlink(),
                "rollback snapshot already exists")
        backup.mkdir(mode=0o700)
        retained = backup / "previous-runtime"
        shutil.copytree(old, retained, symlinks=True)
        require(_inventory(root, retained) == digest,
                "rollback runtime copy differs from original")
        _atomic(backup / service, unit_body, 0o600)
        receipt = {"schema": SCHEMA, "release_id": release,
                   "service": service, "original_runtime": str(original_runtime),
                   "runtime_tree_sha256": digest,
                   "unit_sha256": hashlib.sha256(unit_body).hexdigest()}
        _atomic(backup / "preservation.json", _json(receipt))
        _fsync_directory(backup)
        return receipt


def _reviewed(selection_file, expected_sha256):
    """Use the actual host-deploy PR35 independently reviewed inspector."""
    from zog.host_deploy import fonts_versioned_runtime as verifier
    require(verifier.SCHEMA == "zog-first-fonts-versioned-controller-selection-v1"
            and verifier.CONTRACT == "zog-build-inherited-peer-v2"
            and verifier.SELECTED_SOURCES == {
                role: {"revision": pair[0], "source_tree_sha256": pair[1]}
                for role, pair in SOURCES.items()},
            "installed host-deploy verifier does not match selected compiler contract")
    selection = verifier.load_reviewed_selection(str(selection_file), expected_sha256)
    return verifier, selection


def select(selection_file, expected_sha256, *, root=Path("/"), runner=subprocess.run):
    """Live-only atomic unit selection after independent installed inspection."""
    root = _require_root(root)
    verifier, selection = _reviewed(selection_file, expected_sha256)
    release = selection["release_id"]
    service = selection["service"]["name"]
    with _lock(root):
        _inactive(root, service, runner)
        backup = host_path(root, BACKUPS / release)
        record = backup / "selection-transaction.json"
        require(not record.exists() and not record.is_symlink(),
                "previous or interrupted compiler selection requires recovery")
        verifier.inspect_installed(selection, phase="staged")
        active = host_path(root, selection["service"]["active_unit"])
        previous = _regular(root, active)
        new_unit = _regular(root, host_path(root, selection["service"]["staged_unit"]))
        saved = _regular(root, backup / service)
        require(saved == previous and
                hashlib.sha256(saved).hexdigest() == selection["rollback"]["unit_sha256"],
                "protected original unit differs from active unit")
        tx = {"schema": SCHEMA, "release_id": release, "service": service,
              "selection_sha256": expected_sha256,
              "old_unit_sha256": hashlib.sha256(saved).hexdigest(),
              "new_unit_sha256": hashlib.sha256(new_unit).hexdigest(),
              "state": "pending"}
        _atomic(record, _json(tx))
        _inactive(root, service, runner)
        require(_regular(root, active) == previous, "unit changed before selection")
        try:
            _atomic(active, new_unit, 0o644)
            _reload(root, runner)
            _inactive(root, service, runner)
            verifier.inspect_installed(selection, phase="selected")
        except Exception:
            _atomic(active, saved, 0o644)
            _reload(root, runner)
            raise
        tx["state"] = "selected"
        _atomic(record, _json(tx))
        return tx


def restore(selection_file, expected_sha256, *, root=Path("/"), runner=subprocess.run):
    """Restore independent original unit. No service start or job replay."""
    root = _require_root(root)
    verifier, selection = _reviewed(selection_file, expected_sha256)
    release = selection["release_id"]
    service = selection["service"]["name"]
    with _lock(root):
        _inactive(root, service, runner)
        backup = host_path(root, BACKUPS / release)
        tx_path = backup / "selection-transaction.json"
        tx = json.loads(_regular(root, tx_path))
        require(tx.get("schema") == SCHEMA and tx.get("release_id") == release
                and tx.get("service") == service
                and tx.get("selection_sha256") == expected_sha256
                and tx.get("state") in ("pending", "selected"),
                "unknown compiler rollback transaction")
        saved = _regular(root, backup / service)
        require(hashlib.sha256(saved).hexdigest() == tx["old_unit_sha256"],
                "original unit differs from protected rollback")
        require(verifier._retained_tree_sha256(host_path(root, selection["rollback"]["saved_runtime_root"]))
                == selection["rollback"]["runtime_tree_sha256"],
                "protected original runtime differs")
        active = host_path(root, selection["service"]["active_unit"])
        current = _regular(root, active)
        require(hashlib.sha256(current).hexdigest() in
                (tx["new_unit_sha256"], tx["old_unit_sha256"]),
                "active compiler unit is foreign")
        _atomic(active, saved, 0o644)
        _reload(root, runner)
        _inactive(root, service, runner)
        tx["state"] = "restored"
        _atomic(tx_path, _json(tx))
        return tx



def main(argv=None):
    """Operator-facing separate compiler runtime actions; no activation."""
    parser = argparse.ArgumentParser(description="Versioned compiler-controller installer")
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--stage", metavar="RELEASE")
    actions.add_argument("--preserve", metavar="RELEASE")
    actions.add_argument("--select", action="store_true")
    actions.add_argument("--restore", action="store_true")
    parser.add_argument("--root-control-source")
    parser.add_argument("--box-control-source")
    parser.add_argument("--image-build-source")
    parser.add_argument("--python")
    parser.add_argument("--unit-template")
    parser.add_argument("--executable")
    parser.add_argument("--service")
    parser.add_argument("--original-runtime")
    parser.add_argument("--selection")
    parser.add_argument("--expected-selection-sha256")
    args = parser.parse_args(argv)
    if args.stage:
        if not all((args.root_control_source, args.box_control_source,
                    args.image_build_source, args.python, args.unit_template,
                    args.executable, args.service)):
            parser.error("--stage needs three sources, python, unit template, executable and service")
        result = stage(args.stage, {
            "root-control": args.root_control_source,
            "box-control": args.box_control_source,
            "image-build": args.image_build_source,
        }, python=args.python, service=args.service,
            executable=args.executable,
            unit_template=Path(args.unit_template).read_bytes())
    elif args.preserve:
        if not args.service or not args.original_runtime:
            parser.error("--preserve requires service and original runtime path")
        result = preserve(args.preserve, service=args.service,
                          original_runtime=args.original_runtime)
    else:
        if not args.selection or not args.expected_selection_sha256:
            parser.error("--select/--restore require independently reviewed selection and SHA256")
        result = (select(args.selection, args.expected_selection_sha256)
                  if args.select else restore(args.selection, args.expected_selection_sha256))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
