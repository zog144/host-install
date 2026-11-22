"""Compiler-controller version staging, protected rollback and atomic selection.

Source-only candidate. The host-deploy reviewed *installed* selection remains
the admission authority; a source checkout or pip success never authorizes
compiler execution. Neither a build nor a service start is performed here.
"""
from __future__ import annotations

import argparse
import io
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid

from . import compiler_legacy_rollback as legacy_rollback

SCHEMA = "zog-compiler-controller-versioned-installer-v1"
VERSIONS = Path("/opt/zog/compiler-runtime/versions")
BACKUPS = Path("/opt/zog/compiler-runtime/rollback")
UNIT_DIR = Path("/etc/systemd/system")
SOURCES = {
    "root-control": ("a672f007b33f83bf70970e3a571fd443366bd93f",
                     "c9475afdc6545adc963203f1ef00f77bd5aa542e2bf6337f660a5b64d0800989"),
    "box-control": ("ad61fa6a4e9c3176149720868cb008e0512dbec9",
                    "9bd5484b47e80d96569c7dad4a15b61061919bf013bb0e40e810b906b9c1df00"),
    "image-build": ("0eeb8a1cc73ae2b8410e29865c36ea1e0643b75a",
                    "f17598d995888927e66504d2c1ca65ae675c1efb6ac1208e7de1ce9cdd409688"),
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
    """Use host-deploy's canonical complete no-link runtime inventory digest."""
    _safe_directory(root, path)
    inventory = []
    for folder, dirs, files in os.walk(path, followlinks=False):
        dirs.sort()
        files.sort()
        current = Path(folder)
        for directory in [current] + [current / name for name in dirs]:
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and
                    not info.st_mode & 0o022 and
                    (root != Path("/") or info.st_uid == info.st_gid == 0),
                    "linked, foreign or mutable runtime directory")
        inventory.append({"type": "directory",
                          "path": current.relative_to(path).as_posix(),
                          "mode": stat.S_IMODE(current.lstat().st_mode)})
        for name in files:
            item = current / name
            st = item.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                    and not st.st_mode & 0o022
                    and (root != Path("/") or st.st_uid == st.st_gid == 0)
                    and st.st_size <= 512 * 1024 * 1024,
                    "linked, foreign or mutable runtime file")
            digest = hashlib.sha256()
            length = 0
            with item.open("rb") as reader:
                for block in iter(lambda: reader.read(1024 * 1024), b""):
                    length += len(block)
                    digest.update(block)
            require(length == st.st_size, "runtime changed during inventory")
            inventory.append({
                "type": "file", "path": item.relative_to(path).as_posix(),
                "mode": stat.S_IMODE(st.st_mode), "size": length,
                "sha256": digest.hexdigest(),
            })
    require(any(e["type"] == "file" for e in inventory),
            "empty runtime inventory")
    return hashlib.sha256(json.dumps(
        inventory, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("ascii")).hexdigest()

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


def _snapshot_sources(checkouts, destination):
    """Build from disposable Git HEAD archives; never dirty pinned checkouts."""
    result = {}
    for role in SOURCES:
        copied = Path(destination) / role
        copied.mkdir(mode=0o700)
        archive = subprocess.run(
            ["git", "-C", str(checkouts[role]), "archive", "--format=tar", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=60,
        )
        require(archive.returncode == 0, "cannot snapshot verified source " + role)
        with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
            tar.extractall(path=copied, filter="data")
        require((copied / ("box-control/pyproject.toml"
                            if role == "box-control" else "pyproject.toml")).is_file(),
                "snapshotted source packaging missing: " + role)
        result[role] = copied
    return result


def _normalize_new_venv(venv):
    """Normalize only links emitted by fresh Python 3.12 venv --copies."""
    venv = Path(venv)
    allowed = {
        "bin/python": {"python3", "python3.12"},
        "bin/python3": {"python3.12"},
        "bin/python3.12": {"python3", "python"},
        "lib64": {"lib"},
    }
    encountered = []
    for folder, dirs, files in os.walk(venv, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs + files:
            item = Path(folder) / name
            if not item.is_symlink():
                continue
            relative = item.relative_to(venv).as_posix()
            target = os.readlink(item)
            require(relative in allowed and target in allowed[relative],
                    "unexpected link in newly created Python venv")
            encountered.append((relative, target))
            if name in dirs:
                dirs.remove(name)
    for relative, target in sorted(encountered, key=lambda x: x[0], reverse=True):
        item = venv / relative
        if relative == "lib64":
            require((venv / "lib").is_dir() and
                    not (venv / "lib").is_symlink(), "invalid venv lib64 link")
            item.unlink()
            continue
        source = item.parent / target
        require(source.is_file(), "fresh venv interpreter link is dangling")
        resolved = source.resolve(strict=True)
        require(resolved.is_relative_to(venv) and resolved.is_file() and
                not resolved.is_symlink(), "fresh venv interpreter escapes release")
        temporary = item.with_name("." + item.name + ".copy-" + uuid.uuid4().hex)
        try:
            shutil.copy2(resolved, temporary, follow_symlinks=False)
            require(temporary.is_file() and not temporary.is_symlink() and
                    temporary.stat().st_mode & stat.S_IXUSR,
                    "new venv interpreter copy not executable")
            os.replace(temporary, item)
        finally:
            if temporary.exists():
                temporary.unlink()
    return sorted(relative for relative, _ in encountered)


def stage(release, checkouts, *, python, service, executable, unit_template,
          dropins_directory=None, root=Path("/"), runner=subprocess.run):
    """Install isolated exact tuple. No selection, rollback, service or SSM."""
    root = _require_root(root)
    _check_id(release)
    _check_service(service)
    require(EXECUTABLE_NAME.fullmatch(executable) is not None,
            "invalid selected controller executable")
    verify_sources(checkouts)
    if service == "zog-certbot-seed-root.service":
        require(dropins_directory is not None,
                "compiler successor must explicitly stage reviewed drop-ins")
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
    _normalize_new_venv(venv)
    venv_python = venv / "bin/python"
    require(venv_python.is_file(), "versioned interpreter absent")
    with tempfile.TemporaryDirectory(prefix="zog-compiler-source-") as scratch:
        copies = _snapshot_sources(checkouts, scratch)
        box_project = Path(copies["box-control"]) / "box-control"
        require((box_project / "pyproject.toml").is_file()
                and not (box_project / "pyproject.toml").is_symlink(),
                "pinned box-control project packaging missing")
        invoke([venv_python, "-m", "pip", "install", "--no-cache-dir",
                copies["root-control"], box_project, copies["image-build"]])
    invoke([venv_python, "-m", "pip", "check"])
    invoke([venv_python, "-I", "-B", "-c",
            "import zog.root_control, zog.box_control, zog.image_build; "
            "import zog.image_build.remote_operations"])
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
    if dropins_directory is not None:
        # Candidate drop-ins are source material, not a live systemd directory.
        source_dropins = Path(dropins_directory).absolute()
        require(source_dropins.is_dir() and not source_dropins.is_symlink(),
                "invalid reviewed candidate drop-in directory")
        selected = _dropins(source_dropins.parent, source_dropins)
        target = unit_dir / (service + ".d")
        _safe_directory(root, target, create=True)
        for entry in selected:
            _atomic(target / entry["name"],
                    _regular(source_dropins.parent, source_dropins / entry["name"]),
                    entry["mode"])
        _dropin_names(root, target, selected)
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
        legacy_evidence = legacy_rollback.inventory(root, old)
        digest = legacy_evidence["tree_sha256"]
        unit = host_path(root, UNIT_DIR / service)
        unit_body = _regular(root, unit)
        info = unit.lstat()
        unit_metadata = {"path": str(UNIT_DIR / service),
                         "sha256": hashlib.sha256(unit_body).hexdigest(),
                         "size": len(unit_body),
                         "mode": stat.S_IMODE(info.st_mode),
                         "uid": info.st_uid if root == Path("/") else 0,
                         "gid": info.st_gid if root == Path("/") else 0}
        # The main fragment may name an obsolete command; ordered drop-ins
        # (notably 60/70) determine the *effective* current ExecStart.
        backup = host_path(root, BACKUPS / release)
        require(not backup.exists() and not backup.is_symlink(),
                "rollback snapshot already exists")
        backup.mkdir(mode=0o700)
        retained = backup / "previous-runtime"
        shutil.copytree(old, retained, symlinks=True)
        legacy_rollback.assert_copy(root, old, retained, expected=legacy_evidence)
        _atomic(backup / service, unit_body, unit_metadata["mode"])
        active_dropins = host_path(root, UNIT_DIR / (service + ".d"))
        preserved_dropins = backup / (service + ".d")
        selected_dropins = _dropins(root, active_dropins)
        loaded_properties = _current_manager_composition(
            root, service, unit, selected_dropins, runner)
        ordered_dropins = [
            _regular(root, active_dropins / entry["name"])
            for entry in selected_dropins
        ]
        if loaded_properties is not None:
            from zog.host_deploy import fonts_unit_composition as composition
            try:
                composition.verify_composed(
                    unit_body, ordered_dropins, loaded_properties[0])
            except composition.CompositionHold as error:
                raise CompilerInstallerHold(str(error)) from error
            selected_argv = loaded_properties[0]["ExecStart"][0]["argv"]
        else:
            # A disposable-root fixture has no systemd manager. This checks
            # the old runtime path, but is NOT an admission substitute for the
            # live normalized command + complete prestart verification above.
            lines = [unit_body, *ordered_dropins]
            effective = []
            for raw in lines:
                in_service = False
                for line in raw.decode("utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("[") and line.endswith("]"):
                        in_service = line == "[Service]"
                    elif in_service and line.startswith("ExecStart="):
                        value = line.partition("=")[2].strip()
                        if value:
                            effective.append(value)
                        else:
                            effective.clear()
            require(len(effective) == 1,
                    "original effective ExecStart is ambiguous")
            selected_argv = effective[0]
        try:
            parsed_argv = shlex.split(selected_argv)
        except ValueError as error:
            raise CompilerInstallerHold("ambiguous original command argv") from error
        require(any(arg == str(original_runtime) or
                    arg.startswith(str(original_runtime).rstrip("/") + "/")
                    for arg in parsed_argv),
                "original effective ExecStart does not name retained runtime")
        _safe_directory(root, preserved_dropins, create=True)
        _copy_dropins(root, active_dropins, preserved_dropins,
                      selected_dropins)
        receipt = {"schema": SCHEMA, "release_id": release,
                   "service": service, "original_runtime": str(original_runtime),
                   "runtime_tree_sha256": digest,
                   "legacy_inventory_schema": legacy_rollback.SCHEMA,
                   "legacy_inventory_sha256": legacy_evidence["inventory_sha256"],
                   "python_interpreter_chain": legacy_evidence["python_interpreter_chain"],
                   "unit_sha256": hashlib.sha256(unit_body).hexdigest(),
                   "original_fragment": unit_metadata,
                   "original_dropins": selected_dropins,
                   "original_loaded_properties":
                       loaded_properties[0] if loaded_properties is not None else None,
                   "original_loaded_process_metadata":
                       loaded_properties[1] if loaded_properties is not None else None}
        _atomic(backup / "preservation.json", _json(receipt))
        _fsync_directory(backup)
        return receipt


def _effective_equivalent(observed, reviewed):
    """Match verifier semantics without rewriting protected evidence.

    ExecStart, ExecStartPre and ReadOnlyPaths remain exact; systemd may
    enumerate the same After/Requires dependencies in a different order.
    """
    from zog.host_deploy import fonts_unit_composition as composition
    if type(observed) is not dict or type(reviewed) is not dict:
        return False
    if set(observed) != set(composition.KEYS) or set(reviewed) != set(composition.KEYS):
        return False
    for key in composition.KEYS:
        actual, expected = observed[key], reviewed[key]
        if key in ("After", "Requires"):
            if type(actual) is not str or type(expected) is not str:
                return False
            if sorted(actual.split()) != sorted(expected.split()):
                return False
        elif actual != expected:
            return False
    return True


def _current_manager_composition(root, service, fragment, dropins, runner):
    """Read actual loaded service, fail on additional /run or /usr drop-ins."""
    if root != Path("/"):
        return None
    keys = ("ExecStart", "ExecStartPre", "ReadOnlyPaths",
            "Requires", "After", "DropInPaths", "FragmentPath", "LoadState")
    result = runner(["/usr/bin/systemctl", "show", "--no-pager",
                     "--property=" + ",".join(keys), service],
                    check=False, capture_output=True, text=True)
    require(result.returncode == 0, "cannot read original loaded compiler composition")
    props = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        require(bool(sep) and key not in props,
                "invalid manager loaded composition")
        props[key] = value
    require(set(props) == set(keys) and props["LoadState"] == "loaded"
            and props["FragmentPath"] == str(fragment)
            and set(props["DropInPaths"].split()) ==
                {str(fragment) + ".d/" + item["name"] for item in dropins},
            "original manager composition differs from protected files")
    from zog.host_deploy import fonts_unit_composition as composition
    try:
        return composition.normalize_loaded_commands(
            {key: props[key] for key in composition.KEYS})
    except composition.CompositionHold as error:
        raise CompilerInstallerHold(str(error)) from error


def _dropins(root, directory):
    """Exact files and metadata for the active/staged drop-in directory."""
    if not directory.exists() and not directory.is_symlink():
        return []
    _safe_directory(root, directory)
    result = []
    for item in sorted(directory.iterdir()):
        require(item.name.endswith(".conf") and item.name[0].isalnum()
                and all(c.isalnum() or c in "._-" for c in item.name),
                "foreign systemd drop-in path")
        st = item.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                and not st.st_mode & 0o022
                and (root != Path("/") or st.st_uid == st.st_gid == 0)
                and 0 < st.st_size <= 1024 * 1024,
                "unsafe compiler drop-in")
        raw = _regular(root, item)
        result.append({"name": item.name, "sha256": hashlib.sha256(raw).hexdigest(),
                       "size": len(raw), "mode": stat.S_IMODE(st.st_mode),
                       "uid": st.st_uid if root == Path("/") else 0,
                       "gid": st.st_gid if root == Path("/") else 0})
    require(len(result) <= 64, "too many compiler drop-ins")
    return result


def _dropin_names(root, directory, expected):
    observed = _dropins(root, directory)
    require(observed == expected, "unknown or changed compiler drop-in composition")


def _copy_dropins(root, source, destination, expected):
    """Publish complete exact set only while the unit is masked."""
    _dropin_names(root, source, expected)
    _safe_directory(root, destination, create=True)
    require(not any(destination.iterdir()), "unreconciled destination drop-ins")
    for entry in expected:
        body = _regular(root, source / entry["name"])
        _atomic(destination / entry["name"], body, entry["mode"])
    _dropin_names(root, destination, expected)


def _startup_guard(root, release, active_dir):
    from zog.host_deploy import fonts_unit_composition as composition
    expected = composition.transaction_guard_bytes(release)
    name = composition.GUARD_NAME
    permit = host_path(root, BACKUPS / release / "startup-permit")
    require(not permit.exists() and not permit.is_symlink(),
            "compiler startup permit unexpectedly exists")
    guard = active_dir / name
    if guard.exists() or guard.is_symlink():
        require(_regular(root, guard) == expected
                and stat.S_IMODE(guard.lstat().st_mode) == 0o644,
                "existing compiler startup guard differs")
    else:
        _safe_directory(root, active_dir, create=True)
        _atomic(guard, expected, 0o644)
    items = _dropins(root, active_dir)
    require(all(entry["name"] <= name for entry in items),
            "drop-in ordered after protective startup guard")
    matching = [entry for entry in items if entry["name"] == name]
    require(len(matching) == 1, "missing durable compiler startup guard")
    return matching[0]


def _confirm_guard_loaded(root, service, active_dir, runner):
    if root != Path("/"):
        return
    result = runner(["/usr/bin/systemctl", "show", "--no-pager",
                     "--property=DropInPaths", "--property=LoadState", service],
                    check=False, capture_output=True, text=True)
    require(result.returncode == 0, "cannot inspect loaded compiler guard")
    props = dict(line.split("=", 1) for line in result.stdout.splitlines()
                 if "=" in line)
    require(props.get("LoadState") == "loaded"
            and str(active_dir / "zzzz-zog-compiler-transaction-guard.conf")
                in props.get("DropInPaths", "").split(),
            "persistent startup guard is not manager-loaded")


def _remove_guard(root, release, active_dir, service, runner):
    from zog.host_deploy import fonts_unit_composition as composition
    guard = _startup_guard(root, release, active_dir)
    require(guard["name"] == composition.GUARD_NAME,
            "foreign compiler guard")
    (active_dir / composition.GUARD_NAME).unlink()
    _fsync_directory(active_dir)
    _reload(root, runner)
    _inactive(root, service, runner)


def _assert_masked(root, service, runner):
    if root != Path("/"):
        return
    result = runner(["/usr/bin/systemctl", "show", "--property=LoadState",
                     "--value", service], check=False, capture_output=True, text=True)
    require(result.returncode == 0 and result.stdout.strip() == "masked",
            "compiler service not reliably masked during transition")


def _mask_unit(root, active, service, runner):
    """Durable /etc mask survives a restart before drop-in composition changes."""
    pending = active.with_name("." + active.name + "." + uuid.uuid4().hex + ".mask")
    try:
        os.symlink("/dev/null", pending)
        os.replace(pending, active)
        _fsync_directory(active.parent)
    finally:
        if pending.is_symlink():
            pending.unlink()
    _reload(root, runner)
    _assert_masked(root, service, runner)
    _inactive(root, service, runner)


def _switch_dropins(root, active_dir, existing, wanted_dir, wanted, guard):
    """Keep the permanent startup guard while changing all other drop-ins."""
    require(guard["name"] not in {e["name"] for e in [*existing, *wanted]},
            "reviewed composition conflicts with transaction guard")
    _dropin_names(root, active_dir,
                  sorted([*existing, guard], key=lambda e: e["name"]))
    _safe_directory(root, active_dir, create=True)
    _dropin_names(root, wanted_dir, wanted)
    for entry in existing:
        (active_dir / entry["name"]).unlink()
    _fsync_directory(active_dir)
    for entry in wanted:
        _atomic(active_dir / entry["name"],
                _regular(root, wanted_dir / entry["name"]), entry["mode"])
    _dropin_names(root, active_dir,
                  sorted([*wanted, guard], key=lambda e: e["name"]))




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


def _restore_dropins(root, active_dir, original_dir, composition, guard):
    """Restore original set while retaining the deny-by-default guard."""
    before = {item["name"]: item for item in composition["original_dropins"]}
    after = {item["name"]: item for item in composition["selected_dropins"]}
    observed = _dropins(root, active_dir)
    require(guard in observed, "persistent guard missing during recovery")
    for item in observed:
        if item["name"] == guard["name"]:
            continue
        require(item in (before.get(item["name"]), after.get(item["name"])),
                "unknown or modified drop-in during interrupted selection")
    _safe_directory(root, active_dir, create=True)
    for item in observed:
        if item["name"] != guard["name"]:
            (active_dir / item["name"]).unlink()
    _fsync_directory(active_dir)
    _dropin_names(root, original_dir, composition["original_dropins"])
    for entry in composition["original_dropins"]:
        _atomic(active_dir / entry["name"],
                _regular(root, original_dir / entry["name"]), entry["mode"])
    _dropin_names(root, active_dir,
                  sorted([*composition["original_dropins"], guard],
                         key=lambda item: item["name"]))




def _already_masked(active):
    return active.is_symlink() and os.readlink(active) == "/dev/null"


def select(selection_file, expected_sha256, *, root=Path("/"), runner=subprocess.run):
    """Guarded multi-file selection, with persistent mask and durable recovery."""
    root = _require_root(root)
    verifier, selection = _reviewed(selection_file, expected_sha256)
    release = selection["release_id"]
    service = selection["service"]["name"]
    composition = selection["composition"]
    with _lock(root):
        _inactive(root, service, runner)
        backup = host_path(root, BACKUPS / release)
        transaction_path = backup / "selection-transaction.json"
        require(not transaction_path.exists() and not transaction_path.is_symlink(),
                "previous or interrupted compiler selection requires recovery")
        verifier.inspect_installed(selection, phase="staged")
        active = host_path(root, selection["service"]["active_unit"])
        current = _regular(root, active)
        staged_file = host_path(root, selection["service"]["staged_unit"])
        new_unit = _regular(root, staged_file)
        staged_info = staged_file.lstat()
        chosen = composition["selected_fragment"]
        require(chosen == {
            "path": selection["service"]["staged_unit"],
            "sha256": hashlib.sha256(new_unit).hexdigest(),
            "size": len(new_unit), "mode": stat.S_IMODE(staged_info.st_mode),
            "uid": staged_info.st_uid if root == Path("/") else 0,
            "gid": staged_info.st_gid if root == Path("/") else 0},
            "staged compiler fragment metadata differs from reviewed selection")
        original_unit = _regular(root, backup / service)
        receipt = json.loads(_regular(root, backup / "preservation.json"))
        require(receipt.get("schema") == SCHEMA
                and receipt.get("release_id") == release
                and receipt.get("service") == service
                and receipt.get("original_dropins") == composition["original_dropins"]
                and receipt.get("original_fragment") ==
                    composition["original_fragment"]
                and receipt.get("legacy_inventory_schema") ==
                    selection["rollback"]["legacy_inventory_schema"]
                and receipt.get("legacy_inventory_sha256") ==
                    selection["rollback"]["legacy_inventory_sha256"]
                and receipt.get("python_interpreter_chain") ==
                    selection["rollback"]["python_interpreter_chain"]
                and (root != Path("/") or (
                     type(receipt.get("original_loaded_properties")) is dict
                     and _effective_equivalent(
                         receipt["original_loaded_properties"],
                         composition["original_effective"])
                     and type(receipt.get("original_loaded_process_metadata")) is dict))
                and receipt.get("unit_sha256") == hashlib.sha256(current).hexdigest()
                and receipt.get("original_fragment", {}).get("sha256")
                    == hashlib.sha256(current).hexdigest()
                and current == original_unit
                and hashlib.sha256(new_unit).hexdigest() ==
                    selection["service"]["staged_sha256"],
                "reviewed original unit or drop-in preservation differs")
        active_dir = host_path(root, UNIT_DIR / (service + ".d"))
        staged_dir = host_path(root, VERSIONS / release / "systemd" / (service + ".d"))
        _dropin_names(root, active_dir, composition["original_dropins"])
        _dropin_names(root, staged_dir, composition["selected_dropins"])
        tx = {"schema": SCHEMA, "release_id": release, "service": service,
              "selection_sha256": expected_sha256,
              "old_unit_sha256": hashlib.sha256(current).hexdigest(),
              "new_unit_sha256": hashlib.sha256(new_unit).hexdigest(),
              "old_dropins": composition["original_dropins"],
              "new_dropins": composition["selected_dropins"],
              "state": "arming"}
        # Arming is NOT an incomplete selection: the original, unchanged
        # fragment and drop-ins may still boot. A crash before the guard is
        # manager-loaded must never produce a pending transaction.
        _atomic(transaction_path, _json(tx))
        # The permanent on-disk ConditionPathExists guard survives reboot
        # independently of the temporary /dev/null fragment mask. Its
        # startup-permit marker is deliberately absent and never created.
        guard = _startup_guard(root, release, active_dir)
        _reload(root, runner)
        _inactive(root, service, runner)
        _confirm_guard_loaded(root, service, active_dir, runner)
        # Only the manager-confirmed persistent guard permits the stronger
        # pending invariant: neither reboot nor start may execute this service.
        tx["state"] = "pending"
        _atomic(transaction_path, _json(tx))
        _mask_unit(root, active, service, runner)
        try:
            _switch_dropins(root, active_dir, composition["original_dropins"],
                            staged_dir, composition["selected_dropins"], guard)
            _assert_masked(root, service, runner)
            _atomic(active, new_unit, 0o644)
            _reload(root, runner)
            _inactive(root, service, runner)
            _confirm_guard_loaded(root, service, active_dir, runner)
            verifier.inspect_installed(selection, phase="selected",
                                       transaction_guard=True)
        except Exception:
            # Do not remove the persistent guard on failure or interruption.
            # Even when the fragment has been unmasked, reboot cannot start
            # the pending composition while its permit remains absent.
            if not _already_masked(active):
                _mask_unit(root, active, service, runner)
            raise
        tx["state"] = "selected"
        _atomic(transaction_path, _json(tx))
        # Fully verified and durably selected BEFORE allowing any start.
        # If interrupted here, the verified release remains guarded and
        # explicit restore/recovery can still inspect the transaction.
        _remove_guard(root, release, active_dir, service, runner)
        verifier.inspect_installed(selection, phase="selected")
        return tx


def restore(selection_file, expected_sha256, *, root=Path("/"),
            runner=subprocess.run):
    """Recover original unit+all drop-ins, including interrupted transactions."""
    root = _require_root(root)
    verifier, selection = _reviewed(selection_file, expected_sha256)
    release = selection["release_id"]
    service = selection["service"]["name"]
    composition = selection["composition"]
    with _lock(root):
        # An interrupted pre-guard arming transaction can have started the
        # ORIGINAL unchanged unit at boot. Only pending/restoring require
        # inactivity; arming recovery must not pretend otherwise.
        backup = host_path(root, BACKUPS / release)
        transaction_path = backup / "selection-transaction.json"
        tx = json.loads(_regular(root, transaction_path))
        require(tx.get("schema") == SCHEMA and tx.get("release_id") == release
                and tx.get("service") == service
                and tx.get("selection_sha256") == expected_sha256
                and tx.get("old_dropins") == composition["original_dropins"]
                and tx.get("new_dropins") == composition["selected_dropins"]
                and tx.get("state") in ("arming", "pending", "selected", "restoring", "restored"),
                "unknown compiler rollback transaction")
        original = _regular(root, backup / service)
        require(hashlib.sha256(original).hexdigest() == tx["old_unit_sha256"]
                == selection["rollback"]["unit_sha256"],
                "original unit differs from protected rollback")
        original_dir = backup / (service + ".d")
        _dropin_names(root, original_dir, composition["original_dropins"])
        custody = json.loads(_regular(root, backup / "preservation.json"))
        require(custody.get("schema") == SCHEMA
                and custody.get("release_id") == release
                and custody.get("service") == service
                and custody.get("original_dropins") ==
                    composition["original_dropins"]
                and custody.get("original_fragment") ==
                    composition["original_fragment"]
                and (root != Path("/") or (
                    type(custody.get("original_loaded_properties")) is dict
                    and _effective_equivalent(
                        custody["original_loaded_properties"],
                        composition["original_effective"])
                    and type(custody.get("original_loaded_process_metadata")) is dict)),
                "protected original stable command identity differs")
        custody = json.loads(_regular(root, backup / "preservation.json"))
        original_runtime = host_path(root, custody["original_runtime"])
        copied_runtime = host_path(root, selection["rollback"]["saved_runtime_root"])
        require(custody.get("original_runtime") == selection["rollback"]["original_runtime"],
                "rollback original path differs")
        legacy_evidence = legacy_rollback.assert_copy(
            root, original_runtime, copied_runtime)
        require(legacy_evidence["schema"] == selection["rollback"]["legacy_inventory_schema"]
                and legacy_evidence["tree_sha256"] == selection["rollback"]["runtime_tree_sha256"]
                and legacy_evidence["inventory_sha256"] == selection["rollback"]["legacy_inventory_sha256"]
                and legacy_evidence["python_interpreter_chain"] ==
                    selection["rollback"]["python_interpreter_chain"],
                "protected original runtime or external Python changed")
        active = host_path(root, selection["service"]["active_unit"])
        active_dir = host_path(root, UNIT_DIR / (service + ".d"))
        if tx["state"] == "arming":
            # No unit or reviewed drop-in has been changed in arming. The
            # original service may have booted if the guard was not loaded.
            require(_regular(root, active) == original,
                    "arming original fragment has changed")
            from zog.host_deploy import fonts_unit_composition as check
            guard_file = active_dir / check.GUARD_NAME
            if guard_file.exists() or guard_file.is_symlink():
                # If the guard was written but not loaded at crash, install
                # its protection before cleanup; never unguard an active unit.
                guard = _startup_guard(root, release, active_dir)
                _dropin_names(root, active_dir, sorted(
                    [*composition["original_dropins"], guard],
                    key=lambda entry: entry["name"]))
                _inactive(root, service, runner)
                _reload(root, runner)
                _confirm_guard_loaded(root, service, active_dir, runner)
                if root == Path("/"):
                    try:
                        check.verify_loaded(
                            service, fragment=selection["service"]["active_unit"],
                            names=[e["name"] for e in
                                   composition["original_dropins"]] +
                                  [check.GUARD_NAME],
                            expected=composition["original_effective"])
                    except check.CompositionHold as error:
                        raise CompilerInstallerHold(str(error)) from error
                _remove_guard(root, release, active_dir, service, runner)
            else:
                _dropin_names(root, active_dir, composition["original_dropins"])
            if root == Path("/"):
                try:
                    check.verify_loaded(
                        service, fragment=selection["service"]["active_unit"],
                        names=[e["name"] for e in
                               composition["original_dropins"]],
                        expected=composition["original_effective"])
                except check.CompositionHold as error:
                    raise CompilerInstallerHold(str(error)) from error
            tx["state"] = "aborted"
            _atomic(transaction_path, _json(tx))
            return tx
        _inactive(root, service, runner)
        if tx["state"] == "restored":
            require(_regular(root, active) == original,
                    "already restored compiler fragment differs")
            # Reboot after durable restore may leave only guard cleanup.
            # Independently re-attest loaded original properties before
            # permitting any startup; never rely on a stale pre-reboot check.
            from zog.host_deploy import fonts_unit_composition as check
            guarded = (active_dir / check.GUARD_NAME).exists()
            if guarded:
                guard = _startup_guard(root, release, active_dir)
                _dropin_names(root, active_dir, sorted(
                    [*composition["original_dropins"], guard],
                    key=lambda entry: entry["name"]))
                if root == Path("/"):
                    try:
                        check.verify_loaded(
                            service, fragment=selection["service"]["active_unit"],
                            names=[*[e["name"] for e in
                                     composition["original_dropins"]],
                                   check.GUARD_NAME],
                            expected=composition["original_effective"])
                    except check.CompositionHold as error:
                        raise CompilerInstallerHold(str(error)) from error
                _remove_guard(root, release, active_dir, service, runner)
            _dropin_names(root, active_dir, composition["original_dropins"])
            if root == Path("/"):
                try:
                    check.verify_loaded(
                        service, fragment=selection["service"]["active_unit"],
                        names=[e["name"] for e in
                               composition["original_dropins"]],
                        expected=composition["original_effective"])
                except check.CompositionHold as error:
                    raise CompilerInstallerHold(str(error)) from error
            return tx
        if not _already_masked(active):
            current = _regular(root, active)
            require(hashlib.sha256(current).hexdigest() in
                    (tx["new_unit_sha256"], tx["old_unit_sha256"]),
                    "active compiler unit is foreign")
        # Establish the reboot-persistent deny-by-default guard BEFORE
        # committing a restoring state. A crash prior to that commit then
        # leaves either a complete previously selected service or a masked
        # pending service, never an unguarded incomplete restoration.
        guard = _startup_guard(root, release, active_dir)
        _reload(root, runner)
        _inactive(root, service, runner)
        if not _already_masked(active):
            _confirm_guard_loaded(root, service, active_dir, runner)
        else:
            _assert_masked(root, service, runner)
        tx["state"] = "restoring"
        _atomic(transaction_path, _json(tx))
        if not _already_masked(active):
            _mask_unit(root, active, service, runner)
        else:
            _assert_masked(root, service, runner)
        _restore_dropins(root, active_dir, original_dir, composition, guard)
        _assert_masked(root, service, runner)
        receipt = json.loads(_regular(root, backup / "preservation.json"))
        unit_mode = receipt.get("original_fragment", {}).get("mode")
        require(type(unit_mode) is int and unit_mode in (0o600, 0o640, 0o644),
                "unreviewed original fragment mode")
        _atomic(active, original, unit_mode)
        _reload(root, runner)
        _inactive(root, service, runner)
        _confirm_guard_loaded(root, service, active_dir, runner)
        if root == Path("/"):
            from zog.host_deploy import fonts_unit_composition as check
            try:
                check.verify_loaded(
                    service, fragment=selection["service"]["active_unit"],
                    names=[*[e["name"] for e in composition["original_dropins"]],
                           check.GUARD_NAME],
                    expected=composition["original_effective"])
            except check.CompositionHold as error:
                raise CompilerInstallerHold(str(error)) from error
        tx["state"] = "restored"
        _atomic(transaction_path, _json(tx))
        _remove_guard(root, release, active_dir, service, runner)
        if root == Path("/"):
            try:
                check.verify_loaded(
                    service, fragment=selection["service"]["active_unit"],
                    names=[e["name"] for e in composition["original_dropins"]],
                    expected=composition["original_effective"])
            except check.CompositionHold as error:
                raise CompilerInstallerHold(str(error)) from error
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
    parser.add_argument("--dropins-directory",
                        help="explicitly reviewed successor service drop-in directory")
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
            unit_template=Path(args.unit_template).read_bytes(),
            dropins_directory=args.dropins_directory)
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
