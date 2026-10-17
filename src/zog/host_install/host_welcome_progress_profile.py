"""Dedicated host-welcome controller-progress observer deployment and attestation.

The live staging entrypoint derives peer identities from independent host facts:
the validated dedicated host-welcome account, controller-project ownership, and
the existing root-control socket owner. Caller-supplied numeric UIDs are never
installation authority.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib
import importlib.metadata
import importlib.util
from importlib.resources import files as resource_files
import io
import os
from pathlib import Path
import pwd
import re
import stat
import sys

from .state_contract import canonical, require
from .state_inspect import directory
from .state_io import ensure_directory, lock, publish
from .welcome_readiness import welcome_account

PROFILE_KIND = "zog-host-welcome-progress-observer-profile-v2"
POLICY_SCHEMA = "zog-host-welcome-progress-observer-v1"
POLICY_PATH = "/etc/zog/host-welcome-progress-observer.json"
SOCKET_PATH = "/run/host-welcome/controller-progress.sock"
ROOT_CONTROL_SOCKET = "/run/zog/root-control.sock"
UNIT_SOCKET = "zog-host-welcome-controller-progress.socket"
UNIT_SERVICE = "zog-host-welcome-controller-progress.service"

BOX_CONTROL_COMMIT = "8249715708c6ef8a1fd30a3fb529b4034ffffe25"
BOX_CONTROL_MODULE_BLOBS = {
    "zog.box_control.application_progress_broker":
        "6742f7f3e44fd809f0322fbb3f7cbf7bcd9fa9cc",
    "zog.box_control.application_progress_client":
        "31627205509c1c8faefdb29ebc955d9d34e72cc1",
    "zog.box_control.application_progress":
        "79b06ce3e162ae5fb814091f53e9b047ae857177",
    "zog.box_control.role_broker":
        "16403f5c5612d10639e19f0e44defb4c9d0e5955",
    "zog.box_control.api":
        "3a29cfdbffce13a57f690cc7092ff19d574a23fc",
    "zog.box_control.project":
        "47866e72bcaa1ec37ad06f508fe2c4794bd973eb",
    "zog.box_control.errors":
        "9bbe9e681286c3c8cdc3a703ba0a3f52444bbfbb",
    "zog.box_control.root_protocol":
        "521560cc6addcc00f74103f0096150eff5cb0ab1",
    "zog.box_control.runtime.root_control":
        "7a1122d5db2d8f8f51594421f171be9218b0504b",
}
_SOURCE_FILES = {
    module: "box-control/src/" + module.replace(".", "/") + ".py"
    for module in BOX_CONTROL_MODULE_BLOBS
}
_SIMPLE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z")


def _numeric(value, label):
    require(type(value) is int and 0 < value < 2**31,
            "welcome-progress-profile", label)
    return str(value)


def _absolute(value, label):
    text = str(value)
    parsed = Path(text)
    require(
        _SIMPLE_PATH.fullmatch(text) is not None
        and str(parsed) == text
        and ".." not in parsed.parts
        and "." not in parsed.parts,
        "welcome-progress-profile",
        label,
    )
    return text


def _git_blob_sha(data):
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _record_sha256(data):
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def _protected_ancestry(path, stop):
    path = Path(path)
    stop = Path(stop)
    require(path.is_absolute() and stop.is_absolute(),
            "box-control-installed", "protected path must be absolute")
    try:
        path.relative_to(stop)
    except ValueError:
        require(False, "box-control-installed",
                "installed module is outside aggregate distribution root")
    current = path
    while True:
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not (info.st_mode & 0o022),
                "box-control-installed",
                "installed software path is redirected or writable")
        if current == stop:
            break
        current = current.parent


def _protected_root_control_ancestry():
    current = Path("/")
    for part in Path(ROOT_CONTROL_SOCKET).parent.parts[1:]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and info.st_uid == 0 and not (info.st_mode & 0o022),
                "controller-identity",
                "root-control socket ancestry is not root protected")


def resolve_live_identities(controller_project):
    """Derive actual welcome/controller IDs from independent live host facts."""
    require(os.geteuid() == 0, "root-required",
            "live observer identity resolution requires root")
    project_text = _absolute(
        controller_project, "canonical controller project required"
    )
    project = Path(project_text)
    project_info = project.lstat()
    require(stat.S_ISDIR(project_info.st_mode) and not stat.S_ISLNK(project_info.st_mode)
            and project_info.st_uid >= 1000 and project_info.st_gid > 0
            and not (project_info.st_mode & 0o022),
            "controller-identity",
            "controller project ownership is not protected")
    controller_uid = project_info.st_uid
    controller_gid = project_info.st_gid

    try:
        owner = pwd.getpwuid(controller_uid)
    except KeyError:
        require(False, "controller-identity",
                "controller project owner has no host account")
    require(owner.pw_uid == controller_uid and owner.pw_gid == controller_gid
            and len([row for row in pwd.getpwall()
                     if row.pw_uid == controller_uid]) == 1,
            "controller-identity",
            "controller owner account disagrees with project ownership")

    _protected_root_control_ancestry()
    socket_info = Path(ROOT_CONTROL_SOCKET).lstat()
    require(stat.S_ISSOCK(socket_info.st_mode) and not stat.S_ISLNK(socket_info.st_mode)
            and socket_info.st_uid == controller_uid
            and stat.S_IMODE(socket_info.st_mode) in (0o600, 0o660),
            "controller-identity",
            "root-control socket does not authenticate the project owner UID")

    consumer_uid, consumer_gid = welcome_account()
    require(consumer_uid != controller_uid,
            "welcome-progress-profile",
            "host-welcome consumer and controller owner must be distinct UIDs")
    return {
        "consumer_uid": consumer_uid,
        "consumer_gid": consumer_gid,
        "controller_uid": controller_uid,
        "controller_gid": controller_gid,
        "controller_project": project_text,
        "evidence": {
            "welcome_account": "host-account-database",
            "controller_project_owner": project_text,
            "root_control_socket_owner": ROOT_CONTROL_SOCKET,
        },
    }


def verify_reviewed_source(source):
    """Verify the reviewed broker/client and security-critical dependency bytes."""
    root = Path(source)
    observed = {}
    for module, relative in _SOURCE_FILES.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                "box-control-source",
                "reviewed box-control module missing or redirected")
        data = path.read_bytes()
        require(len(data) <= 262144,
                "box-control-source",
                "reviewed box-control module exceeds size bound")
        digest = _git_blob_sha(data)
        require(digest == BOX_CONTROL_MODULE_BLOBS[module],
                "box-control-source",
                "box-control observer dependency differs from reviewed source")
        observed[module] = {
            "git_blob": digest,
            "sha256": _sha256(data),
        }
    return observed


def _wheel_record(distribution, root):
    text = distribution.read_text("RECORD")
    require(type(text) is str and 0 < len(text) <= 2_000_000,
            "box-control-installed",
            "aggregate wheel RECORD missing or excessive")
    rows = {}
    for row in csv.reader(io.StringIO(text)):
        require(len(row) == 3 and row[0] not in rows,
                "box-control-installed", "invalid aggregate wheel RECORD")
        rows[row[0]] = (row[1], row[2])
    record_files = [
        value for value in distribution.files or ()
        if str(value).endswith(".dist-info/RECORD")
    ]
    require(len(record_files) == 1,
            "box-control-installed", "aggregate RECORD path is ambiguous")
    record_path = Path(distribution.locate_file(record_files[0]))
    _protected_ancestry(record_path, root)
    info = record_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            "box-control-installed", "aggregate RECORD is not a protected file")
    return rows, _sha256(text.encode()), str(record_path)


def verify_installed(*, python_executable="/usr/bin/python3"):
    """Attest actual aggregate-loaded Python bytes against the reviewed Git tree."""
    require(os.geteuid() == 0, "root-required",
            "installed software attestation requires root")
    require(not os.environ.get("PYTHONPATH"),
            "box-control-installed",
            "writable or caller-selected PYTHONPATH is not permitted")
    python_executable = _absolute(
        python_executable, "canonical approved Python executable required"
    )
    configured_python = Path(python_executable)
    require(configured_python.exists(),
            "box-control-installed", "approved Python executable is unavailable")
    running_python = Path(sys.executable).resolve()
    require(configured_python.resolve() == running_python,
            "box-control-installed",
            "attestation interpreter differs from approved service interpreter")
    _protected_ancestry(running_python, Path("/"))

    try:
        distribution = importlib.metadata.distribution("zog")
    except importlib.metadata.PackageNotFoundError:
        require(False, "box-control-installed",
                "aggregate zog distribution is not installed")
    require(distribution.metadata.get("Name") == "zog",
            "box-control-installed", "unexpected aggregate distribution name")
    root = Path(distribution.locate_file("")).resolve()
    _protected_ancestry(root, Path("/"))
    record, record_sha256, record_origin = _wheel_record(distribution, root)

    observed = {}
    for module, expected_blob in BOX_CONTROL_MODULE_BLOBS.items():
        loaded = importlib.import_module(module)
        origin = getattr(loaded, "__file__", None)
        require(type(origin) is str,
                "box-control-installed", "loaded module has no filesystem origin")
        path = Path(origin)
        _protected_ancestry(path, root)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "box-control-installed", "loaded module is not a protected regular file")
        data = path.read_bytes()
        require(len(data) <= 262144,
                "box-control-installed", "installed observer module exceeds size bound")
        git_blob = _git_blob_sha(data)
        require(git_blob == expected_blob,
                "box-control-installed",
                "installed observer bytes differ from reviewed source")
        relative = path.resolve().relative_to(root).as_posix()
        require(relative in record,
                "box-control-installed", "loaded module absent from aggregate RECORD")
        algorithm, separator, encoded = record[relative][0].partition("=")
        require(separator == "=" and algorithm == "sha256"
                and encoded == _record_sha256(data),
                "box-control-installed",
                "aggregate RECORD hash disagrees with loaded module")
        observed[module] = {
            "origin": str(path.resolve()),
            "git_blob": git_blob,
            "sha256": _sha256(data),
            "record_path": relative,
        }

    return {
        "schema": "zog-host-welcome-progress-installed-attestation-v1",
        "status": "box-control-observer-installed-software-verified",
        "box_control_source_commit": BOX_CONTROL_COMMIT,
        "distribution": {
            "name": distribution.metadata["Name"],
            "version": distribution.version,
            "root": str(root),
            "record_origin": record_origin,
            "record_sha256": record_sha256,
        },
        "python_executable": str(running_python),
        "pythonpath_present": False,
        "modules": observed,
        "mutation_authorized": False,
        "production_activation_authorized": False,
    }


def _render(name, replacements):
    text = resource_files(__package__).joinpath("systemd", name).read_text()
    for key, value in replacements.items():
        text = text.replace("@" + key + "@", value)
    require("@" not in text, "welcome-progress-template",
            "unresolved unit template marker")
    return text.encode()


def stage(*, output, controller_project, consumer_uid, controller_uid,
          controller_gid, box_control_source,
          python_executable="/usr/bin/python3", producer_source=None,
          identity_evidence=None):
    """Internal deterministic staging primitive using already-verified numeric IDs."""
    require(os.geteuid() == 0, "root-required",
            "host-welcome progress profile staging requires root")
    controller_project = _absolute(
        controller_project, "canonical controller project required"
    )
    python_executable = _absolute(
        python_executable, "canonical Python executable required"
    )
    consumer_uid_text = _numeric(
        consumer_uid, "authoritative host-welcome consumer UID required"
    )
    controller_uid_text = _numeric(
        controller_uid, "controller owner UID required"
    )
    controller_gid_text = _numeric(
        controller_gid, "controller owner GID required"
    )
    require(consumer_uid != controller_uid, "welcome-progress-profile",
            "host-welcome consumer and controller owner must be distinct UIDs")
    source_blobs = verify_reviewed_source(box_control_source)

    replacements = {
        "WELCOME_UID": consumer_uid_text,
        "CONTROLLER_UID": controller_uid_text,
        "CONTROLLER_GID": controller_gid_text,
        "CONTROLLER_PROJECT": controller_project,
        "PYTHON_EXECUTABLE": python_executable,
    }
    rendered = {
        UNIT_SOCKET: _render(UNIT_SOCKET + ".in", replacements),
        UNIT_SERVICE: _render(UNIT_SERVICE + ".in", replacements),
    }
    if producer_source is not None:
        packaged = resource_files(__package__).joinpath("systemd")
        for template in (UNIT_SOCKET + ".in", UNIT_SERVICE + ".in"):
            require(
                (Path(producer_source) / "examples/systemd" / template).read_bytes()
                == packaged.joinpath(template).read_bytes(),
                "welcome-progress-template",
                "packaged/reference template mismatch",
            )

    policy = {
        "schema": POLICY_SCHEMA,
        "enabled": True,
        "consumer_uid": consumer_uid,
        "controller_owner_uid": controller_uid,
        "socket": SOCKET_PATH,
        "box_control_source_commit": BOX_CONTROL_COMMIT,
    }
    manifest = {
        "schema": 2,
        "kind": PROFILE_KIND,
        "runtime_model": "host-rootfs-bootstrap-consumer",
        "consumer_uid": consumer_uid,
        "controller_owner_uid": controller_uid,
        "controller_owner_gid": controller_gid,
        "controller_project": controller_project,
        "identity_evidence": identity_evidence,
        "socket": SOCKET_PATH,
        "policy": POLICY_PATH,
        "root_control_socket": ROOT_CONTROL_SOCKET,
        "python_executable": python_executable,
        "box_control_source_commit": BOX_CONTROL_COMMIT,
        "box_control_module_source_inventory": source_blobs,
        "visibility": {
            "host_welcome_socket": SOCKET_PATH,
            "host_welcome_policy": POLICY_PATH,
            "station_progress_socket_inherited": False,
            "raw_state_inherited": False,
            "controller_credentials_inherited": False,
            "root_control_socket_inherited_by_consumer": False,
            "arbitrary_host_run_binding": False,
        },
        "units": {
            UNIT_SOCKET: "enable-after-installed-software-attestation-and-native-acceptance",
            UNIT_SERVICE: "socket-activated",
        },
        "boot_dependencies": {
            "state": False,
            "station_access": False,
            "root_control_for_getty": False,
            "network": False,
            "image_build": False,
            "graphics": False,
            "getty_requires_observer": False,
        },
        "mutation_authority": {
            "controller_build": False,
            "application_launch": False,
            "login_manager": False,
            "state_write": False,
            "reboot": False,
        },
    }

    output = Path(output).absolute()
    parent = directory(str(output.parent))
    root = None
    try:
        root = ensure_directory(parent, output.name, 0, 0, 0o700)
        with lock(root):
            allowed = {
                ".host-install.lock", "profile.json", ".pending.profile.json",
                "etc", ".pending-dir.etc",
            }
            require(set(os.listdir(root)) <= allowed,
                    "profile-conflict",
                    "unexpected host-welcome observer overlay contents")
            publish(root, "profile.json", canonical(manifest), 0o444)

            etc = systemd = system = zog = None
            try:
                etc = ensure_directory(root, "etc", 0, 0, 0o755)
                systemd = ensure_directory(etc, "systemd", 0, 0, 0o755)
                system = ensure_directory(systemd, "system", 0, 0, 0o755)
                for name, data in rendered.items():
                    publish(system, name, data, 0o444)
                zog = ensure_directory(etc, "zog", 0, 0, 0o755)
                publish(
                    zog,
                    "host-welcome-progress-observer.json",
                    canonical(policy),
                    0o444,
                )
            finally:
                for fd in (zog, system, systemd, etc):
                    if fd is not None:
                        os.close(fd)
        return {
            "status": "host-welcome-progress-profile-staged",
            "output": str(output),
            "consumer_uid": consumer_uid,
            "controller_owner_uid": controller_uid,
            "socket": SOCKET_PATH,
            "policy": POLICY_PATH,
            "services_enabled": False,
            "installed_software_verified": False,
            "state_modified": False,
        }
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)


def stage_live(*, output, controller_project, box_control_source,
               python_executable="/usr/bin/python3", producer_source=None):
    """Resolve independent live identities and stage the exact dedicated profile."""
    identities = resolve_live_identities(controller_project)
    return stage(
        output=output,
        controller_project=identities["controller_project"],
        consumer_uid=identities["consumer_uid"],
        controller_uid=identities["controller_uid"],
        controller_gid=identities["controller_gid"],
        box_control_source=box_control_source,
        python_executable=python_executable,
        producer_source=producer_source,
        identity_evidence=identities["evidence"],
    )
