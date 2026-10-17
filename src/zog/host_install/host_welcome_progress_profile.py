"""Dedicated host-welcome controller-progress observer deployment.

This is intentionally separate from the station-access application-progress
profile. The host-welcome console is a host-rootfs bootstrap consumer and gets
only its own fixed socket plus a small root-owned policy file.
"""
from __future__ import annotations

import hashlib
import importlib.util
from importlib.resources import files as resource_files
import os
from pathlib import Path
import re
import stat

from .state_contract import canonical, require
from .state_inspect import directory
from .state_io import ensure_directory, lock, publish

PROFILE_KIND = "zog-host-welcome-progress-observer-profile-v1"
POLICY_SCHEMA = "zog-host-welcome-progress-observer-v1"
POLICY_PATH = "/etc/zog/host-welcome-progress-observer.json"
SOCKET_PATH = "/run/host-welcome/controller-progress.sock"
ROOT_CONTROL_SOCKET = "/run/zog/root-control.sock"
UNIT_SOCKET = "zog-host-welcome-controller-progress.socket"
UNIT_SERVICE = "zog-host-welcome-controller-progress.service"

BOX_CONTROL_COMMIT = "644170fc441863307092f329bf7e23cb64eb33e2"
BOX_CONTROL_MODULE_BLOBS = {
    "zog.box_control.application_progress_broker":
        "d81ae4385dd9baa7a6031d61186f02c65b83c75f",
    "zog.box_control.application_progress_client":
        "31627205509c1c8faefdb29ebc955d9d34e72cc1",
}
_SOURCE_FILES = {
    "zog.box_control.application_progress_broker":
        "box-control/src/zog/box_control/application_progress_broker.py",
    "zog.box_control.application_progress_client":
        "box-control/src/zog/box_control/application_progress_client.py",
}
_SIMPLE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z")


def _numeric(value, label):
    require(type(value) is int and 0 < value < 2**31, "welcome-progress-profile", label)
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


def verify_reviewed_source(source):
    """Verify the two explicitly reviewed box-control observer module bytes."""
    root = Path(source)
    observed = {}
    for module, relative in _SOURCE_FILES.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                "box-control-source", "reviewed box-control module missing or redirected")
        data = path.read_bytes()
        require(len(data) <= 131072,
                "box-control-source", "reviewed box-control module exceeds size bound")
        digest = _git_blob_sha(data)
        require(digest == BOX_CONTROL_MODULE_BLOBS[module],
                "box-control-source", "box-control observer module differs from reviewed source")
        observed[module] = digest
    return observed


def verify_installed():
    """Compare actual imported broker/client source bytes with reviewed Git blobs."""
    observed = {}
    for module, expected in BOX_CONTROL_MODULE_BLOBS.items():
        spec = importlib.util.find_spec(module)
        require(spec is not None and type(spec.origin) is str,
                "box-control-installed", "box-control observer module is not installed")
        path = Path(spec.origin)
        try:
            info = path.lstat()
        except OSError as exc:
            raise OSError("installed box-control observer module unavailable") from exc
        require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                "box-control-installed", "installed observer module is redirected")
        data = path.read_bytes()
        require(len(data) <= 131072,
                "box-control-installed", "installed observer module exceeds size bound")
        digest = _git_blob_sha(data)
        require(digest == expected,
                "box-control-installed", "installed observer bytes differ from reviewed source")
        observed[module] = digest
    return {
        "status": "box-control-observer-installed-bytes-verified",
        "box_control_source_commit": BOX_CONTROL_COMMIT,
        "modules": observed,
        "mutation_authorized": False,
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
          python_executable="/usr/bin/python3", producer_source=None):
    """Stage the dedicated host-welcome observer without enabling it."""
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
        "schema": 1,
        "kind": PROFILE_KIND,
        "runtime_model": "host-rootfs-bootstrap-consumer",
        "consumer_uid": consumer_uid,
        "controller_owner_uid": controller_uid,
        "controller_owner_gid": controller_gid,
        "controller_project": controller_project,
        "socket": SOCKET_PATH,
        "policy": POLICY_PATH,
        "root_control_socket": ROOT_CONTROL_SOCKET,
        "box_control_source_commit": BOX_CONTROL_COMMIT,
        "box_control_module_git_blobs": source_blobs,
        "visibility": {
            "host_welcome_socket": SOCKET_PATH,
            "host_welcome_policy": POLICY_PATH,
            "station_progress_socket_inherited": False,
            "raw_state_inherited": False,
            "controller_credentials_inherited": False,
            "arbitrary_host_run_binding": False,
        },
        "units": {
            UNIT_SOCKET: "enable-after-installed-byte-verification",
            UNIT_SERVICE: "socket-activated",
        },
        "boot_dependencies": {
            "state": False,
            "station_access": False,
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
                for name, content in rendered.items():
                    publish(system, name, content, 0o444)
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
            "installed_bytes_verified": False,
            "state_modified": False,
        }
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)
