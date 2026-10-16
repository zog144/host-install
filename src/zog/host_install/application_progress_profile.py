"""Root-owned deployment profile for the box-control application-progress observer.

The station consumer identity comes from the protected execution-identity grant
and is supplied as a numeric UID/GID. No account name is resolved or trusted.
"""
from importlib.resources import files as resource_files
import os
from pathlib import Path
import re

from .state_contract import canonical, decode, fields, require
from .state_inspect import directory
from .state_io import ensure_directory, lock, publish

PROFILE_KIND = "zog-application-progress-observer-profile-v1"
BOX_CONTROL_COMMIT = "03c847ec6adc55fd5e2268534d47b500d9f52ab9"
HOST_SOCKET = "/run/zog-host-export/application-progress/application-progress.sock"
CONSUMER_SOCKET = "/run/zog-host/application-progress/application-progress.sock"
ROOT_CONTROL_SOCKET = "/run/zog/root-control.sock"
UNIT_SOCKET = "zog-application-progress.socket"
UNIT_SERVICE = "zog-application-progress.service"
CAPABILITY = "application-progress"
_APPLICATION = "station-access"
_PROGRAM = "web"
_SIMPLE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z")


def _numeric(value, label):
    require(type(value) is int and 0 < value < 2**31, "progress-profile", label)
    return str(value)


def _absolute(path, label):
    value = str(path)
    parsed = Path(value)
    require(_SIMPLE_PATH.fullmatch(value) is not None and str(parsed) == value
            and ".." not in parsed.parts and "." not in parsed.parts,
            "progress-profile", label)
    return value


def _policy(raw):
    if raw is None:
        return {"schema": 1, "bindings": []}
    value = decode(raw)
    fields(value, "schema bindings")
    require(value["schema"] == 1 and type(value["bindings"]) is list
            and len(value["bindings"]) <= 127,
            "progress-host-bindings", "unsupported or excessive host binding policy")
    for item in value["bindings"]:
        fields(item, "project application program capability source")
        require(all(type(item[key]) is str for key in item),
                "progress-host-bindings", "host binding fields must be strings")
    return value


def merge_host_bindings(raw, controller_project):
    """Add exactly one station web read-only host-export capability."""
    policy = _policy(raw)
    entry = {
        "project": controller_project,
        "application": _APPLICATION,
        "program": _PROGRAM,
        "capability": CAPABILITY,
        "source": str(Path(HOST_SOCKET).parent),
    }
    identity = (controller_project, _APPLICATION, _PROGRAM, CAPABILITY)
    found = [
        item for item in policy["bindings"]
        if (item["project"], item["application"], item["program"], item["capability"]) == identity
    ]
    require(len(found) <= 1, "progress-host-bindings",
            "duplicate application-progress capability")
    if found:
        require(found[0] == entry, "progress-host-bindings",
                "existing application-progress capability disagrees")
    else:
        policy["bindings"].append(entry)
    policy["bindings"] = sorted(
        policy["bindings"],
        key=lambda item: (
            item["project"], item["application"], item["program"],
            item["capability"], item["source"],
        ),
    )
    return policy


def _render(name, replacements):
    text = resource_files(__package__).joinpath("systemd", name).read_text()
    for key, value in replacements.items():
        text = text.replace("@" + key + "@", value)
    require("@" not in text, "progress-template", "unresolved unit template marker")
    return text.encode()


def stage(*, output, controller_project, station_uid, station_gid,
          controller_uid, controller_gid, host_bindings_policy,
          python_executable="/usr/bin/python3", producer_source=None):
    """Stage a root-owned deployable overlay; never infer UIDs from usernames."""
    require(os.geteuid() == 0, "root-required",
            "application-progress profile staging requires root")
    controller_project = _absolute(controller_project, "canonical controller project required")
    python_executable = _absolute(python_executable, "canonical Python executable required")
    station_uid_text = _numeric(station_uid, "station consumer UID required")
    station_gid_text = _numeric(station_gid, "station consumer GID required")
    controller_uid_text = _numeric(controller_uid, "controller owner UID required")
    controller_gid_text = _numeric(controller_gid, "controller owner GID required")
    require(station_uid != controller_uid, "progress-profile",
            "station consumer and controller owner must be distinct UIDs")

    policy_path = Path(host_bindings_policy)
    raw_policy = policy_path.read_bytes()
    require(len(raw_policy) <= 65536, "progress-host-bindings",
            "host binding policy exceeds 64 KiB")
    policy = merge_host_bindings(raw_policy, controller_project)

    replacements = {
        "STATION_UID": station_uid_text,
        "STATION_GID": station_gid_text,
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
            require((Path(producer_source) / "examples/systemd" / template).read_bytes()
                    == packaged.joinpath(template).read_bytes(),
                    "progress-template", "packaged/reference template mismatch")

    manifest = {
        "schema": 1,
        "kind": PROFILE_KIND,
        "box_control_source_commit": BOX_CONTROL_COMMIT,
        "controller_project": controller_project,
        "controller_uid": controller_uid,
        "controller_gid": controller_gid,
        "station_consumer_uid": station_uid,
        "station_consumer_gid": station_gid,
        "host_socket": HOST_SOCKET,
        "consumer_socket": CONSUMER_SOCKET,
        "root_control_socket": ROOT_CONTROL_SOCKET,
        "host_binding": {
            "project": controller_project,
            "application": _APPLICATION,
            "program": _PROGRAM,
            "capability": CAPABILITY,
            "source": str(Path(HOST_SOCKET).parent),
            "destination": str(Path(CONSUMER_SOCKET).parent),
            "access": "read-only",
        },
        "station_settings": {
            "STATION_ACCESS_APPLICATION_PROGRESS_ENABLED": "1",
            "STATION_ACCESS_APPLICATION_PROGRESS_SOCKET": CONSUMER_SOCKET,
            "STATION_ACCESS_APPLICATION_PROGRESS_CONTROLLER_UID": controller_uid_text,
        },
        "units": {
            UNIT_SOCKET: "enable",
            UNIT_SERVICE: "socket-activated",
        },
        "mutation_authority": {
            "controller_build": False,
            "application_launch": False,
            "login_manager": False,
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
            require(set(os.listdir(root)) <= allowed, "profile-conflict",
                    "unexpected application-progress overlay contents")
            publish(root, "profile.json", canonical(manifest), 0o444)

            etc = ensure_directory(root, "etc", 0, 0, 0o755)
            systemd = zog = system = None
            try:
                systemd = ensure_directory(etc, "systemd", 0, 0, 0o755)
                system = ensure_directory(systemd, "system", 0, 0, 0o755)
                for name, content in rendered.items():
                    publish(system, name, content, 0o444)
                zog = ensure_directory(etc, "zog", 0, 0, 0o755)
                publish(zog, "host-bindings.json", canonical(policy), 0o444)
            finally:
                for fd in (zog, system, systemd, etc):
                    if fd is not None:
                        os.close(fd)
        return {
            "status": "application-progress-profile-staged",
            "output": str(output),
            "station_consumer_uid": station_uid,
            "controller_uid": controller_uid,
            "socket": HOST_SOCKET,
            "services_enabled": False,
            "state_modified": False,
        }
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)
