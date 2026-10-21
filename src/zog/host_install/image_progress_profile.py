"""Protected deployment profile for host-welcome's image-build progress observer.

The producer-owned deployment reference is pinned separately from the reviewed
runtime projection source. This module stages root-owned policy/units only. It
never enables the unit, mutates image-build state, starts build work, or grants
graphical readiness.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib
import importlib.metadata
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


PROFILE_KIND = "zog-host-welcome-image-progress-observer-profile-v1"
DEPLOYMENT_CONTRACT = "image-build-post-install-progress-native-deployment-v2"
TRANSPORT_AUTH = "image-build-post-install-progress-linux-credentials-v1"
POLICY_SCHEMA = "zog-host-welcome-image-progress-observer-v1"
POLICY_PATH = "/etc/zog/host-welcome-image-progress-observer.json"
SOCKET_PATH = "/run/host-welcome/image-progress.sock"
UNIT_SOCKET = "zog-host-welcome-image-progress.socket"
UNIT_SERVICE = "zog-host-welcome-image-progress.service"

IMAGE_BUILD_REPOSITORY = "zog144/image-build"
IMAGE_BUILD_COMMIT = "7348ec730a3181f1a8ecc62a6e4d633ce191674a"
IMAGE_BUILD_DEPLOYMENT_COMMIT = "10d5c89f9ad865f3f58094ba2b5a629c211d918d"
IMAGE_BUILD_DEPLOYMENT_MODULE_BLOB = "0ed5e383f0aeaa49761a82cfc94b7cc3148075da"
IMAGE_BUILD_SOCKET_TEMPLATE_BLOB = "8e7e7bbd6af41572441f33e8db178f6588e117d6"
IMAGE_BUILD_SERVICE_TEMPLATE_BLOB = "111d878e873a0c393153cedb148c2003b227cbc7"
HOST_WELCOME_CONSUMER_COMMIT = "6edb11140a44a10061e5308fab03a43d9008dbfc"

GRAPHICAL_APPLICATIONS = (
    "agreety",
    "firefox-esr",
    "greetd",
    "i3",
    "xorg-server",
)

IMAGE_BUILD_MODULE_BLOBS = {
    "zog.image_build.post_install_progress_broker":
        "e7ba6eab10e70e91fc5921bba1eec26f31ace1db",
    "zog.image_build.post_install_progress":
        "5c4e03e1f496b704935caabebfa7eca63188f89e",
    "zog.image_build.application_software":
        "736cffeb3e42811f93bebb50a0fa9c52e4a7b52b",
    "zog.image_build.application_views":
        "91c144628a9cb5293706fb1114a7063dd30d9291",
    "zog.image_build.build_views":
        "7581de78d0d70dbfa1a1f7a2e308cd43fd3bec1c",
    "zog.image_build.errors":
        "dc80cc8438eab55c5438172328ae778e914f506a",
    "zog.image_build.filesystem":
        "1f6c1fa8628118de5ec2e6c727fd6b725498a99f",
    "zog.image_build.metadata":
        "79238579b11e87070886b2fd0125a186a94fd29e",
    "zog.image_build.engine":
        "c65a948ae027850247dee6da8999f121ee3397a4",
    "zog.image_build.rootfs_compatibility":
        "3adbef4cdcef29a89bdc309eab30aeb40be167e2",
    "zog.image_build.artifact_observations":
        "5ca72fc4e3f04a921860ad99853c1981ecf7c188",
    "zog.image_build.runtime_facilities":
        "651f5ceb35f40aae5831ead08d97495575740dff",
    "zog.image_build.application_data_targets":
        "94b5e69dcbe5ad30c4e98787fc217910a38e074e",
}
_SOURCE_FILES = {
    module: "src/" + module.replace(".", "/") + ".py"
    for module in IMAGE_BUILD_MODULE_BLOBS
}
_DEPLOYMENT_FILES = {
    "src/zog/image_build/post_install_progress_deployment.py":
        IMAGE_BUILD_DEPLOYMENT_MODULE_BLOB,
    "examples/systemd/zog-host-welcome-image-progress.socket.in":
        IMAGE_BUILD_SOCKET_TEMPLATE_BLOB,
    "examples/systemd/zog-host-welcome-image-progress.service.in":
        IMAGE_BUILD_SERVICE_TEMPLATE_BLOB,
}

_SIMPLE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z")
_VOLATILE_ROOTS = (
    Path("/run"), Path("/tmp"), Path("/var/tmp"),
    Path("/dev"), Path("/proc"), Path("/sys"),
)


def _numeric(value, label):
    require(type(value) is int and 0 < value < 2**31,
            "image-progress-profile", label)
    return str(value)


def _absolute(value, label):
    text = str(value)
    parsed = Path(text)
    require(
        _SIMPLE_PATH.fullmatch(text) is not None
        and str(parsed) == text
        and ".." not in parsed.parts
        and "." not in parsed.parts
        and parsed != Path("/"),
        "image-progress-profile",
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
    return base64.urlsafe_b64encode(
        hashlib.sha256(data).digest()
    ).rstrip(b"=").decode()


def _protected_ancestry(path, stop, *, code="image-build-installed"):
    path = Path(path)
    stop = Path(stop)
    require(path.is_absolute() and stop.is_absolute(), code,
            "protected path must be absolute")
    try:
        path.relative_to(stop)
    except ValueError:
        require(False, code, "path is outside approved root")
    current = path
    while True:
        info = current.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and info.st_uid == 0
            and not (info.st_mode & 0o022),
            code,
            "installed software path is redirected or writable",
        )
        if current == stop:
            break
        current = current.parent


def _producer_permissions(info, uid, gids):
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid == uid:
        return (mode >> 6) & 0o7
    if info.st_gid in gids:
        return (mode >> 3) & 0o7
    return mode & 0o7


def _protected_state_ancestry(state_root, producer_uid, producer_gids):
    current = Path("/")
    for part in Path(state_root).parts[1:]:
        current /= part
        info = current.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and not (info.st_mode & 0o022)
            and info.st_uid in (0, producer_uid),
            "image-build-identity",
            "image-build state ancestry is not protected",
        )
        require(
            _producer_permissions(info, producer_uid, producer_gids) & 0o1,
            "image-build-identity",
            "image-build producer cannot traverse protected state ancestry",
        )


def resolve_live_identities(image_build_state_root):
    """Resolve welcome and producer identities from independent live host facts."""
    require(os.geteuid() == 0, "root-required",
            "live image observer identity resolution requires root")
    state_text = _absolute(
        image_build_state_root, "canonical image-build state root required"
    )
    state_root = Path(state_text)
    require(
        not any(state_root == root or root in state_root.parents
                for root in _VOLATILE_ROOTS),
        "image-build-identity",
        "image-build state root must be durable",
    )

    state_info = state_root.lstat()
    require(
        stat.S_ISDIR(state_info.st_mode)
        and not stat.S_ISLNK(state_info.st_mode)
        and not (state_info.st_mode & 0o022),
        "image-build-identity",
        "image-build state root is not protected",
    )
    component = state_root / "image-build"
    component_info = component.lstat()
    require(
        stat.S_ISDIR(component_info.st_mode)
        and not stat.S_ISLNK(component_info.st_mode)
        and component_info.st_uid > 0
        and component_info.st_gid > 0
        and not (component_info.st_mode & 0o022),
        "image-build-identity",
        "image-build component state has unsafe ownership or permissions",
    )
    producer_uid = component_info.st_uid
    producer_gid = component_info.st_gid

    try:
        owner = pwd.getpwuid(producer_uid)
    except KeyError:
        require(False, "image-build-identity",
                "image-build state owner has no host account")
    require(
        owner.pw_uid == producer_uid
        and owner.pw_gid == producer_gid
        and len([row for row in pwd.getpwall()
                 if row.pw_uid == producer_uid]) == 1,
        "image-build-identity",
        "image-build host account disagrees with state ownership",
    )
    producer_gids = set(os.getgrouplist(owner.pw_name, producer_gid))
    _protected_state_ancestry(state_root, producer_uid, producer_gids)
    require(
        _producer_permissions(state_info, producer_uid, producer_gids) & 0o5 == 0o5
        and _producer_permissions(component_info, producer_uid, producer_gids) & 0o5 == 0o5,
        "image-build-identity",
        "image-build producer cannot read/traverse its fixed state root",
    )

    consumer_uid, consumer_gid = welcome_account()
    require(
        consumer_uid != producer_uid,
        "image-progress-profile",
        "host-welcome consumer and image-build producer must be distinct UIDs",
    )
    return {
        "consumer_uid": consumer_uid,
        "consumer_gid": consumer_gid,
        "producer_uid": producer_uid,
        "producer_gid": producer_gid,
        "image_build_state_root": state_text,
        "evidence": {
            "welcome_account": "host-account-database",
            "image_build_state_owner": str(component),
            "image_build_account": owner.pw_name,
        },
    }


def verify_reviewed_source(source):
    """Verify producer deployment reference plus the 13 runtime source blobs."""
    root = Path(source)
    require(root.is_dir() and not root.is_symlink(),
            "image-build-source",
            "reviewed image-build deployment source root unavailable")

    deployment = {}
    for relative, expected in _DEPLOYMENT_FILES.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                "image-build-source",
                "reviewed image-build deployment reference missing or redirected")
        data = path.read_bytes()
        blob = _git_blob_sha(data)
        require(blob == expected,
                "image-build-source",
                "image-build deployment reference differs from reviewed revision")
        deployment[relative] = {
            "git_blob": blob,
            "sha256": _sha256(data),
        }

    observed = {}
    for module, relative in _SOURCE_FILES.items():
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                "image-build-source",
                "reviewed image-build observer source missing or redirected")
        data = path.read_bytes()
        require(0 < len(data) <= 2_000_000,
                "image-build-source",
                "reviewed image-build observer source exceeds size bound")
        blob = _git_blob_sha(data)
        require(
            blob == IMAGE_BUILD_MODULE_BLOBS[module],
            "image-build-source",
            "image-build observer dependency differs from reviewed source",
        )
        observed[module] = {
            "git_blob": blob,
            "sha256": _sha256(data),
            "path": relative,
        }
    return {
        "deployment_reference": deployment,
        "runtime_modules": observed,
    }


def _wheel_record(distribution, root):
    text = distribution.read_text("RECORD")
    require(type(text) is str and 0 < len(text) <= 4_000_000,
            "image-build-installed",
            "aggregate wheel RECORD missing or excessive")
    rows = {}
    for row in csv.reader(io.StringIO(text)):
        require(len(row) == 3 and row[0] not in rows,
                "image-build-installed", "invalid aggregate wheel RECORD")
        rows[row[0]] = (row[1], row[2])
    record_files = [
        value for value in distribution.files or ()
        if str(value).endswith(".dist-info/RECORD")
    ]
    require(len(record_files) == 1,
            "image-build-installed", "aggregate RECORD path is ambiguous")
    record_path = Path(distribution.locate_file(record_files[0]))
    _protected_ancestry(record_path, root)
    info = record_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            "image-build-installed", "aggregate RECORD is not a protected file")
    return rows, _sha256(text.encode()), str(record_path)


def verify_installed(*, python_executable="/usr/bin/python3"):
    """Attest the 13 producer-defined security-critical runtime modules."""
    require(os.geteuid() == 0, "root-required",
            "installed image-build observer attestation requires root")
    require(not os.environ.get("PYTHONPATH"),
            "image-build-installed",
            "inherited PYTHONPATH is not permitted")
    require(not os.environ.get("PYTHONHOME"),
            "image-build-installed",
            "inherited PYTHONHOME is not permitted")
    python_executable = _absolute(
        python_executable, "canonical approved Python executable required"
    )
    configured_python = Path(python_executable)
    require(configured_python.exists(),
            "image-build-installed", "approved Python executable is unavailable")
    running_python = Path(sys.executable).resolve()
    require(configured_python.resolve() == running_python,
            "image-build-installed",
            "attestation interpreter differs from approved service interpreter")
    _protected_ancestry(running_python, Path("/"))

    try:
        distribution = importlib.metadata.distribution("zog")
    except importlib.metadata.PackageNotFoundError:
        require(False, "image-build-installed",
                "aggregate zog distribution is not installed")
    require(distribution.metadata.get("Name") == "zog",
            "image-build-installed", "unexpected aggregate distribution name")
    root = Path(distribution.locate_file("")).resolve()
    _protected_ancestry(root, Path("/"))
    record, record_sha256, record_origin = _wheel_record(distribution, root)

    observed = {}
    for module, expected_blob in IMAGE_BUILD_MODULE_BLOBS.items():
        loaded = importlib.import_module(module)
        origin = getattr(loaded, "__file__", None)
        require(type(origin) is str,
                "image-build-installed",
                "loaded image-build module has no filesystem origin")
        path = Path(origin)
        _protected_ancestry(path, root)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "image-build-installed",
                "loaded image-build module is not a protected regular file")
        data = path.read_bytes()
        require(0 < len(data) <= 2_000_000,
                "image-build-installed",
                "installed image-build module exceeds size bound")
        git_blob = _git_blob_sha(data)
        require(git_blob == expected_blob,
                "image-build-installed",
                "installed image-build bytes differ from reviewed source")
        relative = path.resolve().relative_to(root).as_posix()
        require(relative in record,
                "image-build-installed",
                "loaded image-build module absent from aggregate RECORD")
        algorithm, separator, encoded = record[relative][0].partition("=")
        require(separator == "=" and algorithm == "sha256"
                and encoded == _record_sha256(data),
                "image-build-installed",
                "aggregate RECORD hash disagrees with loaded image-build module")
        observed[module] = {
            "origin": str(path.resolve()),
            "git_blob": git_blob,
            "sha256": _sha256(data),
            "record_path": relative,
        }

    return {
        "schema": "zog-host-welcome-image-progress-installed-attestation-v1",
        "status": "image-build-observer-installed-software-verified",
        "deployment_contract": DEPLOYMENT_CONTRACT,
        "transport_auth": TRANSPORT_AUTH,
        "image_build_source_repository": IMAGE_BUILD_REPOSITORY,
        "image_build_source_commit": IMAGE_BUILD_COMMIT,
        "image_build_deployment_reference_commit": IMAGE_BUILD_DEPLOYMENT_COMMIT,
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
    require("@" not in text, "image-progress-template",
            "unresolved unit template marker")
    return text.encode()


def stage(*, output, image_build_state_root, consumer_uid, producer_uid,
          producer_gid, image_build_source, python_executable="/usr/bin/python3",
          producer_source=None, identity_evidence=None):
    """Stage exact producer reference with already-verified numeric identities."""
    require(os.geteuid() == 0, "root-required",
            "host-welcome image progress profile staging requires root")
    state_root = _absolute(
        image_build_state_root, "canonical image-build state root required"
    )
    python_executable = _absolute(
        python_executable, "canonical Python executable required"
    )
    welcome_uid = _numeric(
        consumer_uid, "authoritative host-welcome consumer UID required"
    )
    image_uid = _numeric(producer_uid, "image-build producer UID required")
    image_gid = _numeric(producer_gid, "image-build producer GID required")
    require(consumer_uid != producer_uid, "image-progress-profile",
            "host-welcome consumer and image-build producer must be distinct UIDs")

    reviewed = verify_reviewed_source(image_build_source)

    replacements = {
        "WELCOME_UID": welcome_uid,
        "IMAGE_BUILD_UID": image_uid,
        "IMAGE_BUILD_GID": image_gid,
        "IMAGE_BUILD_STATE": state_root,
        "PYTHON_EXECUTABLE": python_executable,
    }
    rendered = {
        UNIT_SOCKET: _render(UNIT_SOCKET + ".in", replacements),
        UNIT_SERVICE: _render(UNIT_SERVICE + ".in", replacements),
    }

    # Packaged templates must be byte-identical to producer-owned deployment
    # reference templates before any root-owned overlay can be staged.
    reference_templates = {
        UNIT_SOCKET: "examples/systemd/" + UNIT_SOCKET + ".in",
        UNIT_SERVICE: "examples/systemd/" + UNIT_SERVICE + ".in",
    }
    for unit, relative in reference_templates.items():
        reference = (Path(image_build_source) / relative).read_bytes()
        packaged = resource_files(__package__).joinpath(
            "systemd", unit + ".in"
        ).read_bytes()
        require(packaged == reference,
                "image-progress-template",
                "packaged image-build observer template differs from producer reference")

    if producer_source is not None:
        packaged = resource_files(__package__).joinpath("systemd")
        for template in (UNIT_SOCKET + ".in", UNIT_SERVICE + ".in"):
            require(
                (Path(producer_source) / "examples/systemd" / template).read_bytes()
                == packaged.joinpath(template).read_bytes(),
                "image-progress-template",
                "packaged/reference host-install template mismatch",
            )

    policy = {
        "schema": POLICY_SCHEMA,
        "enabled": True,
        "consumer_uid": consumer_uid,
        "producer_uid": producer_uid,
        "socket": SOCKET_PATH,
        "image_build_source_commit": IMAGE_BUILD_COMMIT,
    }
    manifest = {
        "schema": 1,
        "kind": PROFILE_KIND,
        "deployment_contract": DEPLOYMENT_CONTRACT,
        "transport_auth": TRANSPORT_AUTH,
        "runtime_model": "host-rootfs-bootstrap-consumer",
        "consumer_uid": consumer_uid,
        "producer_uid": producer_uid,
        "producer_gid": producer_gid,
        "image_build_state_root": state_root,
        "identity_evidence": identity_evidence,
        "socket": SOCKET_PATH,
        "policy": POLICY_PATH,
        "python_executable": python_executable,
        "image_build_source_repository": IMAGE_BUILD_REPOSITORY,
        "image_build_source_commit": IMAGE_BUILD_COMMIT,
        "image_build_deployment_reference_commit": IMAGE_BUILD_DEPLOYMENT_COMMIT,
        "host_welcome_consumer_commit": HOST_WELCOME_CONSUMER_COMMIT,
        "application_allowlist": list(GRAPHICAL_APPLICATIONS),
        "image_build_reviewed_source": reviewed,
        "selection_binding": {
            "owner": "host-install",
            "receipt_and_sequence_required": True,
            "selected_rootfs_generation_required_for_compatible_view": True,
            "absence_or_mismatch": "unknown",
        },
        "boot_recovery_policy": {
            "snapshot_must_name_current_boot": True,
            "retained_terminal_command_may_name_older_controller_boot": True,
            "selection_and_publication_may_survive_reboot": True,
            "observer_may_not_resume_or_retry_work": True,
        },
        "visibility": {
            "host_welcome_socket": SOCKET_PATH,
            "host_welcome_policy": POLICY_PATH,
            "station_progress_socket_inherited": False,
            "controller_progress_socket_inherited": False,
            "root_control_socket_inherited": False,
            "raw_image_build_state_inherited": False,
            "image_build_credentials_inherited": False,
            "arbitrary_host_run_binding": False,
        },
        "units": {
            UNIT_SOCKET: "enable-after-installed-software-attestation-and-native-acceptance",
            UNIT_SERVICE: "socket-activated",
        },
        "boot_dependencies": {
            "state": False,
            "station_access": False,
            "box_control_for_getty": False,
            "network": False,
            "image_build": False,
            "graphics": False,
            "getty_requires_observer": False,
        },
        "mutation_authority": {
            "submit": False,
            "resume": False,
            "cancel": False,
            "publish": False,
            "install": False,
            "service_start": False,
            "state_write": False,
            "reboot": False,
        },
        "services_enabled": False,
        "installed_software_verified": False,
        "production_activation_authorized": False,
        "native_acceptance_complete": False,
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
                    "unexpected image observer overlay contents")
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
                    "host-welcome-image-progress-observer.json",
                    canonical(policy),
                    0o444,
                )
            finally:
                for fd in (zog, system, systemd, etc):
                    if fd is not None:
                        os.close(fd)
        return {
            "status": "host-welcome-image-progress-profile-staged",
            "output": str(output),
            "consumer_uid": consumer_uid,
            "producer_uid": producer_uid,
            "socket": SOCKET_PATH,
            "policy": POLICY_PATH,
            "services_enabled": False,
            "installed_software_verified": False,
            "production_activation_authorized": False,
            "state_modified": False,
        }
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)


def stage_live(*, output, image_build_state_root, image_build_source,
               python_executable="/usr/bin/python3", producer_source=None):
    """Resolve independent live UIDs and stage the exact producer-owned role."""
    identities = resolve_live_identities(image_build_state_root)
    return stage(
        output=output,
        image_build_state_root=identities["image_build_state_root"],
        consumer_uid=identities["consumer_uid"],
        producer_uid=identities["producer_uid"],
        producer_gid=identities["producer_gid"],
        image_build_source=image_build_source,
        python_executable=python_executable,
        producer_source=producer_source,
        identity_evidence=identities["evidence"],
    )
