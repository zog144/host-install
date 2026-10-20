"""Native-install staging and attestation for the certify-manage issuer.

This module consumes reviewed image-build, certify-manage, box-control and
root-control contracts. It stages root-owned deployment inputs but does not
prepare the application, issue a certificate, install hostname authority,
provision DNS credentials, enable systemd, or mutate ACME state.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import importlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys

from .state_contract import canonical, decode, fields, require
from .state_inspect import directory
from .state_io import ensure_directory, lock, publish


PROFILE_KIND = "zog-certify-manage-native-install-profile-v1"
INSTALL_SCHEMA = "zog-certify-manage-native-install-v1"
INSTALL_PATH = "/etc/zog/certify-manage/install.json"
POLICY_SOURCE = "/etc/zog/certify-policy"
POLICY_GUEST = "/run/zog-host/certify-policy"
LIFECYCLE_SOCKET = "/run/zog/certify-lifecycle.sock"
UNIT_SOCKET = "zog-certify-lifecycle.socket"
UNIT_SERVICE = "zog-certify-lifecycle.service"

IMAGE_BUILD_COMMIT = "b5cf3d761087c157b71724986bc94503089932a2"
IMAGE_BUILD_PRODUCER_BLOB = "ed69143e42d13db8e0165158af61c9d592394e7b"
CERTIFY_MANAGE_COMMIT = "b0e80b92a121678244f1a18fa2055ec769ea8852"
CERTIFY_APPLICATION_BLOB = "23b180f1f731dae67a06fcd1bdb994304c67390f"
BOX_CONTROL_COMMIT = "a3e939b7a22ef6277ae9712961ffbd5a18ccac39"
ROOT_CONTROL_COMMIT = "3a2dd9c935e332e811adaccedf04b16bd2de1ea7"

BOX_CONTROL_MODULE_BLOBS = {
    "zog.box_control.issuer_lifecycle_broker": "137799041bcbafc8ceec589bffbe43e1cb9f0e40",
    "zog.box_control.issuer_lifecycle_client": "662afc2a7718d2cd7d84763ad6f9364590a9e4b0",
    "zog.box_control.issuer_inspection_evidence": "47579c5f0fdbb7ef0c426f02a4f4f02f5495f122",
    "zog.box_control.role_broker": "16403f5c5612d10639e19f0e44defb4c9d0e5955",
    "zog.box_control.role_broker_client": "9e9f9866b3d707328503e6981f05876d00fbb6a8",
    "zog.box_control.runtime.root_control": "f05509294431957e385a07a6bbbe1e82c558f374",
    "zog.box_control.api": "b881183c5d493fc7390a25495e2a93121987c2c8",
    "zog.box_control.application_storage": "72a7cb0d5fc24870ad2336de7579c704a2461b15",
}
ROOT_CONTROL_MODULE_BLOBS = {
    "zog.root_control.daemon": "9af5e9178c74f9c4b11918bd6eacda13fe0267b6",
    "zog.root_control.systemd": "f6df19600493a55aff9df5d5fb932f1fb8c33e06",
    "zog.root_control.issuer_inspection_result": "fc810766fc2a2140770398bb503ab42442a24e30",
    "zog.root_control.issuer_observation": "3b8ac6f8bf8d541b6e24a96f9fcff5e4f64bc242",
    "zog.root_control.identities": "ef265ffd5340c189ecb59392e0541861201716b9",
}
INSTALLED_MODULE_BLOBS = {**BOX_CONTROL_MODULE_BLOBS, **ROOT_CONTROL_MODULE_BLOBS}

PROGRAMS = ("prepare", "issue", "renew", "inspect", "stage")
_SELECTED_BROKER_PROGRAMS = ("renew", "inspect", "stage")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_STORAGE = re.compile(r"[0-9a-f]{32}\Z")
_SIMPLE_PATH = re.compile(r"/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z")


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


def _absolute(value, label):
    value = str(value)
    path = Path(value)
    require(
        _SIMPLE_PATH.fullmatch(value) is not None
        and str(path) == value
        and path != Path("/")
        and ".." not in path.parts
        and "." not in path.parts,
        "certify-install",
        label,
    )
    return value


def _account(name, label):
    require(type(name) is str and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name),
            "certify-install", label)
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        require(False, "certify-install", label + " account missing")
    require(entry.pw_uid >= 1000 and entry.pw_gid > 0
            and len([row for row in pwd.getpwall() if row.pw_uid == entry.pw_uid]) == 1,
            "certify-install", label + " account is not a unique unprivileged identity")
    return entry


def _protected_socket_parent(path):
    current = Path("/")
    for part in Path(path).parent.parts[1:]:
        current /= part
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and info.st_uid == 0 and not (info.st_mode & 0o022),
                "certify-install", "root-control socket ancestry is not protected")


def resolve_live_controller(controller_project, root_control_socket, consumer_account):
    """Resolve project owner, root-control peer authority, and broker consumer UID."""
    require(os.geteuid() == 0, "root-required",
            "certify-manage native install staging requires root")
    project_text = _absolute(controller_project, "canonical controller project required")
    root_socket = _absolute(root_control_socket, "canonical root-control socket required")
    project = Path(project_text)
    info = project.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid >= 1000 and info.st_gid > 0
            and not (info.st_mode & 0o022),
            "certify-install", "controller project ownership is not protected")
    try:
        owner = pwd.getpwuid(info.st_uid)
    except KeyError:
        require(False, "certify-install", "controller project owner account missing")
    require(owner.pw_uid == info.st_uid and owner.pw_gid == info.st_gid
            and len([row for row in pwd.getpwall() if row.pw_uid == info.st_uid]) == 1,
            "certify-install", "controller project owner account disagrees")

    _protected_socket_parent(root_socket)
    socket_info = Path(root_socket).lstat()
    require(stat.S_ISSOCK(socket_info.st_mode) and not stat.S_ISLNK(socket_info.st_mode)
            and socket_info.st_uid == info.st_uid
            and stat.S_IMODE(socket_info.st_mode) in (0o600, 0o660),
            "certify-install",
            "root-control socket does not authenticate controller project owner")

    consumer = _account(consumer_account, "lifecycle consumer")
    require(consumer.pw_uid != owner.pw_uid,
            "certify-install", "lifecycle consumer must differ from controller owner")
    return {
        "controller_uid": owner.pw_uid,
        "controller_gid": owner.pw_gid,
        "controller_account": owner.pw_name,
        "consumer_uid": consumer.pw_uid,
        "consumer_gid": consumer.pw_gid,
        "consumer_account": consumer.pw_name,
        "controller_project": project_text,
        "root_control_socket": root_socket,
        "evidence": {
            "controller_project_owner": project_text,
            "root_control_socket_owner": root_socket,
            "lifecycle_consumer_account": consumer.pw_name,
        },
    }


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def validate_software_result(value):
    """Validate image-build's immutable certify-manage consumer binding."""
    if isinstance(value, (str, os.PathLike, Path)):
        value = json.loads(Path(value).read_text())
    require(type(value) is dict and set(value) == {
        "contract", "profile", "runtime_lock_digest", "artifact", "view",
        "binding", "commands",
    }, "certify-software", "invalid certify-manage software result")
    require(value["contract"] == "image-build-certify-manage-software-result-v1"
            and value["profile"] in ("http-01", "cloudflare-dns-01")
            and type(value["runtime_lock_digest"]) is str
            and _SHA.fullmatch(value["runtime_lock_digest"]),
            "certify-software", "unsupported certify-manage software result")
    require(type(value["artifact"]) is str and _SHA.fullmatch(value["artifact"])
            and type(value["view"]) is str and _SHA.fullmatch(value["view"]),
            "certify-software", "invalid immutable certify-manage identities")
    require(value["commands"] == {
        "python": "/applications/certify-manage/bin/python3",
        "certbot": "/applications/certify-manage/bin/certbot",
    }, "certify-software", "immutable certify-manage command paths differ")

    binding = value["binding"]
    required = {
        "schema", "contract", "mount_contract", "view", "application", "profile",
        "root", "manifest", "mount_point", "objects", "rootfs_compatibility",
        "visibility", "reclamation_protection", "binding_digest",
    }
    require(type(binding) is dict and set(binding) == required
            and binding["schema"] == 1
            and binding["contract"] == "application-software-consumer-v1"
            and binding["view"] == value["view"]
            and binding["application"] == "certify-manage"
            and binding["profile"] == "application"
            and binding["mount_point"] == "/applications/certify-manage"
            and binding["visibility"] == {
                "executables": ["bin"], "libraries": ["lib", "lib64"],
                "resources": ["share"], "helpers": ["libexec"],
            },
            "certify-software", "certify-manage consumer binding differs")
    require(type(binding["objects"]) is list and len(binding["objects"]) == 1
            and binding["objects"][0].get("artifact") == value["artifact"]
            and binding["reclamation_protection"] == {
                "view": value["view"], "artifacts": [value["artifact"]]
            },
            "certify-software", "certify-manage artifact binding differs")
    expected = "sha256:" + hashlib.sha256(
        _canonical_json({
            key: binding[key] for key in binding if key != "binding_digest"
        }).encode("utf-8")
    ).hexdigest()
    require(binding["binding_digest"] == expected,
            "certify-software", "certify-manage binding digest differs")
    return json.loads(json.dumps(value))


def verify_reviewed_sources(image_build_source, certify_manage_source):
    pairs = (
        (
            Path(image_build_source) / "src/zog/image_build/certify_manage_software.py",
            IMAGE_BUILD_PRODUCER_BLOB,
            "image-build certify-manage software producer",
        ),
        (
            Path(certify_manage_source) / "integration/box-control/application.py",
            CERTIFY_APPLICATION_BLOB,
            "certify-manage controller declaration",
        ),
    )
    observed = {}
    for path, expected, label in pairs:
        require(path.is_file() and not path.is_symlink(),
                "certify-source", label + " missing or redirected")
        data = path.read_bytes()
        require(_git_blob_sha(data) == expected,
                "certify-source", label + " differs from reviewed source")
        observed[label] = {"git_blob": expected, "sha256": _sha256(data)}
    return observed


def _binding_policy(raw, project):
    if raw is None:
        policy = {"schema": 1, "bindings": []}
    else:
        policy = decode(raw)
    fields(policy, "schema bindings")
    require(policy["schema"] == 1 and type(policy["bindings"]) is list
            and len(policy["bindings"]) <= 127,
            "certify-bindings", "unsupported host binding policy")
    expected = {
        program: {
            "project": project,
            "application": "certify-manage",
            "program": program,
            "capability": "certify-policy",
            "source": POLICY_SOURCE,
        }
        for program in PROGRAMS
    }
    result = list(policy["bindings"])
    for program, entry in expected.items():
        matches = [
            row for row in result
            if type(row) is dict
            and row.get("project") == project
            and row.get("application") == "certify-manage"
            and row.get("program") == program
            and row.get("capability") == "certify-policy"
        ]
        require(len(matches) <= 1, "certify-bindings",
                "duplicate certify-policy binding")
        if matches:
            require(matches[0] == entry, "certify-bindings",
                    "existing certify-policy binding disagrees")
        else:
            result.append(entry)
    result.sort(key=lambda row: (
        row.get("project", ""), row.get("application", ""),
        row.get("program", ""), row.get("capability", ""),
        row.get("source", ""),
    ))
    return {"schema": 1, "bindings": result}


def render_application(software_view):
    require(type(software_view) is str and _SHA.fullmatch(software_view),
            "certify-application", "exact software view required")
    py = "/applications/certify-manage/bin/python3"
    state = "/var/lib/zog-certify-manage"
    policy = "/run/zog-host/certify-policy/policy.json"
    def command(name):
        return (
            f'("{py}", "-m", "zog.certify_manage", "{name}", '
            f'"--state", "{state}", "--policy", "{policy}")'
        )
    lines = [
        "application(",
        '    name="certify-manage",',
        '    description="ACME certificate issuance and renewal, no ingress control",',
        "    persistent=True,",
        "    multiple_instances=False,",
        '    execution_identity="application",',
        '    start_policy="externally-controlled",',
        f'    software_view="{software_view}",',
        '    writable_mounts=("certificate-data",),',
        '    preparation_revision="certify-manage-state-v1",',
        "    preparation=(",
        "        program(",
        '            name="prepare",',
        f"            command={command('prepare')},",
        "            execution_timeout_seconds=120,",
        f'            mounts={{"certificate-data": "{state}"}},',
        "        ),",
        "    ),",
        "    programs=(",
    ]
    for name in ("issue", "renew", "stage", "inspect"):
        lines += [
            "        program(",
            f'            name="{name}",',
            f"            command={command(name)},",
        ]
        if name == "stage":
            lines += ["            execution_timeout_seconds=120,"]
        lines += [
            f'            mounts={{"certificate-data": "{state}"}},',
            "        ),",
        ]
    lines += ["    ),", ")", ""]
    return "\n".join(lines).encode()


def _socket_unit(consumer_uid):
    return (
        "[Unit]\nDescription=Authenticated certify-manage lifecycle controller socket\n"
        "After=sysinit.target\nBefore=shutdown.target\nConflicts=shutdown.target\n"
        "DefaultDependencies=no\n\n[Socket]\n"
        f"ListenStream={LIFECYCLE_SOCKET}\nSocketUser={consumer_uid}\n"
        "SocketMode=0600\nDirectoryMode=0711\nAccept=no\nBacklog=8\n"
        "RemoveOnStop=yes\n\n[Install]\nWantedBy=multi-user.target\n"
    ).encode()


def _service_unit(*, controller_uid, controller_gid, consumer_uid,
                  project, generation, software_view, root_control_socket):
    argv = (
        "/usr/bin/python3 -m zog.box_control.issuer_lifecycle_broker"
        f" --project {project} --authorized-uid {consumer_uid}"
        f" --generation {generation} --software-view {software_view}"
        f" --root-control-socket {root_control_socket}"
    )
    return (
        "[Unit]\nDescription=Selected certify-manage lifecycle controller broker\n"
        "After=sysinit.target\n\n[Service]\nType=simple\n"
        "Sockets=zog-certify-lifecycle.socket\n"
        f"User={controller_uid}\nGroup={controller_gid}\n"
        "Environment=PYTHONPATH=\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n"
        f"ExecStart={argv}\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
        "ProtectSystem=strict\nProtectHome=read-only\nProtectKernelTunables=yes\n"
        "ProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n"
        "RestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\n"
        "RestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n"
        "CapabilityBoundingSet=\nAmbientCapabilities=\nUMask=0077\n"
        "Restart=on-failure\nRestartSec=2s\nStandardOutput=journal\n"
        "StandardError=journal\n"
    ).encode()


def stage_live(*, output, controller_project, root_control_socket,
               lifecycle_consumer_account, generation, software_result,
               host_bindings_policy, image_build_source, certify_manage_source):
    require(type(generation) is str and _HEX.fullmatch(generation),
            "certify-install", "exact rootfs generation required")
    identities = resolve_live_controller(
        controller_project, root_control_socket, lifecycle_consumer_account
    )
    software = validate_software_result(software_result)
    sources = verify_reviewed_sources(image_build_source, certify_manage_source)
    policy_path = Path(host_bindings_policy)
    raw = policy_path.read_bytes()
    require(len(raw) <= 65536, "certify-bindings",
            "host binding policy exceeds 64 KiB")
    bindings = _binding_policy(raw, identities["controller_project"])

    install = {
        "schema": INSTALL_SCHEMA,
        "application": "certify-manage",
        "controller_project": identities["controller_project"],
        "controller_uid": identities["controller_uid"],
        "controller_gid": identities["controller_gid"],
        "lifecycle_consumer_uid": identities["consumer_uid"],
        "lifecycle_consumer_gid": identities["consumer_gid"],
        "root_control_socket": identities["root_control_socket"],
        "rootfs_generation": generation,
        "software_view": software["view"],
        "software_binding_digest": software["binding"]["binding_digest"],
        "software_artifact": software["artifact"],
        "software_profile": software["profile"],
        "runtime_lock_digest": software["runtime_lock_digest"],
        "python": software["commands"]["python"],
        "certbot": software["commands"]["certbot"],
        "policy_source": POLICY_SOURCE,
        "policy_guest": POLICY_GUEST,
        "lifecycle_socket": LIFECYCLE_SOCKET,
        "box_control_source_commit": BOX_CONTROL_COMMIT,
        "root_control_source_commit": ROOT_CONTROL_COMMIT,
        "certify_manage_source_commit": CERTIFY_MANAGE_COMMIT,
        "image_build_source_commit": IMAGE_BUILD_COMMIT,
        "policy_installed": False,
        "application_prepared": False,
        "production_activation_authorized": False,
    }
    manifest = {
        "schema": 1,
        "kind": PROFILE_KIND,
        "install": install,
        "identity_evidence": identities["evidence"],
        "reviewed_sources": sources,
        "host_bindings": {
            "programs": list(PROGRAMS),
            "source": POLICY_SOURCE,
            "destination": POLICY_GUEST,
            "access": "read-only",
        },
        "issuer_storage": {
            "name": "certificate-data",
            "guest": "/var/lib/zog-certify-manage",
            "mode": "0700",
            "owner": "controller-issued-application-grant",
            "precreate_host_path": False,
        },
        "lifecycle_broker": {
            "socket": LIFECYCLE_SOCKET,
            "allowed_programs": list(_SELECTED_BROKER_PROGRAMS),
            "server_uid": identities["controller_uid"],
            "authorized_consumer_uid": identities["consumer_uid"],
        },
        "external_owners": {
            "hostname_policy": "station-access/host-discover + host owner",
            "dns_credential": "root-control issuer-only bridge",
            "certificate_delivery": "host-deploy",
        },
        "services_enabled": False,
        "mutation_authority": {
            "prepare_application": False,
            "issue_certificate": False,
            "renew_certificate": False,
            "stage_certificate": False,
            "install_hostname_policy": False,
            "provision_dns_secret": False,
            "reload_nginx": False,
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
                "etc", ".pending-dir.etc", "controller", ".pending-dir.controller",
            }
            require(set(os.listdir(root)) <= allowed,
                    "profile-conflict", "unexpected certify-manage overlay contents")
            publish(root, "profile.json", canonical(manifest), 0o444)

            etc = systemd = system = zog = install_dir = controller = appdir = certdir = None
            try:
                etc = ensure_directory(root, "etc", 0, 0, 0o755)
                systemd = ensure_directory(etc, "systemd", 0, 0, 0o755)
                system = ensure_directory(systemd, "system", 0, 0, 0o755)
                publish(system, UNIT_SOCKET, _socket_unit(identities["consumer_uid"]), 0o444)
                publish(system, UNIT_SERVICE, _service_unit(
                    controller_uid=identities["controller_uid"],
                    controller_gid=identities["controller_gid"],
                    consumer_uid=identities["consumer_uid"],
                    project=identities["controller_project"],
                    generation=generation,
                    software_view=software["view"],
                    root_control_socket=identities["root_control_socket"],
                ), 0o444)
                zog = ensure_directory(etc, "zog", 0, 0, 0o755)
                publish(zog, "host-bindings.json", canonical(bindings), 0o444)
                install_dir = ensure_directory(zog, "certify-manage", 0, 0, 0o755)
                publish(install_dir, "install.json", canonical(install), 0o444)

                controller = ensure_directory(root, "controller", 0, 0, 0o755)
                appdir = ensure_directory(controller, "application", 0, 0, 0o755)
                certdir = ensure_directory(appdir, "certify-manage", 0, 0, 0o755)
                publish(certdir, "application.py", render_application(software["view"]), 0o444)
            finally:
                for fd in (certdir, appdir, controller, install_dir, zog, system, systemd, etc):
                    if fd is not None:
                        os.close(fd)
        return {
            "status": "certify-manage-native-install-staged",
            "output": str(output),
            "controller_uid": identities["controller_uid"],
            "lifecycle_consumer_uid": identities["consumer_uid"],
            "software_view": software["view"],
            "lifecycle_socket": LIFECYCLE_SOCKET,
            "services_enabled": False,
            "application_prepared": False,
            "production_activation_authorized": False,
        }
    finally:
        if root is not None:
            os.close(root)
        os.close(parent)


def attest_prepared(*, controller_project, root_control_socket,
                    expected_software_view):
    """Read actual prepared grant/storage and compare to root-control identity."""
    require(os.geteuid() == 0, "root-required",
            "certify-manage prepared-state attestation requires root")
    project_path = _absolute(controller_project, "canonical controller project required")
    root_socket = _absolute(root_control_socket, "canonical root-control socket required")
    require(type(expected_software_view) is str and _SHA.fullmatch(expected_software_view),
            "certify-attest", "expected software view required")

    from zog.box_control.project import Project
    from zog.box_control.api import BoxControl
    from zog.box_control.runtime.root_control import RootControlSystemdTransport

    project = Project(Path(project_path))
    transport = RootControlSystemdTransport(Path(root_socket))
    control = BoxControl(project, systemd_transport=transport)
    state = control.application_preparation("certify-manage")
    require(type(state) is dict and state.get("state") == "ready"
            and state.get("revision") == "certify-manage-state-v1"
            and type(state.get("storage_id")) is str
            and _STORAGE.fullmatch(state["storage_id"]),
            "certify-attest", "certify-manage preparation is not ready")
    definition = state.get("definition")
    require(type(definition) is dict
            and definition.get("name") == "certify-manage"
            and definition.get("software_view") == expected_software_view,
            "certify-attest", "prepared issuer definition differs")
    grant = definition.get("execution_binding")
    require(type(grant) is dict
            and grant.get("schema") == "zog-execution-identity-v1"
            and grant.get("project") == project_path
            and grant.get("application") == "certify-manage"
            and type(grant.get("grant_id")) is str
            and re.fullmatch(r"[0-9a-f]{32}", grant["grant_id"])
            and type(grant.get("uid")) is int and grant["uid"] > 0
            and type(grant.get("gid")) is int and grant["gid"] > 0,
            "certify-attest", "prepared issuer execution grant differs")
    privileged = transport.resolve_execution_identity(
        project_root=project.path, application="certify-manage"
    )
    require(privileged == grant,
            "certify-attest", "root-control execution identity disagrees with preparation")

    storage = (
        project.mounts_dir / "persistent" / state["storage_id"] / "certificate-data"
    )
    info = storage.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == grant["uid"] and info.st_gid == grant["gid"],
            "certify-attest", "certificate-data ownership or mode differs")
    return {
        "schema": "zog-certify-manage-prepared-attestation-v1",
        "status": "ready",
        "application": "certify-manage",
        "preparation_revision": state["revision"],
        "storage_id": state["storage_id"],
        "grant_id": grant["grant_id"],
        "issuer_uid": grant["uid"],
        "issuer_gid": grant["gid"],
        "software_view": expected_software_view,
        "certificate_data_path": str(storage),
        "certificate_data_mode": "0700",
        "root_control_identity_verified": True,
        "production_activation_authorized": False,
    }


def _protected_ancestry(path, stop):
    path = Path(path)
    stop = Path(stop)
    try:
        path.relative_to(stop)
    except ValueError:
        require(False, "certify-installed", "module outside aggregate distribution")
    current = path
    while True:
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not (info.st_mode & 0o022),
                "certify-installed", "installed controller path is redirected or writable")
        if current == stop:
            break
        current = current.parent


def attest_installed_controller(*, python_executable="/usr/bin/python3"):
    """Attest pinned box-control/root-control modules from the aggregate wheel."""
    require(os.geteuid() == 0, "root-required",
            "controller installed-software attestation requires root")
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "certify-installed", "caller-selected Python import paths are not permitted")
    python_executable = _absolute(
        python_executable, "canonical approved Python executable required"
    )
    running = Path(sys.executable).resolve()
    require(Path(python_executable).resolve() == running,
            "certify-installed", "attestation interpreter differs")
    try:
        dist = importlib.metadata.distribution("zog")
    except importlib.metadata.PackageNotFoundError:
        require(False, "certify-installed", "aggregate zog distribution unavailable")
    require(dist.metadata.get("Name") == "zog",
            "certify-installed", "unexpected aggregate distribution")
    root = Path(dist.locate_file("")).resolve()
    text = dist.read_text("RECORD")
    require(type(text) is str and 0 < len(text) <= 4_000_000,
            "certify-installed", "aggregate RECORD missing or excessive")
    rows = {}
    for row in csv.reader(io.StringIO(text)):
        require(len(row) == 3 and row[0] not in rows,
                "certify-installed", "invalid aggregate RECORD")
        rows[row[0]] = row[1]

    observed = {}
    for module, expected in INSTALLED_MODULE_BLOBS.items():
        loaded = importlib.import_module(module)
        origin = getattr(loaded, "__file__", None)
        require(type(origin) is str, "certify-installed",
                "installed controller module has no origin")
        path = Path(origin)
        _protected_ancestry(path, root)
        data = path.read_bytes()
        require(_git_blob_sha(data) == expected,
                "certify-installed", "installed controller bytes differ from pin")
        relative = path.resolve().relative_to(root).as_posix()
        require(relative in rows, "certify-installed",
                "installed controller module absent from RECORD")
        algorithm, sep, encoded = rows[relative].partition("=")
        require(sep == "=" and algorithm == "sha256"
                and encoded == _record_sha256(data),
                "certify-installed", "aggregate RECORD disagrees with controller module")
        observed[module] = {
            "origin": str(path.resolve()),
            "git_blob": expected,
            "sha256": _sha256(data),
        }
    return {
        "schema": "zog-certify-manage-controller-installed-attestation-v1",
        "box_control_source_commit": BOX_CONTROL_COMMIT,
        "root_control_source_commit": ROOT_CONTROL_COMMIT,
        "distribution_version": dist.version,
        "record_sha256": _sha256(text.encode()),
        "modules": observed,
        "production_activation_authorized": False,
    }
