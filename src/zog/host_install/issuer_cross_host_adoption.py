"""Read-only source/RECORD and retained-owner admission for SSH issuer bridge.

Root-control alone cannot confer the managed Host's certificate authority.
The original host-install second owner ledger, station signer pin and
host-deploy consumer policy are independent inputs. No token is fetched here.
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
import stat
import sys
import time

from . import certificate_owner_authority as owner
from .state_contract import StateError, require

ROOT_BRIDGE_COMMIT = "33e4a974a7f1919cd3fabdeb89c771514e9b18e0"
ROOT_BRIDGE_BLOB = "2f159a59bbc8fef0f53ce35fbf82833c9a88c645"
HOST_DEPLOY_BRIDGE_BLOB = "ced728c5c8d7a2b1ced449091494e783680633c1"
SOURCE = {
    "zog.root_control.issuer_cross_host": ("root-control", ROOT_BRIDGE_BLOB),
    "zog.host_deploy.certificate_cross_host_admission":
        ("host-deploy", HOST_DEPLOY_BRIDGE_BLOB),
}


def _check_installed_stat(path):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and info.st_nlink == 1 and not info.st_mode & 0o022,
            "cross-host-installed", "installed source/RECORD is unsafe")


def _attest_module(name, distribution, blob, *, package=""):
    selected = package or distribution
    require(selected in (distribution, "zog"), "cross-host-installed",
            "unsupported issuer bridge distribution")
    try:
        dist = importlib.metadata.distribution(selected)
        module = importlib.import_module(name)
        import_path = Path(module.__file__)
    except (ImportError, AttributeError, importlib.metadata.PackageNotFoundError):
        require(False, "cross-host-installed", "issuer bridge module unavailable")
    root = Path(dist.locate_file("")).resolve()
    resolved = import_path.resolve()
    owner._protected_ancestry(root)
    owner._protected_ancestry(resolved, root)
    relative = "zog/" + "/".join(name.split(".")[1:]) + ".py"
    expected = root / relative
    require(resolved == expected, "cross-host-installed",
            "loaded module is not installed distribution source")
    _check_installed_stat(resolved)
    data = resolved.read_bytes()
    require(owner._git_blob(data) == blob,
            "cross-host-installed", "issuer bridge source differs from reviewed pin")
    raw_record = dist.read_text("RECORD")
    require(type(raw_record) is str and 0 < len(raw_record) <= 4_000_000,
            "cross-host-installed", "installed wheel RECORD absent")
    record_files = [f for f in dist.files or ()
                    if str(f).endswith(".dist-info/RECORD")]
    require(len(record_files) == 1, "cross-host-installed", "wheel RECORD ambiguous")
    record_path = Path(dist.locate_file(record_files[0]))
    owner._protected_ancestry(record_path, root)
    _check_installed_stat(record_path)
    rows = {}
    for row in csv.reader(io.StringIO(raw_record)):
        require(len(row) == 3 and row[0] not in rows,
                "cross-host-installed", "invalid wheel RECORD")
        rows[row[0]] = row[1]
    require(rows.get(relative) == "sha256=" + owner._record_sha256(data),
            "cross-host-installed", "installed module and RECORD disagree")
    return dict(module=name, git_blob=blob,
                sha256=hashlib.sha256(data).hexdigest(),
                wheel_record_sha256=hashlib.sha256(raw_record.encode()).hexdigest(),
                distribution=selected)


def attest_installed(*, python_executable, root_distribution="root-control",
                     deploy_distribution="host-deploy"):
    """Root-only, selected interpreter, exact source and wheel RECORD."""
    require(os.geteuid() == 0, "root-required",
            "issuer bridge installed source attestation requires root")
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "cross-host-installed", "untrusted import path overrides")
    exe = Path(python_executable)
    require(exe.is_absolute() and exe.resolve() == Path(sys.executable).resolve(),
            "cross-host-installed", "unexpected interpreter")
    owner._protected_ancestry(exe.resolve())
    result = {}
    for name, (distribution, sha) in SOURCE.items():
        result[name] = _attest_module(
            name, distribution, sha,
            package=(root_distribution if distribution == "root-control"
                     else deploy_distribution))
    return dict(status="source-and-record-verified", modules=result,
                credential_transferred=False)


def inspect(project_root, delivery_policy, *, python_executable,
            root_distribution="root-control", deploy_distribution="host-deploy"):
    """Preflight: source bytes, live STATE, second owner, and exact grant.

    Root-control's separate transfer command must RECHECK all of these under
    the original locks before and after retrieval. This inspector itself is
    read-only; it does not authorize any remote invocation.
    """
    require(os.geteuid() == 0, "root-required",
            "protected cross-host inspection requires root")
    installed = attest_installed(
        python_executable=python_executable,
        root_distribution=root_distribution,
        deploy_distribution=deploy_distribution)
    from zog.box_control.project import Project
    from zog.root_control import issuer_cross_host as cross
    from zog.root_control import issuer_credentials as cred
    from zog.root_control import issuer_station_transfer as transfer
    from zog.host_deploy import certificate_managed_authority as managed
    from zog.host_deploy import certificate_delivery
    from zog.host_deploy import certificate_cross_host_admission as admission

    project = Project(Path(project_root))
    require(str(project.path) == str(Path(project_root)),
            "cross-host-owner", "project path is not canonical")
    initial = owner.inspect_live_owner()
    require(initial["status"] == "retained"
            and initial["status_authority"] == "approved"
            and initial["pending_transaction"] is None,
            "cross-host-owner", "retained issuer owner requires recovery")
    client = cross._client_binding(project)
    identifier = cross._client_approved(project, client)
    authorization = cred._read_protected(cred._paths(project)[0])
    require(type(authorization) is dict
            and cred._authorization_id(authorization) == identifier,
            "cross-host-owner", "root approval differs from client")
    _, peer = transfer._checked_current(project)
    station_projection_path, _ = cred._projection_paths(project)
    projection = transfer._private_file(
        station_projection_path, gid=peer["reader_gid"], mode=0o440)

    managed_path = managed.ROOT_OWNER_AUTHORITY_PATH
    owner_receipt = managed._read_root_json(managed_path, mode=0o600, limit=8192)
    owner_ledger = managed._read_root_json(
        managed.ROOT_OWNER_LEDGER_PATH, mode=0o600, limit=65536)
    consumer = managed._read_root_json(
        managed.ROOT_CONSUMER_BINDING_PATH, mode=0o600, limit=8192)
    delivery = certificate_delivery.read_policy(delivery_policy)
    signer = cross._root_regular(managed.ROOT_SIGNER_PIN_PATH, mode=0o444)
    receipt = cross._root_regular(managed_path, mode=0o600)
    result = admission.validate(
        owner_receipt, consumer, owner_ledger, delivery, authorization,
        projection, client, owner_bytes=receipt,
        signer_pin_bytes=signer, now=int(time.time()))
    # Never trust a single snapshot of a mutable installation.
    after = owner.inspect_live_owner()
    require(after == initial, "cross-host-owner",
            "installed owner/STATE/issuer identity changed during inspection")
    return dict(
        schema="zog-host-install-cross-host-issuer-inspection-v1",
        status="protected-source-preflight-only",
        installed=installed, owner=initial, admission=result,
        native_ssh_accepted=False, token_transferred=False,
        issuer_preparation_recovered=False, production_activation_authorized=False)
