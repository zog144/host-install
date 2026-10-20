"""Authenticated native certify-manage readiness observation.

This adapter composes existing trust roots. It never executes Certbot, prepares
an application, allocates an issuer identity, writes certificate policy, reads
UID-970 assignment state directly, or authorizes nginx/HTTPS.
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
import time

from .certificate_lifecycle import load_record, reconcile, store_record
from .certify_manage_profile import attest_installed_controller
from .state_admission import observe as observe_state_admission
from .state_contract import CONFIG, StateError, canonical, decode, fields, require, sha
from .state_inspect import directory, inspect_live, read_at


APPLICATION = "certify-manage"
PREPARATION_REVISION = "certify-manage-state-v1"
PIN_NAME = "certificate-assignment-authority.json"
PIN_KIND = "zog-certificate-assignment-authority-pin"
HOST_DISCOVER_COMMIT = "69ef2620f644a83ccc309f13b71b7f0e30a684aa"
HOST_DISCOVER_MODULE_BLOBS = {
    "zog.host_discover.supervisor": "419c56e07e22d2784fca6cb44ccb1e7a4dd54f0f",
    "zog.host_discover.certificate_assignment": "ac7ef69f6b22bc227c0b1eb05b76c1bf4bd389e2",
}
_REQUEST = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_PROGRAMS = ("prepare", "issue", "renew", "inspect", "stage")
_RUNTIME_PROGRAMS = ("issue", "renew", "inspect", "stage")
_PYTHON = "/applications/certify-manage/bin/python3"
_STATE = "/var/lib/zog-certify-manage"
_POLICY_FILE = "/run/zog-host/certify-policy/policy.json"
_HOST_POLICY = Path("/etc/zog/certify-policy/policy.json")


def _gate(status, code, evidence=None):
    require(status in ("PASS", "BLOCKED", "NOT RUN"),
            "certificate-native", "invalid matrix status")
    value = {"status": status, "code": code}
    if evidence is not None:
        value["evidence"] = evidence
    return value


def _git_blob(data):
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def _record_sha256(data):
    return base64.urlsafe_b64encode(
        hashlib.sha256(data).digest()
    ).rstrip(b"=").decode()


def _installed_host_discover():
    """Verify the installed root-observation producer against reviewed source."""
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "certificate-native-installed",
            "caller-selected Python import paths are not permitted")
    try:
        distribution = importlib.metadata.distribution("zog")
    except importlib.metadata.PackageNotFoundError:
        require(False, "certificate-native-installed",
                "aggregate zog distribution is unavailable")
    require(distribution.metadata.get("Name") == "zog",
            "certificate-native-installed", "unexpected aggregate distribution")
    root = Path(distribution.locate_file("")).resolve()
    from .certify_manage_profile import _protected_ancestry
    text = distribution.read_text("RECORD")
    require(type(text) is str and 0 < len(text) <= 4_000_000,
            "certificate-native-installed", "aggregate RECORD unavailable")
    rows = {}
    for row in csv.reader(io.StringIO(text)):
        require(len(row) == 3 and row[0] not in rows,
                "certificate-native-installed", "invalid aggregate RECORD")
        rows[row[0]] = row[1]

    observed = {}
    for module, expected in HOST_DISCOVER_MODULE_BLOBS.items():
        loaded = importlib.import_module(module)
        origin = getattr(loaded, "__file__", None)
        require(type(origin) is str,
                "certificate-native-installed", "host-discover module has no origin")
        path = Path(origin).resolve()
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            require(False, "certificate-native-installed",
                    "host-discover module is outside aggregate distribution")
        _protected_ancestry(path, root)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "certificate-native-installed",
                "host-discover module origin is not a protected regular file")
        data = path.read_bytes()
        require(_git_blob(data) == expected,
                "certificate-native-installed",
                "installed host-discover authority bytes differ from reviewed source")
        require(relative in rows,
                "certificate-native-installed",
                "host-discover module absent from aggregate RECORD")
        algorithm, sep, encoded = rows[relative].partition("=")
        require(sep == "=" and algorithm == "sha256"
                and encoded == _record_sha256(data),
                "certificate-native-installed",
                "aggregate RECORD disagrees with host-discover module")
        observed[module] = {
            "origin": str(path),
            "git_blob": expected,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return {
        "source_commit": HOST_DISCOVER_COMMIT,
        "distribution_version": distribution.version,
        "record_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "modules": observed,
    }


def _authority_pin():
    """Read the installer-owned Ed25519 assignment pin, never UID-970 state."""
    from zog.host_identify import signatures

    fd = directory(CONFIG)
    try:
        value = decode(read_at(fd, PIN_NAME, 0, 0, 0o444))
    finally:
        os.close(fd)
    fields(value, "schema kind registry_id authority_public_key authority_key_id")
    require(type(value["schema"]) is int and value["schema"] == 1
            and value["kind"] == PIN_KIND
            and type(value["registry_id"]) is str
            and 1 <= len(value["registry_id"]) <= 64,
            "certificate-authority-pin", "unsupported assignment authority pin")
    sha(value["authority_key_id"])
    try:
        key = signatures.public_key(value["authority_public_key"])
    except (TypeError, ValueError) as exc:
        raise StateError(
            "certificate-authority-pin",
            "invalid assignment authority public key",
        ) from exc
    require(signatures.fingerprint(key) == value["authority_key_id"],
            "certificate-authority-pin",
            "assignment authority fingerprint differs")
    return value


def _authority(context):
    """Inspect only the root-owned host-discover checkpoint."""
    from zog.host_discover import supervisor

    pin = _authority_pin()
    value = supervisor.inspect_authority(context)
    require(value["installation_id"] == context.bundle["bootstrap"]["installation_id"]
            and value["state_volume_id"]
            == context.bundle["bootstrap"]["state"]["state_volume_id"],
            "certificate-authority-binding",
            "root authority belongs to another installation or STATE")
    require(value["registry_id"] == pin["registry_id"]
            and value["authority_public_key"] == pin["authority_public_key"]
            and value["authority_key_id"] == pin["authority_key_id"],
            "certificate-authority-pin",
            "root authority observation differs from installed pin")
    assignment = value["envelope"]["assignment"]
    now = int(time.time())
    if assignment["status"] == "revoked":
        status = "revoked"
    elif assignment["approved_at"] > now:
        status = "not-yet-valid"
    elif assignment["expires_at"] <= now:
        status = "expired"
    else:
        status = "approved"
    return {
        "status": status,
        "origin": value["origin"],
        "verified_by": value["verified_by"],
        "host_id": value["host_id"],
        "installation_id": value["installation_id"],
        "state_volume_id": value["state_volume_id"],
        "registry_id": value["registry_id"],
        "authority_key_id": value["authority_key_id"],
        "revision": value["revision"],
        "operation_id": value["operation_id"],
        "assignment_sha256": value["assignment_sha256"],
        "consumer": assignment["consumer"],
        "certificate_id": assignment["certificate_id"],
        "challenge": assignment["challenge"],
        "hostnames_count": len(assignment["hostnames"]),
        "hostnames_sha256": hashlib.sha256(
            canonical(assignment["hostnames"])
        ).hexdigest(),
        "expires_at": assignment["expires_at"],
    }


def _project_owner(project, root_control_socket):
    """Verify controller project and root-control peer ownership."""
    from .certify_manage_profile import _protected_socket_parent

    info = project.path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid >= 1000 and info.st_gid > 0
            and not (info.st_mode & 0o022),
            "certificate-native-controller",
            "controller project ownership is not protected")
    try:
        owner = pwd.getpwuid(info.st_uid)
    except KeyError:
        require(False, "certificate-native-controller",
                "controller project owner account missing")
    require(owner.pw_gid == info.st_gid
            and len([row for row in pwd.getpwall()
                     if row.pw_uid == info.st_uid]) == 1,
            "certificate-native-controller",
            "controller project owner is ambiguous")
    root_control_socket = Path(root_control_socket)
    _protected_socket_parent(str(root_control_socket))
    socket_info = root_control_socket.lstat()
    require(stat.S_ISSOCK(socket_info.st_mode)
            and socket_info.st_uid == info.st_uid
            and stat.S_IMODE(socket_info.st_mode) in (0o600, 0o660),
            "certificate-native-controller",
            "root-control socket does not authenticate controller owner")
    return {
        "uid": owner.pw_uid,
        "gid": owner.pw_gid,
        "account": owner.pw_name,
        "root_control_socket": str(root_control_socket),
    }


def _expected_command(name):
    return (
        _PYTHON, "-m", "zog.certify_manage", name,
        "--state", _STATE, "--policy", _POLICY_FILE,
    )


def _software_and_preparation(project, generation, software_view):
    from zog.box_control.application_software import (
        resolve_binding,
        rootfs_compatibility,
        validate_binding,
    )
    from zog.box_control.application_storage import ApplicationStorage
    from zog.box_control.images import published_selection
    from zog.box_control.mounts import validate as validate_mounts
    from zog.box_control.specification import discover_applications

    require(type(generation) is str and _HEX64.fullmatch(generation),
            "certificate-native-software", "exact rootfs generation required")
    require(type(software_view) is str and _DIGEST.fullmatch(software_view),
            "certificate-native-software", "exact application software view required")

    if (project.state_dir / "mutation-incomplete.json").exists() or (
            project.state_dir / "session-recovery-pending.json").exists():
        raise StateError(
            "certificate-native-controller-recovery",
            "controller mutation/recovery marker is present",
        )

    applications = discover_applications(project.application_dir)
    require(set(applications) >= {APPLICATION},
            "certificate-native-application",
            "certify-manage application declaration is unavailable")
    application = applications[APPLICATION]
    require(application.persistent and not application.multiple_instances
            and application.execution_identity == "application"
            and application.software_view == software_view
            and application.preparation_revision == PREPARATION_REVISION
            and application.writable_mounts == ("certificate-data",),
            "certificate-native-application",
            "certify-manage application declaration differs")

    prep = {p.name: p for p in application.preparation}
    runtime = {p.name: p for p in application.programs}
    require(set(prep) == {"prepare"} and set(runtime) == set(_RUNTIME_PROGRAMS),
            "certificate-native-application",
            "selected certify-manage program set differs")
    for name, program in {**prep, **runtime}.items():
        require(tuple(program.command) == _expected_command(name)
                and dict(program.mounts) == {"certificate-data": _STATE},
                "certificate-native-application",
                "selected certify-manage command or mount differs")

    selection = published_selection(project.path, generation)
    require(selection.generation == generation,
            "certificate-native-software", "published rootfs generation differs")
    for program in application.preparation + application.programs:
        validate_mounts(
            selection.root, program.mounts, program.command, require_targets=True
        )

    storage = ApplicationStorage(project)
    storage.admission()
    raw = storage.load(APPLICATION)
    if raw is None:
        bound = resolve_binding(project, application, selection)
        binding = bound.software_binding
    else:
        binding = raw.get("definition", {}).get("software_binding")
        validate_binding(project, APPLICATION, binding)

    require(type(binding) is dict
            and binding.get("controller_contract")
            == "box-control-application-software-v1"
            and binding.get("contract") == "application-software-consumer-v1"
            and binding.get("view") == software_view
            and binding.get("application") == APPLICATION
            and binding.get("mount_point") == "/applications/certify-manage"
            and binding.get("rootfs_compatibility") == rootfs_compatibility(selection),
            "certificate-native-software",
            "prepared immutable software binding differs from selected rootfs/view")
    return application, selection, binding, raw


def _policy(project):
    """Verify protected issuer policy independently of managed assignment."""
    from zog.box_control.host_bindings import resolve
    from zog.certify_manage.model import Authorization
    from zog.certify_manage.security import trusted_policy

    if not _HOST_POLICY.exists() and not _HOST_POLICY.is_symlink():
        return None
    raw = trusted_policy(_HOST_POLICY)
    require(len(raw) <= 65536,
            "certificate-native-policy", "certificate policy exceeds size bound")
    try:
        parsed = json.loads(raw)
        authorization = Authorization.from_dict(parsed)
    except (ValueError, TypeError) as exc:
        raise StateError(
            "certificate-native-policy",
            "root-owned certificate policy is invalid",
        ) from exc

    entries = []
    for program in _PROGRAMS:
        selected = resolve(project.path, APPLICATION, program)
        require(len(selected) == 1,
                "certificate-native-policy",
                "certificate policy capability is missing or ambiguous")
        entry = selected[0]
        require(entry["capability"] == "certify-policy"
                and entry["destination"] == "/run/zog-host/certify-policy"
                and entry["access"] == "read-only",
                "certificate-native-policy",
                "certificate policy mount differs")
        entries.append(entry)
    digest = entries[0]["policy_digest"]
    require(all(item["policy_digest"] == digest for item in entries)
            and digest == "sha256:" + hashlib.sha256(raw).hexdigest(),
            "certificate-native-policy",
            "certificate policy digest differs across selected programs")
    return {
        "host_policy_digest": digest,
        "policy_sha256": authorization.fingerprint,
        "certificate_id": authorization.certificate_id,
        "challenge": authorization.challenge,
        "hostnames_count": len(authorization.hostnames),
        "hostnames_sha256": hashlib.sha256(
            canonical(list(authorization.hostnames))
        ).hexdigest(),
    }


def _prepared(project, application, generation, raw, transport):
    from zog.box_control.application_storage import ApplicationStorage

    if raw is None:
        return None
    require(raw.get("state") == "ready"
            and raw.get("cleanup_pending") is False
            and raw.get("revision") == PREPARATION_REVISION
            and raw.get("generation") == generation
            and type(raw.get("storage_id")) is str
            and _OPAQUE32.fullmatch(raw["storage_id"]),
            "certificate-native-preparation",
            "certify-manage preparation is not a ready frozen binding")
    bound = ApplicationStorage(project).bind(application, generation)
    grant = raw.get("definition", {}).get("execution_binding")
    require(type(grant) is dict
            and grant.get("schema") == "zog-execution-identity-v1"
            and grant.get("project") == str(project.path)
            and grant.get("application") == APPLICATION
            and type(grant.get("grant_id")) is str
            and _OPAQUE32.fullmatch(grant["grant_id"])
            and type(grant.get("uid")) is int and grant["uid"] >= 1000
            and type(grant.get("gid")) is int and grant["gid"] >= 1000
            and bound.execution_binding == grant,
            "certificate-native-grant",
            "prepared issuer execution grant differs")
    privileged = transport.resolve_execution_identity(
        project_root=project.path, application=APPLICATION
    )
    require(privileged == grant,
            "certificate-native-grant",
            "root-control execution identity differs from preparation")

    state = (
        project.mounts_dir / "persistent" / raw["storage_id"] / "certificate-data"
    )
    info = state.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_uid, info.st_gid) == (grant["uid"], grant["gid"]),
            "certificate-native-storage",
            "persistent certificate-data owner/mode differs")

    steps = []
    for step in raw.get("steps", ()):
        require(type(step) is dict
                and step.get("program") == "prepare"
                and type(step.get("boot_id")) is str
                and type(step.get("invocation_id")) is str
                and step.get("outcome") == "success",
                "certificate-native-preparation",
                "preparation terminal provenance is incomplete")
        steps.append({
            key: step.get(key)
            for key in (
                "program", "runtime_id", "unit_name", "boot_id",
                "invocation_id", "outcome",
            )
        })
    require(len(steps) == 1,
            "certificate-native-preparation",
            "certify-manage must have one completed preparation step")

    return {
        "storage_id": raw["storage_id"],
        "grant_id": grant["grant_id"],
        "issuer_uid": grant["uid"],
        "issuer_gid": grant["gid"],
        "preparation_revision": raw["revision"],
        "preparation_attempt_id": raw.get("attempt_id"),
        "generation": raw["generation"],
        "certificate_data_path": str(state),
        "certificate_data_mode": "0700",
        "steps": steps,
    }


def _inspect_selected(project, transport, request_id, prepared, policy):
    from zog.box_control.api import BoxControl
    from zog.box_control.issuer_inspection_evidence import sanitize_issuer_inspection

    require(type(request_id) is str and _REQUEST.fullmatch(request_id),
            "certificate-native-inspection",
            "durable selected inspect request identity required")
    require(prepared is not None,
            "certificate-native-inspection",
            "selected inspection requires prepared issuer identity")
    raw = BoxControl(project, systemd_transport=transport).inspect_issuer_result(
        request_id
    )
    value = sanitize_issuer_inspection(raw, request_id)
    require(value["storage_id"] == prepared["storage_id"]
            and value["grant_id"] == prepared["grant_id"]
            and value["issuer_uid"] == prepared["issuer_uid"]
            and value["issuer_gid"] == prepared["issuer_gid"],
            "certificate-native-inspection",
            "selected inspection issuer identity differs from preparation")
    if policy is not None:
        require(value["host_policy_digest"] == policy["host_policy_digest"]
                and value["inspection"]["policy_sha256"]
                == policy["policy_sha256"],
                "certificate-native-inspection",
                "selected inspection policy differs from protected host policy")
    inspection = value["inspection"]
    return {
        "status": value["status"],
        "request_id": value["request_id"],
        "runtime_id": value["runtime_id"],
        "boot_id": value["boot_id"],
        "invocation_id": value["invocation_id"],
        "storage_id": value["storage_id"],
        "grant_id": value["grant_id"],
        "issuer_uid": value["issuer_uid"],
        "issuer_gid": value["issuer_gid"],
        "host_policy_digest": value["host_policy_digest"],
        "policy_sha256": inspection["policy_sha256"],
        "health": inspection["health"],
        "certificate_fingerprint_sha256":
            inspection["certificate_fingerprint_sha256"],
        "operation": inspection["operation"],
        "outcome": inspection["outcome"],
        "issuer_verified": inspection["issuer_verified"],
        "observed_at": inspection["observed_at"],
        "tls_ready": False,
        "hostnames_count": len(inspection["hostnames"]),
        "hostnames_sha256": hashlib.sha256(
            canonical(inspection["hostnames"])
        ).hexdigest(),
    }


def _lifecycle_observation(*, event, state_ok, recovery_hold, software_ok,
                           generation, policy, policy_error, prepared,
                           preparation_error, inspection, previous):
    previous_identity = bool(previous and previous["acme_identity_seen"])
    previous_lineage = bool(previous and previous["lineage_seen"])
    trusted_native = state_ok and not recovery_hold
    storage_ok = trusted_native and prepared is not None

    if storage_ok:
        if inspection is not None and inspection["status"] == "verified":
            persistent_status = "available"
            existing_identity = True
            lineage = "healthy"
        elif previous_identity or previous_lineage:
            persistent_status = "uncertain"
            existing_identity = previous_identity
            lineage = "uncertain" if previous_lineage else "absent"
        else:
            persistent_status = "available"
            existing_identity = False
            lineage = "absent"
    else:
        persistent_status = "unavailable" if preparation_error else "missing"
        existing_identity = previous_identity
        lineage = "uncertain" if previous_lineage else "absent"

    if inspection is not None and inspection["status"] == "verified":
        issuance = {"status": "issued", "local_verified": True}
    elif inspection is not None or previous_identity or previous_lineage:
        issuance = {"status": "uncertain", "local_verified": False}
    else:
        issuance = {"status": "not-started", "local_verified": False}

    if policy is not None:
        policy_value = {
            "status": "approved",
            "hostname_approved": True,
            "challenge_approved": True,
            "challenge": policy["challenge"],
        }
    elif policy_error is None:
        policy_value = {
            "status": "missing",
            "hostname_approved": False,
            "challenge_approved": False,
            "challenge": None,
        }
    else:
        policy_value = {
            "status": "invalid",
            "hostname_approved": False,
            "challenge_approved": False,
            "challenge": None,
        }

    if not trusted_native:
        prep_status = "failed" if prepared is not None else "not-run"
    elif preparation_error is not None:
        prep_status = "failed"
    elif prepared is not None:
        prep_status = "complete"
    else:
        prep_status = "not-run"

    app_available = trusted_native and software_ok
    return {
        "schema": 1,
        "kind": "zog-certificate-lifecycle-observation",
        "event": event,
        "application": {
            "status": "available" if app_available else "invalid",
            "persistent_state_id":
                prepared["storage_id"]
                if app_available and persistent_status == "available" else None,
            "preparation_revision":
                PREPARATION_REVISION if app_available else None,
        },
        "evidence": {
            "schema": 1,
            "kind": "zog-certificate-enablement-evidence",
            "state": {
                "verified": state_ok,
                "recovery_hold": recovery_hold,
            },
            "grant": {
                "status": (
                    "verified" if trusted_native and prepared is not None
                    else ("invalid" if prepared is not None or preparation_error
                          else "missing")
                ),
                "grant_id": (
                    prepared["grant_id"]
                    if trusted_native and prepared is not None else None
                ),
            },
            "software": {
                "status": "verified" if trusted_native and software_ok else "invalid",
                "generation": generation if trusted_native and software_ok else None,
            },
            "policy": policy_value,
            "persistent": {
                "status": persistent_status,
                "existing_acme_identity": existing_identity,
                "lineage_status": lineage,
                "replacement_attempted": False,
            },
            "preparation": {"status": prep_status},
            "issuance": issuance,
            "publication": {"status": "not-started"},
            "external": {"status": "not-verified"},
        },
    }


def observe_live(*, controller_project, root_control_socket, generation,
                 software_view, lifecycle_record, event="status",
                 inspect_request_id=None, python_executable="/usr/bin/python3"):
    """Return a redacted native matrix and advance only the lifecycle status record."""
    require(os.geteuid() == 0, "root-required",
            "native certificate observation requires root")
    require(event in ("install", "reboot", "upgrade", "status"),
            "certificate-native", "unsupported lifecycle event")
    require(Path(sys.executable).resolve() == Path(python_executable).resolve(),
            "certificate-native-installed",
            "native observer interpreter differs from approved interpreter")

    matrix = {}
    previous = load_record(lifecycle_record)

    state_ok = False
    recovery_hold = True
    authority = None
    state_identity = None
    context = None
    try:
        context = inspect_live()
        admission = observe_state_admission(context)
        recovery_hold = admission["recovery_hold"]
        require(not recovery_hold,
                "certificate-native-state",
                "host-install recovery hold blocks native issuer admission")
        state_identity = {
            "installation_id": context.bundle["bootstrap"]["installation_id"],
            "state_volume_id":
                context.bundle["bootstrap"]["state"]["state_volume_id"],
            "boot_id": admission["bindings"]["boot_id"],
            "bootstrap_sha256": admission["bindings"]["bootstrap_sha256"],
            "marker_sha256": admission["bindings"]["marker_sha256"],
        }
        state_ok = True
        matrix["state"] = _gate("PASS", "verified-state", state_identity)
        try:
            installed_discover = _installed_host_discover()
            matrix["hostname_authority_producer"] = _gate(
                "PASS", "installed-reviewed-host-discover", installed_discover
            )
        except (StateError, OSError, ValueError, KeyError, TypeError) as exc:
            matrix["hostname_authority_producer"] = _gate(
                "BLOCKED",
                getattr(exc, "code", "host-discover-installed-unverified"),
            )
        try:
            authority = _authority(context)
            authority_status = (
                "PASS" if authority["status"] == "approved" else "BLOCKED"
            )
            matrix["managed_hostname_authority"] = _gate(
                authority_status,
                "managed-authority-" + authority["status"],
                authority,
            )
        except (StateError, OSError, ValueError, KeyError, TypeError) as exc:
            matrix["managed_hostname_authority"] = _gate(
                "BLOCKED",
                getattr(exc, "code", "managed-authority-unavailable"),
            )
        context.recheck()
    except (StateError, OSError, ValueError, KeyError, TypeError) as exc:
        matrix["state"] = _gate(
            "BLOCKED", getattr(exc, "code", "state-unverified")
        )
        matrix["hostname_authority_producer"] = _gate(
            "NOT RUN", "state-prerequisite-unavailable"
        )
        matrix["managed_hostname_authority"] = _gate(
            "NOT RUN", "state-prerequisite-unavailable"
        )
    finally:
        if context is not None:
            context.close()

    from zog.box_control.project import Project
    from zog.box_control.runtime.root_control import RootControlSystemdTransport

    project = Project(Path(controller_project))
    transport = RootControlSystemdTransport(Path(root_control_socket))

    controller_ok = False
    try:
        owner = _project_owner(project, root_control_socket)
        installed = attest_installed_controller(
            python_executable=python_executable
        )
        matrix["controller"] = _gate(
            "PASS",
            "installed-controller-root-control-verified",
            {"owner": owner, "installed": installed},
        )
        controller_ok = True
    except (StateError, OSError, ValueError, KeyError, TypeError) as exc:
        matrix["controller"] = _gate(
            "BLOCKED", getattr(exc, "code", "controller-unverified")
        )

    software_ok = False
    application = selection = binding = raw = None
    software_error = None
    if controller_ok:
        try:
            application, selection, binding, raw = _software_and_preparation(
                project, generation, software_view
            )
            matrix["software_view"] = _gate(
                "PASS",
                "immutable-application-view-verified",
                {
                    "generation": selection.generation,
                    "view": binding["view"],
                    "binding_digest": binding["binding_digest"],
                    "view_manifest_digest": binding["view_manifest_digest"],
                    "artifacts":
                        list(binding["reclamation_protection"]["artifacts"]),
                    "mount_point": binding["mount_point"],
                    "python": _PYTHON,
                    "certbot": "/applications/certify-manage/bin/certbot",
                },
            )
            software_ok = True
        except Exception as exc:
            # Box-control/image-build use typed domain errors that do not derive
            # from host-install StateError; keep only the bounded class/code here.
            software_error = getattr(exc, "code", exc.__class__.__name__)
            matrix["software_view"] = _gate(
                "BLOCKED", str(software_error)
            )
    else:
        matrix["software_view"] = _gate(
            "NOT RUN", "controller-prerequisite-unavailable"
        )

    policy = None
    policy_error = None
    if controller_ok:
        try:
            policy = _policy(project)
            if policy is None:
                matrix["issuer_policy"] = _gate(
                    "BLOCKED",
                    "awaiting-operator-approved-hostname-challenge",
                )
            else:
                matrix["issuer_policy"] = _gate(
                    "PASS", "protected-root-policy-verified", policy
                )
        except Exception as exc:
            policy_error = getattr(exc, "code", exc.__class__.__name__)
            matrix["issuer_policy"] = _gate(
                "BLOCKED", str(policy_error)
            )
    else:
        matrix["issuer_policy"] = _gate(
            "NOT RUN", "controller-prerequisite-unavailable"
        )

    prepared = None
    preparation_error = None
    if software_ok:
        try:
            prepared = _prepared(
                project, application, generation, raw, transport
            )
            if prepared is None:
                matrix["preparation"] = _gate(
                    "NOT RUN", "application-preparation-not-run"
                )
                matrix["grant_storage"] = _gate(
                    "NOT RUN", "application-preparation-not-run"
                )
            else:
                matrix["preparation"] = _gate(
                    "PASS", "prepared-binding-terminal", {
                        "preparation_revision":
                            prepared["preparation_revision"],
                        "preparation_attempt_id":
                            prepared["preparation_attempt_id"],
                        "generation": prepared["generation"],
                        "steps": prepared["steps"],
                    }
                )
                matrix["grant_storage"] = _gate(
                    "PASS", "issuer-grant-storage-verified", {
                        key: prepared[key] for key in (
                            "storage_id", "grant_id", "issuer_uid",
                            "issuer_gid", "certificate_data_path",
                            "certificate_data_mode",
                        )
                    }
                )
        except Exception as exc:
            preparation_error = getattr(
                exc, "code", exc.__class__.__name__
            )
            matrix["preparation"] = _gate(
                "BLOCKED", str(preparation_error)
            )
            matrix["grant_storage"] = _gate(
                "BLOCKED", str(preparation_error)
            )
    else:
        matrix["preparation"] = _gate(
            "NOT RUN", "software-prerequisite-unavailable"
        )
        matrix["grant_storage"] = _gate(
            "NOT RUN", "software-prerequisite-unavailable"
        )

    inspection = None
    if inspect_request_id is None:
        matrix["selected_inspection"] = _gate(
            "NOT RUN", "no-selected-inspect-request"
        )
    elif prepared is None or policy is None:
        matrix["selected_inspection"] = _gate(
            "NOT RUN", "issuer-prerequisite-unavailable"
        )
    else:
        try:
            inspection = _inspect_selected(
                project, transport, inspect_request_id, prepared, policy
            )
            matrix["selected_inspection"] = _gate(
                "PASS" if inspection["status"] == "verified" else "BLOCKED",
                "selected-inspection-" + inspection["status"],
                inspection,
            )
        except Exception as exc:
            matrix["selected_inspection"] = _gate(
                "BLOCKED",
                str(getattr(exc, "code", exc.__class__.__name__)),
            )

    # host-deploy owns the managed-root-observation -> exact policy_sha256 and
    # local delivery-service binding. Never claim it here.
    matrix["host_deploy_owner_policy_binding"] = _gate(
        "NOT RUN",
        "host-deploy-policy-sha256-binding-required",
        {
            "root_assignment_sha256":
                None if authority is None else authority["assignment_sha256"],
            "local_policy_sha256":
                None if policy is None else policy["policy_sha256"],
        },
    )

    observation = _lifecycle_observation(
        event=event,
        state_ok=state_ok,
        recovery_hold=recovery_hold,
        software_ok=software_ok,
        generation=generation,
        policy=policy,
        policy_error=policy_error,
        prepared=prepared,
        preparation_error=preparation_error,
        inspection=inspection,
        previous=previous,
    )
    lifecycle = reconcile(previous, observation)
    store_record(lifecycle_record, lifecycle["record"], previous)

    issuer_required = (
        "state", "controller", "software_view", "issuer_policy",
        "preparation", "grant_storage",
    )
    issuer_ready = all(matrix[name]["status"] == "PASS"
                       for name in issuer_required)
    if previous and (previous["acme_identity_seen"] or previous["lineage_seen"]):
        issuer_ready = issuer_ready and (
            matrix["selected_inspection"]["status"] == "PASS"
        )
    managed_ready = (
        matrix["hostname_authority_producer"]["status"] == "PASS"
        and matrix["managed_hostname_authority"]["status"] == "PASS"
    )

    return {
        "schema": "zog-host-install-native-issuer-observation-v1",
        "status": "PASS" if issuer_ready else "BLOCKED",
        "code": (
            "issuer-ready-for-operator-authorized-selected-operation"
            if issuer_ready
            else lifecycle["status"]["code"]
        ),
        "matrix": matrix,
        "lifecycle": lifecycle,
        "managed_authority_ready": managed_ready,
        "host_deploy_native_gate_handoff_ready": False,
        "host_deploy_blocker": "host-deploy-policy-sha256-binding-required",
        "production_activation_authorized": False,
        "live_acme_authorized": False,
        "nginx_reload_authorized": False,
    }
