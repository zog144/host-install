"""Durable, secret-free certificate application lifecycle coordination.

This is not a certificate issuer or controller. Application availability and all
certificate evidence are observations supplied by trusted adapters. The record
contains no hostname, ACME URL, certificate bytes, keys, DNS credentials, or
provider identifiers.
"""
import fcntl
import os
import stat
from pathlib import Path

from .certificate_gate import decide as gate_decide, validate_evidence
from .state_contract import canonical, decode, fields, require

SCHEMA = 1
RECORD_KIND = "zog-certificate-lifecycle-record"
OBSERVATION_KIND = "zog-certificate-lifecycle-observation"
APPLICATION = "certify-manage"


def _token(value, name, *, optional=False):
    import re
    if optional and value is None:
        return
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value),
            "certificate-lifecycle", name)


def validate_record(record):
    fields(record, """schema kind application revision persistent_state_id prepared_revision
                      acme_identity_seen lineage_seen first_software_generation
                      last_software_generation last_event last_code""")
    require(record["schema"] == SCHEMA and record["kind"] == RECORD_KIND and
            record["application"] == APPLICATION,
            "certificate-lifecycle", "unsupported lifecycle record")
    require(type(record["revision"]) is int and record["revision"] > 0,
            "certificate-lifecycle", "positive lifecycle revision required")
    _token(record["persistent_state_id"], "persistent state id", optional=True)
    _token(record["prepared_revision"], "preparation revision", optional=True)
    require(type(record["acme_identity_seen"]) is bool and
            type(record["lineage_seen"]) is bool,
            "certificate-lifecycle", "durable observation flags")
    _token(record["first_software_generation"], "first software generation", optional=True)
    _token(record["last_software_generation"], "last software generation", optional=True)
    require(record["last_event"] in ("install", "reboot", "upgrade", "status"),
            "certificate-lifecycle", "event")
    _token(record["last_code"], "last status code")
    return record


def validate_observation(observation):
    fields(observation, "schema kind event application evidence")
    require(observation["schema"] == SCHEMA and
            observation["kind"] == OBSERVATION_KIND,
            "certificate-lifecycle", "unsupported lifecycle observation")
    require(observation["event"] in ("install", "reboot", "upgrade", "status"),
            "certificate-lifecycle", "event")
    application = observation["application"]
    fields(application, "status persistent_state_id preparation_revision")
    require(application["status"] in ("available", "unavailable", "invalid"),
            "certificate-lifecycle", "application status")
    evidence = validate_evidence(observation["evidence"])
    if application["status"] == "available":
        _token(application["preparation_revision"], "preparation revision")
        if evidence["persistent"]["status"] == "available":
            _token(application["persistent_state_id"], "persistent state id")
        else:
            require(application["persistent_state_id"] is None,
                    "certificate-lifecycle",
                    "persistent state id requires available persistent state")
    else:
        require(application["persistent_state_id"] is None and
                application["preparation_revision"] is None,
                "certificate-lifecycle",
                "unavailable/invalid application cannot assert state identity")
    return observation


def _blank(event):
    return {
        "schema": SCHEMA,
        "kind": RECORD_KIND,
        "application": APPLICATION,
        "revision": 1,
        "persistent_state_id": None,
        "prepared_revision": None,
        "acme_identity_seen": False,
        "lineage_seen": False,
        "first_software_generation": None,
        "last_software_generation": None,
        "last_event": event,
        "last_code": "lifecycle-created",
    }


def _safe_flags():
    return {
        "self_signed_allowed": False,
        "public_auto_issuance_allowed": False,
        "proxy_exposure_allowed": False,
        "archive_role_change_allowed": False,
        "station_observer_mtls_separate": True,
    }


def _external_observed(evidence):
    return (evidence["issuance"]["status"] == "issued" and
            evidence["issuance"]["local_verified"] and
            evidence["publication"]["status"] == "loaded" and
            evidence["external"]["status"] == "verified")


def _status(base, record, observation, generation_changed):
    result = dict(base)
    result.update({
        "application_available": observation["application"]["status"] == "available",
        "configuration_pending":
            base["code"] == "awaiting-operator-approved-hostname-challenge",
        "persistent_state_bound": record["persistent_state_id"] is not None,
        "durable_preparation_complete": record["prepared_revision"] is not None,
        "generation_changed": generation_changed,
        "external_https_observed": _external_observed(observation["evidence"]),
    })
    result.update(_safe_flags())
    return result


def _blocked(code, next_step, identity_action):
    result = {
        "status": "blocked",
        "code": code,
        "next_step": next_step,
        "identity_action": identity_action,
        "issuance_allowed": False,
        "host_deploy_handoff_ready": False,
        "external_https_ready": False,
    }
    result.update(_safe_flags())
    return result


def reconcile(previous, observation):
    """Advance secret-free lifecycle evidence using one simulated/live observation."""
    validate_observation(observation)
    if previous is None:
        record = _blank(observation["event"])
        old_generation = None
    else:
        validate_record(previous)
        record = dict(previous)
        record["revision"] += 1
        old_generation = previous["last_software_generation"]

    evidence = observation["evidence"]
    software = evidence["software"]
    if software["status"] == "verified":
        generation = software["generation"]
        if record["first_software_generation"] is None:
            record["first_software_generation"] = generation
        record["last_software_generation"] = generation
    generation_changed = (old_generation is not None and
                          record["last_software_generation"] is not None and
                          old_generation != record["last_software_generation"])

    application = observation["application"]
    identity_action = ("preserve-existing" if
                       (record["acme_identity_seen"] or
                        evidence["persistent"]["existing_acme_identity"])
                       else "create-only-on-authorized-issuance")
    override = None

    if (application["status"] == "invalid"
            and evidence["state"]["verified"]
            and not evidence["state"]["recovery_hold"]):
        override = _blocked("certificate-application-invalid",
                            "repair-certificate-application", identity_action)

    if application["status"] == "available" and override is None:
        persistent = evidence["persistent"]
        if persistent["status"] == "available":
            state_id = application["persistent_state_id"]
            if record["persistent_state_id"] is None:
                record["persistent_state_id"] = state_id
            elif record["persistent_state_id"] != state_id:
                override = _blocked("certificate-persistent-state-replaced",
                                    "operator-reconciliation", identity_action)

            if override is None and record["acme_identity_seen"] and not persistent["existing_acme_identity"]:
                override = _blocked("acme-identity-disappeared",
                                    "operator-reconciliation", "preserve-existing")
            if override is None and record["lineage_seen"] and persistent["lineage_status"] == "absent":
                override = _blocked("certificate-lineage-disappeared",
                                    "operator-reconciliation", identity_action)

            if persistent["existing_acme_identity"]:
                record["acme_identity_seen"] = True
                identity_action = "preserve-existing"
            if persistent["lineage_status"] == "healthy":
                record["lineage_seen"] = True

            prep_revision = application["preparation_revision"]
            if record["prepared_revision"] is not None:
                if record["prepared_revision"] != prep_revision and override is None:
                    override = _blocked("certificate-preparation-migration-required",
                                        "approve-preparation-migration", identity_action)
                elif evidence["preparation"]["status"] != "complete" and override is None:
                    override = _blocked("certificate-preparation-state-regressed",
                                        "operator-reconciliation", identity_action)
            elif evidence["preparation"]["status"] == "complete":
                record["prepared_revision"] = prep_revision

    gate = gate_decide(evidence)
    if override is None:
        status = gate
        if application["status"] == "unavailable":
            if (gate["code"] in ("application-preparation-required",
                                 "ready-for-authorized-issuance") or
                    gate["code"].startswith("persistent-state-")):
                status = {
                    **gate,
                    "status": "pending",
                    "code": "certificate-application-unavailable",
                    "next_step": "wait-for-certificate-application",
                    "issuance_allowed": False,
                }
            elif gate["code"] == "certificate-issuance-pending":
                status = _blocked("certificate-issuance-availability-lost",
                                  "operator-reconciliation", identity_action)
    else:
        status = override

    status["identity_action"] = identity_action
    status = _status(status, record, observation, generation_changed)
    record["last_event"] = observation["event"]
    record["last_code"] = status["code"]
    validate_record(record)
    return {"record": record, "status": status}


def _open_parent(path):
    path = Path(path)
    require(path.name not in ("", ".", ".."), "certificate-lifecycle", "record filename")
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    return path, fd


def _read_at(fd, name):
    try:
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        return None
    try:
        st = os.fstat(handle)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                st.st_uid == os.geteuid() and st.st_gid == os.getegid() and
                stat.S_IMODE(st.st_mode) == 0o600,
                "certificate-lifecycle-record-unsafe", name)
        data = bytearray()
        while len(data) <= 65536:
            chunk = os.read(handle, min(8192, 65537 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) <= 65536, "record-size", name)
        return bytes(data)
    finally:
        os.close(handle)


def load_record(path):
    path, fd = _open_parent(path)
    try:
        raw = _read_at(fd, path.name)
        return None if raw is None else validate_record(decode(raw))
    finally:
        os.close(fd)


def store_record(path, record, expected_previous):
    """Atomically replace one simulated lifecycle record with stale-writer detection."""
    validate_record(record)
    if expected_previous is not None:
        validate_record(expected_previous)
        require(record["revision"] == expected_previous["revision"] + 1,
                "certificate-lifecycle-stale", "revision")
    else:
        require(record["revision"] == 1,
                "certificate-lifecycle-stale", "first revision")
    path, fd = _open_parent(path)
    lock_name = "." + path.name + ".lock"
    lock_fd = os.open(lock_name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(lock_fd, 0o600)
        st = os.fstat(lock_fd)
        require(st.st_uid == os.geteuid() and st.st_gid == os.getegid(),
                "certificate-lifecycle-record-unsafe", lock_name)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        existing = _read_at(fd, path.name)
        expected = None if expected_previous is None else canonical(expected_previous)
        require(existing == expected,
                "certificate-lifecycle-stale", "record changed since load")
        data = canonical(record)
        pending = ".pending." + path.name
        staged = _read_at(fd, pending)
        if staged is None:
            pending_fd = os.open(pending,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
            try:
                view = memoryview(data)
                while view:
                    count = os.write(pending_fd, view)
                    require(count > 0, "short-write", pending)
                    view = view[count:]
                os.fsync(pending_fd)
            finally:
                os.close(pending_fd)
        else:
            require(staged == data,
                    "certificate-lifecycle-pending-conflict", pending)
        os.fsync(fd)
        os.replace(pending, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(lock_fd)
        os.close(fd)
