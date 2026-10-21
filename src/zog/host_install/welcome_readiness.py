"""Sanitized read-only bootstrap readiness for console/welcome consumers.

The root producer may inspect protected STATE, but the unprivileged consumer never
receives raw STATE paths, device identities, host-key material, admission receipts,
controller data, or mutation authority.
"""
from datetime import datetime, timedelta, timezone
import grp
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import struct

from . import state_admission
from .state_contract import ACCOUNTS, StateError, canonical, decode, fields, header, identifier, require, sha
from .state_inspect import host_generation_report, inspect_live, directory, metadata

SOCKET = "/run/host-install/welcome.sock"
ACCOUNT = "host-welcome"
SCHEMA = "zog-host-install-bootstrap-readiness-v1"
TIMEOUT = 3
REQUEST_LIMIT = 4096
RESPONSE_LIMIT = 32768
FRESH_SECONDS = 15
STATUSES = {"verified", "pending", "unknown", "degraded", "failed"}
_INVALID_STATE_CODES = {
    # Protected bytes/records were readable enough to classify but are malformed,
    # internally inconsistent, or violate the fixed STATE trust contract.
    "account-mismatch", "account-profile", "boot-provenance", "ca-digest",
    "ca-path", "configuration-owner", "control-authority", "duplicate-field",
    "generation", "hardlink", "host-root-device", "identity-binding", "initialization-policy",
    "inspection-data-invalid", "installation-mode", "invalid-digest",
    "invalid-integer", "invalid-json", "invalid-number", "invalid-uuid",
    "marker-mismatch", "nested-mount", "ownership-mode", "record-binding",
    "record-fields", "record-size", "registry", "security-claim", "slot",
    "slot-binding", "state-path", "state-schema", "unsupported-feature",
    "unsupported-schema", "unsafe-path", "wrong-mount", "wrong-volume",
}
_IDENTITY_PENDING_CODES = {
    "consumption-unavailable", "initialization-not-authorized",
    "layout-not-prepared", "operation-incomplete",
}


def _now():
    return datetime.now(timezone.utc)


def _time_text(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def boot_id():
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return None
    return value if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value) else None


def welcome_account():
    """Return the dedicated presentation UID/GID without altering STATE accounts."""
    try:
        user = pwd.getpwnam(ACCOUNT)
        group = grp.getgrnam(ACCOUNT)
    except KeyError as exc:
        raise StateError("welcome-account", "dedicated host-welcome account required") from exc
    protected_uids = {row["uid"] for row in ACCOUNTS["users"].values()}
    protected_gids = set(ACCOUNTS["groups"].values())
    require(user.pw_uid != 0 and group.gr_gid != 0 and
            user.pw_uid not in protected_uids and group.gr_gid not in protected_gids,
            "welcome-account", "host-welcome must be separate from protected service accounts")
    require(user.pw_gid == group.gr_gid and
            len([row for row in pwd.getpwall() if row.pw_uid == user.pw_uid]) == 1 and
            len([row for row in grp.getgrall() if row.gr_gid == group.gr_gid]) == 1,
            "welcome-account", "host-welcome UID/GID must be unique")
    require(user.pw_shell.endswith("/nologin"),
            "welcome-account", "host-welcome must not be a login account")
    require(set(os.getgrouplist(ACCOUNT, group.gr_gid)) == {group.gr_gid},
            "welcome-account", "host-welcome must not inherit supplementary privilege groups")
    return user.pw_uid, group.gr_gid


def _item(status, message_code, evidence_ref=None):
    require(status in STATUSES, "welcome-status", "invalid readiness status")
    require(type(message_code) is str and
            re.fullmatch(r"[a-z][a-z0-9-]{0,63}", message_code),
            "welcome-status", "invalid message code")
    require(evidence_ref is None or
            (type(evidence_ref) is str and 0 < len(evidence_ref) <= 160 and
             not any(ord(c) < 32 or ord(c) == 127 for c in evidence_ref)),
            "welcome-status", "invalid evidence reference")
    return {"status": status, "message_code": message_code, "evidence_ref": evidence_ref}


def _headless(items):
    states = {items[name]["status"] for name in
              ("installation", "state_integrity", "host_identity", "recovery", "boot_generation")}
    if "failed" in states:
        return _item("failed", "headless-installation-blocked")
    if "degraded" in states:
        return _item("degraded", "headless-installation-degraded")
    if states == {"verified"}:
        return _item("verified", "headless-installation-ready",
                     "host-install:verified-core-bootstrap")
    if "pending" in states:
        return _item("pending", "headless-installation-pending")
    return _item("unknown", "headless-installation-unknown")


def _base(now=None):
    now = now or _now()
    return {
        "schema": SCHEMA,
        "snapshot_id": secrets.token_hex(16),
        "observed_at": _time_text(now),
        "boot_id": boot_id(),
        "installation_id": None,
        "installation": _item("unknown", "installation-unobserved"),
        "state_integrity": _item("unknown", "state-unobserved"),
        "host_identity": _item("unknown", "identity-unobserved"),
        "recovery": _item("unknown", "recovery-unobserved"),
        "boot_generation": {
            **_item("unknown", "boot-generation-unobserved"),
            "selected_slot": None,
            "booted_slot": None,
            "selected_generation": None,
            "booted_generation": None,
            "selected_matches_booted": None,
        },
        "headless_installation": _item("unknown", "headless-installation-unknown"),
        "optional_applications": {
            "progress_authoritative": False,
            "download_authorized": False,
            "launch_authorized": False,
            "generation_promotion_authorized": False,
            "login_manager_start_authorized": False,
            "reboot_authorized": False,
            "graphics_required_for_headless_success": False,
        },
        "observation_dependencies": {
            "state_required_for_socket_start": False,
            "network_required": False,
            "controller_required": False,
            "browser_required": False,
        },
        "capabilities": {
            "state_write": False,
            "device_write": False,
            "identity_secret_access": False,
            "controller_command": False,
            "application_mutation": False,
        },
    }


def _state_failure(snapshot, exc):
    invalid = isinstance(exc, StateError) and exc.code in _INVALID_STATE_CODES
    snapshot["state_integrity"] = _item(
        "failed" if invalid else "unknown",
        "state-invalid" if invalid else "state-unavailable",
    )
    snapshot["installation"] = _item("unknown", "installation-unavailable")
    snapshot["host_identity"] = _item("unknown", "identity-unavailable")
    snapshot["recovery"] = _item("unknown", "recovery-unavailable")
    snapshot["boot_generation"].update(_item("unknown", "boot-generation-unavailable"))
    snapshot["headless_installation"] = _headless(snapshot)
    return snapshot


def snapshot_live(*, now=None):
    """Perform one bounded protected read and return only the sanitized projection."""
    require(os.geteuid() == 0, "root-required",
            "bootstrap readiness producer requires root inspection")
    snapshot = _base(now)
    try:
        context = inspect_live()
    except (StateError, OSError, ValueError) as exc:
        return validate_snapshot(_state_failure(snapshot, exc))

    with context:
        bundle = context.bundle
        installation = bundle["installation"]
        snapshot["installation_id"] = installation["installation_id"]
        snapshot["state_integrity"] = _item(
            "verified", "state-verified", "host-install:live-state"
        )
        snapshot["installation"] = _item(
            "verified", "installation-record-verified",
            "host-install:installation:" + installation["record_id"],
        )

        try:
            generation = host_generation_report(context)
            selected = generation["selected_slot"]
            booted = generation["booted_slot"]
            selected_row = generation["slots"][selected]
            booted_row = None if booted is None else generation["slots"][booted]
            snapshot["boot_generation"] = {
                **_item(
                    "verified" if booted is not None else "unknown",
                    "booted-generation-observed" if booted is not None
                    else "booted-generation-unverified",
                    "host-install:boot-generation" if booted is not None else None,
                ),
                "selected_slot": selected,
                "booted_slot": booted,
                "selected_generation": selected_row["generation"],
                "booted_generation": None if booted_row is None else booted_row["generation"],
                "selected_matches_booted": None if booted is None else selected == booted,
            }
        except (StateError, OSError, ValueError, KeyError, TypeError):
            snapshot["boot_generation"].update(
                _item("unknown", "boot-generation-unavailable")
            )

        try:
            admission = state_admission.observe(context)
            if admission["recovery_hold"]:
                snapshot["recovery"] = _item(
                    "failed", "recovery-required", "host-install:recovery-hold"
                )
                snapshot["host_identity"] = _item(
                    "unknown", "identity-blocked-by-recovery"
                )
            else:
                snapshot["recovery"] = _item(
                    "verified", "recovery-clear", "host-install:recovery-clear"
                )
                snapshot["host_identity"] = _item(
                    "verified", "identity-consumption-observed",
                    "host-install:identity-consumption",
                )
        except StateError as exc:
            if exc.code in _IDENTITY_PENDING_CODES:
                snapshot["host_identity"] = _item("pending", "identity-pending")
                snapshot["recovery"] = _item("unknown", "recovery-unobserved")
            else:
                snapshot["host_identity"] = _item("unknown", "identity-unavailable")
                snapshot["recovery"] = _item("unknown", "recovery-unavailable")
        except (OSError, ValueError, KeyError, TypeError):
            snapshot["host_identity"] = _item("unknown", "identity-unavailable")
            snapshot["recovery"] = _item("unknown", "recovery-unavailable")
        context.recheck()

    snapshot["headless_installation"] = _headless(snapshot)
    return validate_snapshot(snapshot)


def graphical_handoff(evidence):
    """Pure first-boot handoff gate; never launches or authorizes a process."""
    fields(evidence, "schema kind requested artifact controller session_security")
    require(evidence["schema"] == 1 and
            evidence["kind"] == "zog-graphical-handoff-evidence",
            "graphical-handoff", "unsupported handoff evidence")
    require(type(evidence["requested"]) is bool,
            "graphical-handoff", "requested must be boolean")
    artifact, controller, session = (
        evidence["artifact"], evidence["controller"], evidence["session_security"]
    )
    fields(artifact, "status software_id")
    fields(controller, "status request_id")
    fields(session, "status capability_id")
    require(artifact["status"] in ("verified", "missing", "invalid", "revoked"),
            "graphical-handoff", "artifact status")
    require(controller["status"] in ("authorized", "missing", "unavailable", "denied"),
            "graphical-handoff", "controller status")
    require(session["status"] in ("verified", "missing", "invalid", "unavailable"),
            "graphical-handoff", "session status")
    for value, name, required in (
        (artifact["software_id"], "software id", artifact["status"] == "verified"),
        (controller["request_id"], "controller request id",
         controller["status"] == "authorized"),
        (session["capability_id"], "session capability id",
         session["status"] == "verified"),
    ):
        require(value is None or
                (type(value) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value)),
                "graphical-handoff", name)
        if required:
            require(value is not None, "graphical-handoff", name + " required")
    eligible = (evidence["requested"] and artifact["status"] == "verified" and
                controller["status"] == "authorized" and
                session["status"] == "verified")
    if not evidence["requested"]:
        code = "graphical-session-not-requested"
    elif eligible:
        code = "eligible-for-authorized-supervisor-request"
    else:
        code = "graphical-session-gates-incomplete"
    return {
        "status": "eligible" if eligible else
                  ("not-requested" if not evidence["requested"] else "blocked"),
        "code": code,
        "supervisor_request_eligible": eligible,
        "host_install_authorizes_launch": False,
        "auto_start": False,
        "auto_reboot": False,
        "installation_success_depends_on_graphics": False,
    }


def _validate_item(value):
    fields(value, "status message_code evidence_ref")
    require(value["status"] in STATUSES, "welcome-snapshot", "invalid item status")
    require(type(value["message_code"]) is str and
            re.fullmatch(r"[a-z][a-z0-9-]{0,63}", value["message_code"]),
            "welcome-snapshot", "invalid message code")
    require(value["evidence_ref"] is None or
            (type(value["evidence_ref"]) is str and
             0 < len(value["evidence_ref"]) <= 160),
            "welcome-snapshot", "invalid evidence ref")


def validate_snapshot(snapshot):
    fields(snapshot, """schema snapshot_id observed_at boot_id installation_id installation
                       state_integrity host_identity recovery boot_generation
                       headless_installation optional_applications
                       observation_dependencies capabilities""")
    require(snapshot["schema"] == SCHEMA, "welcome-snapshot", "unsupported schema")
    require(type(snapshot["snapshot_id"]) is str and
            re.fullmatch(r"[0-9a-f]{32}", snapshot["snapshot_id"]),
            "welcome-snapshot", "snapshot id")
    require(type(snapshot["observed_at"]) is str and len(snapshot["observed_at"]) <= 40,
            "welcome-snapshot", "observed timestamp")
    try:
        observed = datetime.fromisoformat(snapshot["observed_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise StateError("welcome-snapshot", "invalid observed timestamp") from exc
    require(observed.tzinfo is not None and observed.utcoffset() is not None,
            "welcome-snapshot", "observed timestamp timezone required")
    if snapshot["boot_id"] is not None:
        require(type(snapshot["boot_id"]) is str and
                re.fullmatch(r"[0-9a-f-]{36}", snapshot["boot_id"]),
                "welcome-snapshot", "boot id")
    if snapshot["installation_id"] is not None:
        identifier(snapshot["installation_id"])
    for name in ("installation", "state_integrity", "host_identity",
                 "recovery", "headless_installation"):
        _validate_item(snapshot[name])
    generation = snapshot["boot_generation"]
    fields(generation, """status message_code evidence_ref selected_slot booted_slot
                          selected_generation booted_generation selected_matches_booted""")
    _validate_item({key: generation[key] for key in
                    ("status", "message_code", "evidence_ref")})
    for slot in ("selected_slot", "booted_slot"):
        require(generation[slot] in (None, "HOST-A", "HOST-B"),
                "welcome-snapshot", slot)
    for key in ("selected_generation", "booted_generation"):
        require(generation[key] is None or
                (type(generation[key]) is str and
                 re.fullmatch(r"[A-Za-z0-9._-]{1,128}", generation[key])),
                "welcome-snapshot", key)
    require(generation["selected_matches_booted"] in (None, True, False),
            "welcome-snapshot", "selected_matches_booted")
    require(snapshot["optional_applications"] == {
        "progress_authoritative": False,
        "download_authorized": False,
        "launch_authorized": False,
        "generation_promotion_authorized": False,
        "login_manager_start_authorized": False,
        "reboot_authorized": False,
        "graphics_required_for_headless_success": False,
    }, "welcome-snapshot", "optional application boundary")
    require(snapshot["observation_dependencies"] == {
        "state_required_for_socket_start": False,
        "network_required": False,
        "controller_required": False,
        "browser_required": False,
    }, "welcome-snapshot", "observation dependency boundary")
    require(snapshot["capabilities"] == {
        "state_write": False,
        "device_write": False,
        "identity_secret_access": False,
        "controller_command": False,
        "application_mutation": False,
    }, "welcome-snapshot", "capability boundary")
    return snapshot


def peer_uid(connection):
    return struct.unpack(
        "3i",
        connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i")),
    )[1]


def receive(connection, limit):
    data = bytearray()
    while True:
        chunk = connection.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            return decode(bytes(data))
        data.extend(chunk)
        require(len(data) <= limit, "message-size", "local protocol limit exceeded")


def request_valid(request):
    header(request, "zog-host-welcome-readiness-request", "nonce")
    sha(request["nonce"])
    return request["nonce"]


def serve_connection(connection):
    require(os.geteuid() == 0, "root-required", "root producer required")
    expected_uid, _ = welcome_account()
    connection.settimeout(TIMEOUT)
    require(peer_uid(connection) == expected_uid,
            "welcome-peer", "dedicated host-welcome UID required")
    nonce = request_valid(receive(connection, REQUEST_LIMIT))
    response = {
        "schema": 1,
        "kind": "zog-host-welcome-readiness-response",
        "nonce": nonce,
        "ok": True,
        "snapshot": snapshot_live(),
    }
    connection.sendall(canonical(response))


def serve_stdin():
    with socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        require(connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX and
                connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
                "welcome-socket", "local stream socket required")
        serve_connection(connection)
    return {"status": "welcome-readiness-served", "mutation_authorized": False}


def validate_response(response, nonce, *, now=None):
    require(type(response) is dict and response.get("ok") is True,
            "welcome-response", "producer did not return a snapshot")
    header(response, "zog-host-welcome-readiness-response", "nonce ok snapshot")
    require(response["nonce"] == nonce, "welcome-nonce", "response nonce mismatch")
    snapshot = validate_snapshot(response["snapshot"])
    current_boot = boot_id()
    require(current_boot is not None and snapshot["boot_id"] == current_boot,
            "welcome-stale", "snapshot is not from this boot")
    now = now or _now()
    observed = datetime.fromisoformat(snapshot["observed_at"].replace("Z", "+00:00"))
    age = now - observed
    require(timedelta(seconds=-5) <= age <= timedelta(seconds=FRESH_SECONDS),
            "welcome-stale", "snapshot is stale or future-dated")
    return snapshot


def request_live():
    """Unprivileged authenticated client; no cached JSON or caller-selected socket."""
    uid, gid = welcome_account()
    require((os.geteuid(), os.getegid()) == (uid, gid),
            "welcome-account", "run as dedicated host-welcome account")
    parent = directory("/run/host-install")
    try:
        metadata(parent, 0, 0, 0o755)
        entry = os.stat("welcome.sock", dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISSOCK(entry.st_mode) and
                (entry.st_uid, entry.st_gid, stat.S_IMODE(entry.st_mode)) ==
                (0, gid, 0o660),
                "welcome-socket", "unexpected welcome socket ownership/mode")
        nonce = secrets.token_hex(32)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(TIMEOUT)
            connection.connect(f"/proc/self/fd/{parent}/welcome.sock")
            require(peer_uid(connection) == 0, "welcome-peer", "root producer required")
            connection.sendall(canonical({
                "schema": 1,
                "kind": "zog-host-welcome-readiness-request",
                "nonce": nonce,
            }))
            connection.shutdown(socket.SHUT_WR)
            response = receive(connection, RESPONSE_LIMIT)
        return validate_response(response, nonce)
    finally:
        os.close(parent)
