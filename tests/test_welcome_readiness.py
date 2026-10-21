import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from zog.host_install.state_contract import StateError
from zog.host_install import state_contract
from zog.host_install import welcome_readiness as welcome

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = json.loads((ROOT / "examples/state-contract-v1/bundle.json").read_text())
FIXTURES = json.loads((ROOT / "examples/welcome-bootstrap-v1/scenarios.json").read_text())


class Context:
    def __init__(self):
        self.bundle = copy.deepcopy(BUNDLE)
        self.checks = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def recheck(self):
        self.checks += 1


def generation(booted="HOST-A"):
    r = BUNDLE["installation"]["installer_recorded"]
    return {
        "selected_slot": "HOST-A",
        "booted_slot": booted,
        "slots": {
            "HOST-A": {
                "generation": r["expected_host_generation"],
                "root_partuuid": r["root_partuuid"],
            },
            "HOST-B": None,
        },
    }


def snapshot(*, admission=None, generation_value=None):
    context = Context()
    if admission is None:
        admission = {
            "status": "consumption-observed",
            "recovery_hold": False,
            "receipt": {"fingerprint": "a" * 64},
            "bindings": {},
            "identity_action": "verify-existing",
            "control_authorized": False,
            "transport_enabled": False,
        }
    if generation_value is None:
        generation_value = generation()
    now = datetime(2026, 10, 16, 17, 0, tzinfo=timezone.utc)
    with patch.object(welcome.os, "geteuid", return_value=0),          patch.object(welcome, "boot_id", return_value="11111111-1111-4111-8111-111111111111"),          patch.object(welcome, "inspect_live", return_value=context),          patch.object(welcome, "host_generation_report", return_value=generation_value),          patch.object(welcome.state_admission, "observe", return_value=admission):
        return welcome.snapshot_live(now=now), context


def test_verified_snapshot_is_sanitized_and_headless_complete():
    value, context = snapshot()
    assert value["state_integrity"]["status"] == "verified"
    assert value["installation"]["status"] == "verified"
    assert value["host_identity"]["status"] == "verified"
    assert value["recovery"]["status"] == "verified"
    assert value["boot_generation"]["status"] == "verified"
    assert value["headless_installation"]["status"] == "verified"
    assert value["optional_applications"]["graphics_required_for_headless_success"] is False
    assert value["optional_applications"]["launch_authorized"] is False
    assert value["optional_applications"]["login_manager_start_authorized"] is False
    assert value["capabilities"] == {
        "state_write": False,
        "device_write": False,
        "identity_secret_access": False,
        "controller_command": False,
        "application_mutation": False,
    }
    encoded = json.dumps(value, sort_keys=True)
    for forbidden in (
        "fingerprint", "receipt", "private_key", "state_device",
        "partition_partuuid", "filesystem_uuid", "control_authority",
    ):
        assert forbidden not in encoded
    assert context.checks == 1


@pytest.mark.parametrize(
    "code,status,message",
    [
        ("state-not-mounted", "unknown", "state-unavailable"),
        ("required-path-missing", "unknown", "state-unavailable"),
        ("record-fields", "failed", "state-invalid"),
        ("marker-mismatch", "failed", "state-invalid"),
        ("invalid-json", "failed", "state-invalid"),
        ("duplicate-field", "failed", "state-invalid"),
        ("invalid-number", "failed", "state-invalid"),
        ("record-size", "failed", "state-invalid"),
        ("host-root-device", "failed", "state-invalid"),
    ],
)
def test_reviewed_invalid_state_code_taxonomy_is_closed():
    assert welcome._INVALID_STATE_CODES == {
        "account-mismatch",
        "account-profile",
        "boot-provenance",
        "ca-digest",
        "ca-path",
        "configuration-owner",
        "control-authority",
        "duplicate-field",
        "generation",
        "hardlink",
        "host-root-device",
        "identity-binding",
        "initialization-policy",
        "inspection-data-invalid",
        "installation-mode",
        "invalid-digest",
        "invalid-integer",
        "invalid-json",
        "invalid-number",
        "invalid-uuid",
        "marker-mismatch",
        "nested-mount",
        "ownership-mode",
        "record-binding",
        "record-fields",
        "record-size",
        "registry",
        "security-claim",
        "slot",
        "slot-binding",
        "state-path",
        "state-schema",
        "unsupported-feature",
        "unsupported-schema",
        "unsafe-path",
        "wrong-mount",
        "wrong-volume",
    }


def test_early_or_corrupt_state_fails_closed_without_green_status(code, status, message):
    now = datetime(2026, 10, 16, 17, 0, tzinfo=timezone.utc)
    with patch.object(welcome.os, "geteuid", return_value=0),          patch.object(welcome, "boot_id", return_value="11111111-1111-4111-8111-111111111111"),          patch.object(welcome, "inspect_live", side_effect=StateError(code, "synthetic")):
        value = welcome.snapshot_live(now=now)
    assert value["state_integrity"] == {
        "status": status, "message_code": message, "evidence_ref": None
    }
    assert value["headless_installation"]["status"] != "verified"
    assert value["host_identity"]["status"] == "unknown"


def _snapshot_from_protected_bytes(raw, *, validate=None):
    def inspect():
        value = state_contract.decode(raw)
        if validate is not None:
            validate(value)
        raise AssertionError("fixture must fail before STATE inspection completes")

    now = datetime(2026, 10, 16, 17, 0, tzinfo=timezone.utc)
    with patch.object(welcome.os, "geteuid", return_value=0), \
         patch.object(
             welcome,
             "boot_id",
             return_value="11111111-1111-4111-8111-111111111111",
         ), \
         patch.object(welcome, "inspect_live", side_effect=inspect):
        return welcome.snapshot_live(now=now)


@pytest.mark.parametrize(
    "raw,validate",
    [
        (b"{malformed", None),
        (b'{"schema":1,"schema":1}', None),
        (b"\xff", None),
        (b"NaN", None),
        (b"1.5", None),
        (b"x" * 65537, None),
        (
            b"{}",
            lambda value: state_contract.fields(
                value, "schema kind profile installation_id"
            ),
        ),
    ],
)
def test_real_decoder_failures_are_sanitized_as_invalid_state(raw, validate):
    value = _snapshot_from_protected_bytes(raw, validate=validate)
    assert value["state_integrity"] == {
        "status": "failed",
        "message_code": "state-invalid",
        "evidence_ref": None,
    }
    assert value["installation"] == {
        "status": "unknown",
        "message_code": "installation-unavailable",
        "evidence_ref": None,
    }
    assert value["host_identity"]["status"] == "unknown"
    assert value["headless_installation"]["status"] == "failed"

    encoded = json.dumps(value, sort_keys=True)
    assert "malformed" not in encoded
    assert "schema" not in value["state_integrity"]
    assert "duplicate-field" not in encoded
    assert "invalid-json" not in encoded
    assert "invalid-number" not in encoded
    assert "record-size" not in encoded
    assert "record-fields" not in encoded


@pytest.mark.parametrize(
    "code",
    [
        "state-not-mounted",
        "required-path-missing",
        "state-access-denied",
        "state-io-failure",
        "state-inspection-io",
        "topology-unavailable",
        "volume-ambiguous-or-missing",
        "host-root-ambiguous",
        "record-changed",
        "mount-changed",
        "state-read-only",
    ],
)
def test_absent_or_unsafe_to_read_state_remains_unknown(code):
    now = datetime(2026, 10, 16, 17, 0, tzinfo=timezone.utc)
    with patch.object(welcome.os, "geteuid", return_value=0), \
         patch.object(
             welcome,
             "boot_id",
             return_value="11111111-1111-4111-8111-111111111111",
         ), \
         patch.object(
             welcome,
             "inspect_live",
             side_effect=StateError(code, "sensitive diagnostic"),
         ):
        value = welcome.snapshot_live(now=now)
    assert value["state_integrity"] == {
        "status": "unknown",
        "message_code": "state-unavailable",
        "evidence_ref": None,
    }
    assert "sensitive diagnostic" not in json.dumps(value, sort_keys=True)
    assert value["headless_installation"]["status"] != "verified"


def test_incomplete_identity_is_pending_not_installation_success():
    context = Context()
    now = datetime(2026, 10, 16, 17, 0, tzinfo=timezone.utc)
    with patch.object(welcome.os, "geteuid", return_value=0),          patch.object(welcome, "boot_id", return_value="11111111-1111-4111-8111-111111111111"),          patch.object(welcome, "inspect_live", return_value=context),          patch.object(welcome, "host_generation_report", return_value=generation()),          patch.object(
             welcome.state_admission,
             "observe",
             side_effect=StateError("consumption-unavailable", "synthetic"),
         ):
        value = welcome.snapshot_live(now=now)
    assert value["installation"]["status"] == "verified"
    assert value["state_integrity"]["status"] == "verified"
    assert value["host_identity"]["status"] == "pending"
    assert value["headless_installation"]["status"] == "pending"


def test_recovery_hold_blocks_headless_without_projection_writes():
    admission = {
        "status": "recovery-required",
        "recovery_hold": True,
        "receipt": None,
        "bindings": {},
        "identity_action": "block",
        "control_authorized": False,
        "transport_enabled": False,
    }
    with patch.object(welcome.os, "open", side_effect=AssertionError("projection wrote/opened directly")):
        value, _ = snapshot(admission=admission)
    assert value["recovery"]["status"] == "failed"
    assert value["recovery"]["message_code"] == "recovery-required"
    assert value["host_identity"]["status"] == "unknown"
    assert value["headless_installation"]["status"] == "failed"
    assert value["capabilities"]["state_write"] is False


def test_unknown_boot_generation_does_not_invent_selected_runtime():
    value, _ = snapshot(generation_value=generation(booted=None))
    assert value["boot_generation"]["status"] == "unknown"
    assert value["boot_generation"]["booted_generation"] is None
    assert value["boot_generation"]["selected_matches_booted"] is None
    assert value["headless_installation"]["status"] == "unknown"


def test_network_controller_browser_and_graphics_are_not_observation_dependencies():
    value, _ = snapshot()
    assert value["observation_dependencies"] == {
        "state_required_for_socket_start": False,
        "network_required": False,
        "controller_required": False,
        "browser_required": False,
    }
    assert value["optional_applications"]["graphics_required_for_headless_success"] is False
    names = {row["name"] for row in FIXTURES["scenarios"]}
    assert {"unavailable-controller", "delayed-network", "no-browser"} <= names


def test_stale_or_prior_boot_response_is_rejected():
    value, _ = snapshot()
    nonce = "b" * 64
    response = {
        "schema": 1,
        "kind": "zog-host-welcome-readiness-response",
        "nonce": nonce,
        "ok": True,
        "snapshot": value,
    }
    observed = datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
    with patch.object(welcome, "boot_id", return_value=value["boot_id"]):
        assert welcome.validate_response(response, nonce, now=observed) == value
        with pytest.raises(StateError, match="welcome-stale"):
            welcome.validate_response(
                response, nonce,
                now=observed + timedelta(seconds=welcome.FRESH_SECONDS + 1),
            )
    with patch.object(welcome, "boot_id", return_value="22222222-2222-4222-8222-222222222222"):
        with pytest.raises(StateError, match="welcome-stale"):
            welcome.validate_response(response, nonce, now=observed)


def test_graphical_handoff_is_explicit_and_never_a_host_install_launch():
    base = {
        "schema": 1,
        "kind": "zog-graphical-handoff-evidence",
        "requested": False,
        "artifact": {"status": "missing", "software_id": None},
        "controller": {"status": "missing", "request_id": None},
        "session_security": {"status": "missing", "capability_id": None},
    }
    result = welcome.graphical_handoff(base)
    assert result["status"] == "not-requested"
    assert result["installation_success_depends_on_graphics"] is False
    assert result["host_install_authorizes_launch"] is False
    assert result["auto_start"] is False
    assert result["auto_reboot"] is False

    ready = copy.deepcopy(base)
    ready.update(requested=True)
    ready["artifact"] = {"status": "verified", "software_id": "view-firefox-1"}
    ready["controller"] = {"status": "authorized", "request_id": "request-1"}
    ready["session_security"] = {"status": "verified", "capability_id": "local-seat-1"}
    result = welcome.graphical_handoff(ready)
    assert result["status"] == "eligible"
    assert result["supervisor_request_eligible"] is True
    assert result["host_install_authorizes_launch"] is False
    assert result["auto_start"] is False
    assert result["auto_reboot"] is False

    for section, status in (
        ("artifact", "revoked"),
        ("controller", "unavailable"),
        ("session_security", "invalid"),
    ):
        candidate = copy.deepcopy(ready)
        candidate[section]["status"] = status
        candidate[section][next(k for k in candidate[section] if k != "status")] = None
        assert welcome.graphical_handoff(candidate)["status"] == "blocked"


def test_peer_boundary_rejects_other_uid_before_state_inspection():
    class Connection:
        def settimeout(self, _): pass

    with patch.object(welcome.os, "geteuid", return_value=0),          patch.object(welcome, "welcome_account", return_value=(1500, 1500)),          patch.object(welcome, "peer_uid", return_value=1501),          patch.object(welcome, "snapshot_live") as live:
        with pytest.raises(StateError, match="welcome-peer"):
            welcome.serve_connection(Connection())
    live.assert_not_called()


def test_fault_fixture_manifest_is_closed_and_complete():
    assert FIXTURES["schema"] == 1
    assert FIXTURES["kind"] == "zog-host-install-welcome-fixtures"
    names = [row["name"] for row in FIXTURES["scenarios"]]
    assert names == [
        "offline-reboot",
        "unavailable-controller",
        "malformed-state",
        "incomplete-install",
        "stale-identity-observation",
        "delayed-network",
        "no-browser",
        "foreground-console-login",
        "recovery-hold",
    ]
    assert all(row["persistent_writes_expected"] is False for row in FIXTURES["scenarios"])
