import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from zog.host_install import certificate_native_observation as native
from zog.host_install import certificate_owner_authority as owner_authority
from zog.host_install.certificate_lifecycle import reconcile
from zog.host_install.state_contract import StateError


def previous_record():
    observation = {
        "schema": 1,
        "kind": "zog-certificate-lifecycle-observation",
        "event": "install",
        "application": {
            "status": "available",
            "persistent_state_id": "a" * 32,
            "preparation_revision": "certify-manage-state-v1",
        },
        "evidence": {
            "schema": 1,
            "kind": "zog-certificate-enablement-evidence",
            "state": {"verified": True, "recovery_hold": False},
            "grant": {"status": "verified", "grant_id": "b" * 32},
            "software": {"status": "verified", "generation": "c" * 64},
            "policy": {
                "status": "approved",
                "hostname_approved": True,
                "challenge_approved": True,
                "challenge": "dns-01",
            },
            "persistent": {
                "status": "available",
                "existing_acme_identity": True,
                "lineage_status": "healthy",
                "replacement_attempted": False,
            },
            "preparation": {"status": "complete"},
            "issuance": {"status": "issued", "local_verified": True},
            "publication": {"status": "not-started"},
            "external": {"status": "not-verified"},
        },
    }
    return reconcile(None, observation)["record"]


def prepared():
    return {
        "storage_id": "a" * 32,
        "grant_id": "b" * 32,
        "issuer_uid": 29001,
        "issuer_gid": 29002,
        "preparation_revision": "certify-manage-state-v1",
        "preparation_attempt_id": "d" * 32,
        "generation": "c" * 64,
        "certificate_data_path": "/project/state/mounts/persistent/" + "a" * 32 + "/certificate-data",
        "certificate_data_mode": "0700",
        "steps": [{
            "program": "prepare",
            "runtime_id": "runtime-1",
            "unit_name": "unit.service",
            "boot_id": "1" * 32,
            "invocation_id": "2" * 32,
            "outcome": "success",
        }],
    }


def policy():
    return {
        "host_policy_digest": "sha256:" + "e" * 64,
        "policy_sha256": "f" * 64,
        "certificate_id": "station",
        "challenge": "dns-01",
        "hostnames_count": 1,
        "hostnames_sha256": "1" * 64,
    }


def inspection():
    return {
        "status": "verified",
        "request_id": "3" * 32,
        "runtime_id": "runtime-2",
        "boot_id": "4" * 32,
        "invocation_id": "5" * 32,
        "storage_id": "a" * 32,
        "grant_id": "b" * 32,
        "issuer_uid": 29001,
        "issuer_gid": 29002,
        "host_policy_digest": "sha256:" + "e" * 64,
        "policy_sha256": "f" * 64,
        "health": "valid",
        "certificate_fingerprint_sha256": "6" * 64,
        "operation": "renew",
        "outcome": "renewed",
        "issuer_verified": True,
        "observed_at": "2026-10-20T20:00:00+00:00",
        "tls_ready": False,
        "hostnames_count": 1,
        "hostnames_sha256": "1" * 64,
    }


def test_prior_identity_requires_fresh_selected_inspection_after_reboot():
    previous = previous_record()
    observation = native._lifecycle_observation(
        event="reboot",
        state_ok=True,
        recovery_hold=False,
        software_ok=True,
        generation="c" * 64,
        policy=policy(),
        policy_error=None,
        prepared=prepared(),
        preparation_error=None,
        inspection=None,
        previous=previous,
    )
    persistent = observation["evidence"]["persistent"]
    assert persistent["status"] == "uncertain"
    assert persistent["existing_acme_identity"] is True
    assert persistent["lineage_status"] == "uncertain"
    assert observation["evidence"]["issuance"] == {
        "status": "uncertain", "local_verified": False
    }
    result = reconcile(previous, observation)
    assert result["status"]["code"] == "persistent-state-uncertain"
    assert result["status"]["issuance_allowed"] is False


def test_verified_selected_inspection_reestablishes_account_and_lineage_evidence():
    previous = previous_record()
    observation = native._lifecycle_observation(
        event="reboot",
        state_ok=True,
        recovery_hold=False,
        software_ok=True,
        generation="c" * 64,
        policy=policy(),
        policy_error=None,
        prepared=prepared(),
        preparation_error=None,
        inspection=inspection(),
        previous=previous,
    )
    persistent = observation["evidence"]["persistent"]
    assert persistent == {
        "status": "available",
        "existing_acme_identity": True,
        "lineage_status": "healthy",
        "replacement_attempted": False,
    }
    assert observation["evidence"]["issuance"] == {
        "status": "issued", "local_verified": True
    }


def test_exact_selected_commands_never_use_host_python_or_host_certbot():
    for name in ("prepare", "issue", "renew", "inspect", "stage"):
        command = native._expected_command(name)
        assert command == (
            "/applications/certify-manage/bin/python3",
            "-m",
            "zog.certify_manage",
            name,
            "--state",
            "/var/lib/zog-certify-manage",
            "--policy",
            "/run/zog-host/certify-policy/policy.json",
        )
        assert "/usr/bin/certbot" not in command


class FakeContext:
    def __init__(self):
        self.bundle = {
            "bootstrap": {
                "installation_id": "11111111-1111-4111-8111-111111111111",
                "state": {
                    "state_volume_id": "22222222-2222-4222-8222-222222222222"
                },
            }
        }
    def recheck(self): return None
    def close(self): return None


def test_native_observer_does_not_promote_missing_owner_binding(tmp_path, monkeypatch):
    ctx = FakeContext()
    monkeypatch.setattr(native, "inspect_live", lambda: ctx)
    monkeypatch.setattr(native, "observe_state_admission", lambda context: {
        "recovery_hold": False,
        "bindings": {
            "boot_id": "33333333-3333-4333-8333-333333333333",
            "bootstrap_sha256": "7" * 64,
            "marker_sha256": "8" * 64,
        },
    })
    monkeypatch.setattr(native, "_installed_host_discover", lambda **kwargs: {
        "source_commit": native.HOST_DISCOVER_COMMIT,
    })
    monkeypatch.setattr(native, "_authority", lambda context: {
        "status": "approved",
        "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": "44444444-4444-4444-8444-444444444444",
        "installation_id": ctx.bundle["bootstrap"]["installation_id"],
        "state_volume_id": ctx.bundle["bootstrap"]["state"]["state_volume_id"],
        "registry_id": "primary",
        "authority_key_id": "9" * 64,
        "revision": 4,
        "operation_id": "55555555-5555-4555-8555-555555555555",
        "assignment_sha256": "a" * 64,
        "consumer": "host-nginx-https",
        "certificate_id": "station",
        "challenge": "dns-01",
        "hostnames_count": 1,
        "hostnames_sha256": "b" * 64,
        "expires_at": 2_000_000_000,
    })
    monkeypatch.setattr(native, "_project_owner", lambda *args: {
        "uid": 11021, "gid": 11022, "account": "controller",
        "root_control_socket": "/run/zog/root-control.sock",
    })
    monkeypatch.setattr(native, "attest_installed_controller", lambda **kwargs: {
        "box_control_source_commit": "a3e939b7",
        "root_control_source_commit": "3a2dd9c9",
    })
    binding = {
        "view": "sha256:" + "d" * 64,
        "binding_digest": "sha256:" + "e" * 64,
        "view_manifest_digest": "sha256:" + "f" * 64,
        "reclamation_protection": {"artifacts": ["sha256:" + "1" * 64]},
        "mount_point": "/applications/certify-manage",
    }
    monkeypatch.setattr(
        native,
        "_software_and_preparation",
        lambda *args: (
            SimpleNamespace(),
            SimpleNamespace(generation="c" * 64),
            binding,
            {"state": "ready"},
        ),
    )
    monkeypatch.setattr(native, "_policy", lambda project: policy())
    monkeypatch.setattr(native, "_prepared", lambda *args: prepared())
    monkeypatch.setattr(native, "_inspect_selected", lambda *args: inspection())
    monkeypatch.setattr(
        owner_authority,
        "inspect_live_owner",
        lambda: (_ for _ in ()).throw(
            StateError("certificate-owner-unavailable", "missing")
        ),
    )
    monkeypatch.setattr(native.os, "geteuid", lambda: 0)
    monkeypatch.setattr(native.sys, "executable", "/usr/bin/python3")

    import zog.box_control.project as project_mod
    import zog.box_control.runtime.root_control as root_mod

    class FakeProject:
        def __init__(self, path):
            self.path = Path(path)
    class FakeTransport:
        def __init__(self, path):
            self.path = path
    monkeypatch.setattr(project_mod, "Project", FakeProject)
    monkeypatch.setattr(root_mod, "RootControlSystemdTransport", FakeTransport)

    record = tmp_path / "lifecycle.json"
    result = native.observe_live(
        controller_project="/home/controller/project",
        root_control_socket="/run/zog/root-control.sock",
        generation="c" * 64,
        software_view="sha256:" + "d" * 64,
        lifecycle_record=record,
        event="status",
        inspect_request_id="3" * 32,
    )
    assert result["status"] == "PASS"
    assert result["managed_authority_ready"] is True
    assert result["host_deploy_native_gate_handoff_ready"] is False
    assert result["host_deploy_blocker"] == (
        "host-install-owner-or-selected-inspection-incomplete"
    )
    owner = result["matrix"]["host_deploy_owner_policy_binding"]
    assert owner["status"] == "NOT RUN"
    assert owner["code"] == "certificate-owner-unavailable"
    assert owner["evidence"] == {
        "root_assignment_sha256": "a" * 64,
        "local_policy_sha256": "f" * 64,
    }
    assert json.loads(record.read_text())["kind"] == (
        "zog-certificate-lifecycle-record"
    )


def test_native_observer_handoff_ready_only_with_owner_ledger_and_selected_inspection(
    tmp_path, monkeypatch
):
    ctx = FakeContext()
    authority = {
        "status": "approved",
        "origin": "managed",
        "verified_by": "signed-host-discover",
        "host_id": "44444444-4444-4444-8444-444444444444",
        "installation_id": ctx.bundle["bootstrap"]["installation_id"],
        "state_volume_id": ctx.bundle["bootstrap"]["state"]["state_volume_id"],
        "registry_id": "primary",
        "authority_key_id": "9" * 64,
        "revision": 4,
        "operation_id": "55555555-5555-4555-8555-555555555555",
        "assignment_sha256": "a" * 64,
        "consumer": "host-nginx-https",
        "certificate_id": "station",
        "challenge": "dns-01",
        "hostnames_count": 1,
        "hostnames_sha256": "b" * 64,
        "expires_at": 2_000_000_000,
    }
    monkeypatch.setattr(native, "inspect_live", lambda: ctx)
    monkeypatch.setattr(native, "observe_state_admission", lambda context: {
        "recovery_hold": False,
        "bindings": {
            "boot_id": "33333333-3333-4333-8333-333333333333",
            "bootstrap_sha256": "7" * 64,
            "marker_sha256": "8" * 64,
        },
    })
    monkeypatch.setattr(
        native, "_installed_host_discover",
        lambda **kwargs: {"source_commit": native.HOST_DISCOVER_COMMIT},
    )
    monkeypatch.setattr(native, "_authority", lambda context: authority)
    monkeypatch.setattr(native, "_project_owner", lambda *args: {
        "uid": 11021,
        "gid": 11022,
        "account": "controller",
        "root_control_socket": "/run/zog/root-control.sock",
    })
    monkeypatch.setattr(
        native, "attest_installed_controller",
        lambda **kwargs: {
            "box_control_source_commit": "a3e939b7",
            "root_control_source_commit": "3a2dd9c9",
        },
    )
    software_binding = {
        "view": "sha256:" + "d" * 64,
        "binding_digest": "sha256:" + "e" * 64,
        "view_manifest_digest": "sha256:" + "f" * 64,
        "reclamation_protection": {"artifacts": ["sha256:" + "1" * 64]},
        "mount_point": "/applications/certify-manage",
    }
    monkeypatch.setattr(
        native,
        "_software_and_preparation",
        lambda *args: (
            SimpleNamespace(),
            SimpleNamespace(generation="c" * 64),
            software_binding,
            {"state": "ready"},
        ),
    )
    monkeypatch.setattr(native, "_policy", lambda project: policy())
    monkeypatch.setattr(native, "_prepared", lambda *args: prepared())
    monkeypatch.setattr(native, "_inspect_selected", lambda *args: inspection())
    monkeypatch.setattr(native.os, "geteuid", lambda: 0)
    monkeypatch.setattr(native.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(owner_authority, "inspect_live_owner", lambda: {
        "schema": "zog-host-install-certificate-owner-inspection-v1",
        "status": "retained",
        "installation_id": ctx.bundle["bootstrap"]["installation_id"],
        "state_volume_id": ctx.bundle["bootstrap"]["state"]["state_volume_id"],
        "registry_id": "primary",
        "authority_key_id": "9" * 64,
        "service_id": "candidate-nginx",
        "certificate_id": "station",
        "revision": 4,
        "operation_id": authority["operation_id"],
        "assignment_sha256": authority["assignment_sha256"],
        "status_authority": "approved",
        "binding_path": owner_authority.BINDING_PATH,
        "binding_sha256": "c" * 64,
        "owner_authority_path": owner_authority.OWNER_PATH,
        "owner_authority_sha256": "d" * 64,
        "delivery_policy_sha256": "e" * 64,
        "local_intent_sha256": "f" * 64,
        "issuer": {
            "storage_id": prepared()["storage_id"],
            "grant_id": prepared()["grant_id"],
            "uid": prepared()["issuer_uid"],
            "gid": prepared()["issuer_gid"],
            "software_view": "sha256:" + "d" * 64,
            "certificate_data_path": prepared()["certificate_data_path"],
            "controller_record_sha256": "1" * 64,
        },
        "pending_transaction": None,
        "production_activation_authorized": False,
    })

    import zog.box_control.project as project_mod
    import zog.box_control.runtime.root_control as root_mod

    class FakeProject:
        def __init__(self, path):
            self.path = Path(path)

    class FakeTransport:
        def __init__(self, path):
            self.path = path

    monkeypatch.setattr(project_mod, "Project", FakeProject)
    monkeypatch.setattr(root_mod, "RootControlSystemdTransport", FakeTransport)

    result = native.observe_live(
        controller_project="/home/controller/project",
        root_control_socket="/run/zog/root-control.sock",
        generation="c" * 64,
        software_view="sha256:" + "d" * 64,
        lifecycle_record=tmp_path / "lifecycle-owner-ready.json",
        event="status",
        inspect_request_id="3" * 32,
    )
    assert result["status"] == "PASS"
    assert result["managed_authority_ready"] is True
    assert result["matrix"]["host_deploy_owner_policy_binding"]["status"] == "PASS"
    assert result["host_deploy_native_gate_handoff_ready"] is True
    assert result["host_deploy_blocker"] is None
    assert result["production_activation_authorized"] is False
    assert result["live_acme_authorized"] is False
    assert result["nginx_reload_authorized"] is False


def test_missing_root_authority_does_not_fall_back_to_uid970(tmp_path, monkeypatch):
    ctx = FakeContext()
    monkeypatch.setattr(native, "inspect_live", lambda: ctx)
    monkeypatch.setattr(native, "observe_state_admission", lambda context: {
        "recovery_hold": False,
        "bindings": {
            "boot_id": "33333333-3333-4333-8333-333333333333",
            "bootstrap_sha256": "7" * 64,
            "marker_sha256": "8" * 64,
        },
    })
    monkeypatch.setattr(native, "_installed_host_discover", lambda **kwargs: {})
    monkeypatch.setattr(
        native, "_authority",
        lambda context: (_ for _ in ()).throw(
            StateError("certificate-authority-unavailable", "missing")
        ),
    )
    monkeypatch.setattr(native, "_project_owner", lambda *args: {
        "uid": 11021, "gid": 11022, "account": "controller",
        "root_control_socket": "/run/zog/root-control.sock",
    })
    monkeypatch.setattr(native, "attest_installed_controller", lambda **kwargs: {})
    monkeypatch.setattr(native, "_software_and_preparation", lambda *args: (
        SimpleNamespace(),
        SimpleNamespace(generation="c" * 64),
        {
            "view": "sha256:" + "d" * 64,
            "binding_digest": "sha256:" + "e" * 64,
            "view_manifest_digest": "sha256:" + "f" * 64,
            "reclamation_protection": {"artifacts": []},
            "mount_point": "/applications/certify-manage",
        },
        None,
    ))
    monkeypatch.setattr(native, "_policy", lambda project: None)
    monkeypatch.setattr(native.os, "geteuid", lambda: 0)
    monkeypatch.setattr(native.sys, "executable", "/usr/bin/python3")

    import zog.box_control.project as project_mod
    import zog.box_control.runtime.root_control as root_mod
    monkeypatch.setattr(
        project_mod, "Project",
        type("FakeProject", (), {"__init__": lambda self, path: setattr(self, "path", Path(path))})
    )
    monkeypatch.setattr(
        root_mod, "RootControlSystemdTransport",
        type("FakeTransport", (), {"__init__": lambda self, path: setattr(self, "path", path)})
    )
    result = native.observe_live(
        controller_project="/home/controller/project",
        root_control_socket="/run/zog/root-control.sock",
        generation="c" * 64,
        software_view="sha256:" + "d" * 64,
        lifecycle_record=tmp_path / "lifecycle.json",
    )
    assert result["matrix"]["managed_hostname_authority"]["status"] == "BLOCKED"
    assert result["matrix"]["managed_hostname_authority"]["code"] == (
        "certificate-authority-unavailable"
    )
    assert result["managed_authority_ready"] is False
    assert result["host_deploy_native_gate_handoff_ready"] is False


def test_unverified_state_never_adopts_controller_identity_into_lifecycle_record():
    observation = native._lifecycle_observation(
        event="status",
        state_ok=False,
        recovery_hold=True,
        software_ok=True,
        generation="c" * 64,
        policy=policy(),
        policy_error=None,
        prepared=prepared(),
        preparation_error=None,
        inspection=inspection(),
        previous=None,
    )
    assert observation["application"]["status"] == "invalid"
    assert observation["application"]["persistent_state_id"] is None
    assert observation["evidence"]["grant"]["status"] == "invalid"
    assert observation["evidence"]["grant"]["grant_id"] is None
    assert observation["evidence"]["software"] == {
        "status": "invalid", "generation": None
    }
    result = reconcile(None, observation)
    assert result["record"]["persistent_state_id"] is None
    assert result["record"]["first_software_generation"] is None
    assert result["status"]["code"] == "state-unverified"
