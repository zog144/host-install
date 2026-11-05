"""Exact disabled Task C read-only broker sources; never installed/cloud-authorized.

The authority, signed pins and RECORD digests below are *synthetic fixtures*.
A passing test must not claim real S3 GetObject IAM or gateway UID denial.
"""
import copy
from pathlib import Path
import sys

import pytest

from zog.host_install import graphical_readonly_trust_broker_install as b

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "companions/host-deploy"
ORIGIN = ROOT / "companions/root-control"

sys.path.insert(0, str(HOST / "tests"))
from test_graphics_owner_trust_install import candidate


def _unit(name):
    return (ROOT / "src/zog/host_install/systemd" / name).read_bytes()


def fixture():
    gateway, sources, _, _, original = candidate()
    gateway["gateway_source_revision"] = b.BROKER_SOURCE
    service, sock = _unit(b.SERVICE), _unit(b.SOCKET)
    gateway["service_sha256"] = b.sha(service)
    gateway["socket_sha256"] = b.sha(sock)
    gateway["runtime_python"] = b.BROKER_PYTHON
    root_source = (ORIGIN / "src/zog/root_control"
                   / "graphical_task_c_trust_authority.py").read_bytes()
    selection = {
        "schema": b.SCHEMA,
        "original_owner_source": b.OWNER_SOURCE,
        "root_provider_source": b.ROOT_PROVIDER_SOURCE,
        "broker_source": b.BROKER_SOURCE,
        "original_checkpoint_sha256": gateway["original_checkpoint_sha256"],
        "approved_pin_sha256": "sha256:" + "1"*64,
        "broker_purpose_approval_sha256": "sha256:" + "2"*64,
        "root_provider_module_sha256": b.sha(root_source),
        "broker_source_module_sha256": gateway["source_modules_sha256"],
        "broker_service_sha256": gateway["service_sha256"],
        "broker_socket_sha256": gateway["socket_sha256"],
        "broker_wheel_record_sha256": "sha256:" + "3"*64,
        "root_wheel_record_sha256": "sha256:" + "4"*64,
        "original_anchor_path": b.ORIGINAL_ANCHOR,
        "broker_purpose_approval_path": b.APPROVED_PIN,
        "gateway_public_pin_path": b.GATEWAY_PUBLIC_PIN,
        "broker_signer_source": b.SIGNER_SOURCE,
        "broker_signer_target": b.SIGNER_TARGET,
        "readonly_session_source": b.READ_SOURCE,
        "readonly_session_target": b.READ_TARGET,
        "broker_python": b.BROKER_PYTHON,
        "readonly_role_arn": gateway["readonly_checkpoint_role_arn"],
        "writer_role_arn": gateway["owner_checkpoint_write_role_arn"],
        "ssm_role_arn": gateway["owner_ssm_role_arn"],
        "state": "NOT_INSTALLED", "socket_enabled": False,
        "service_enabled": False, "broker_admitted": False,
        "gateway_credentials_denied": False,
        "installed_record_accepted": False,
    }
    return selection, root_source, sources, service, sock, original, gateway


def verify(inputs):
    selected, root, sources, service, sock, original, gateway = inputs
    return b.review_disabled_source(
        selected, root_module=root, broker_modules=sources,
        service=service, socket_unit=sock, original_record=original,
        broker_manifest=gateway,
    )


def test_selected_root_provider_and_broker_are_disabled_and_exact():
    items = fixture()
    result = verify(items)
    assert result["status"] == "SOURCE_REVIEW_ONLY"
    assert set(result.values()) == {"SOURCE_REVIEW_ONLY", False}
    assert items[0]["root_provider_source"] == b.ROOT_PROVIDER_SOURCE
    assert items[0]["broker_source"] == b.BROKER_SOURCE
    assert b.BROKER_PYTHON != "/usr/bin/python3"
    assert b.READ_SOURCE != b.SIGNER_SOURCE


@pytest.mark.parametrize("field,wrong", (
    ("root_provider_source", "0"*40),
    ("original_owner_source", "0"*40),
    ("broker_source", "0"*40),
    ("approved_pin_sha256", "NOT_A_PIN"),
    ("broker_purpose_approval_sha256", "sha256:"+"q"*64),
    ("root_provider_module_sha256", "sha256:"+"0"*64),
    ("broker_wheel_record_sha256", "missing"),
    ("original_anchor_path", "/state/fake-anchor"),
    ("broker_purpose_approval_path", "/state/fake-grant.json"),
    ("readonly_session_source", "/state/gateway-access-key.json"),
    ("broker_signer_source", "/home/gateway/private.key"),
    ("broker_python", "/usr/bin/python3"),
    ("state", "ACTIVATED"),
    ("socket_enabled", True),
    ("service_enabled", True),
    ("broker_admitted", True),
    ("gateway_credentials_denied", True),
    ("installed_record_accepted", True),
))
def test_changed_source_pin_signer_credential_or_claim_holds(field, wrong):
    rows = list(fixture())
    rows[0][field] = wrong
    with pytest.raises(b.BrokerInstallHeld):
        verify(rows)


@pytest.mark.parametrize("case", (
    "provider", "broker", "service", "socket", "exec",
    "multiple_exec", "extra_cred", "remove_cred", "writable",
    "auto_enable", "wrong_original", "wrong_role", "same_role",
    "different_account", "legacy_python", "replace_gateway_source",
))
def test_source_substitution_original_replacement_and_role_alias_denied(case):
    rows = list(fixture())
    s, root, modules, service, sock, record, gate = rows
    if case == "provider":
        rows[1] = root + b"\n"
    elif case == "broker":
        key = next(iter(modules))
        modules[key] += b"\n"
    elif case == "service":
        rows[3] = service + b"\nNoNewPrivileges=no"
    elif case == "socket":
        rows[4] = sock + b"\nListenStream=/tmp/untrusted.sock"
    elif case == "exec":
        rows[3] = service.replace(b"zog.host_deploy.gateway.graphics_owner_trust_daemon",
                                  b"zog.root_control.graphical_owner_service")
    elif case == "multiple_exec":
        rows[3] = service + b"\nExecStart=/usr/bin/python3 /tmp/sender"
    elif case == "extra_cred":
        rows[3] = service + b"\nLoadCredential=writer:/state/writer"
    elif case == "remove_cred":
        rows[3] = service.replace(b"LoadCredential=read-only-checkpoint.json:",
                                  b"#LoadCredential=read-only-checkpoint.json:")
    elif case == "writable":
        rows[3] = service + b"\nReadWritePaths=/state"
    elif case == "auto_enable":
        rows[3] = service + b"\n[Install]\nWantedBy=multi-user.target"
    elif case == "wrong_original":
        record["checkpoint_prefix"] = "fresh-rollback/"
    elif case == "wrong_role":
        s["readonly_role_arn"] = (
            "arn:aws:iam::123456789012:role/ChangedReadOnlyRole")
    elif case == "same_role":
        s["readonly_role_arn"] = s["writer_role_arn"]
    elif case == "different_account":
        s["readonly_role_arn"] = (
            "arn:aws:iam::999999999999:role/OriginalGetObjectOnly")
    elif case == "legacy_python":
        gate["runtime_python"] = "/usr/bin/python3"
    elif case == "replace_gateway_source":
        gate["gateway_source_revision"] = "0"*40
    with pytest.raises(b.BrokerInstallHeld):
        verify(rows)


def test_exact_three_owner_constructor_revision_set():
    assert b.ROOT_PROVIDER_SOURCE == "c603eee47e8e43ed0e1b46052337a35ce9836e7c"
    assert b.BROKER_SOURCE == "0ea6d583fa441527f45dabbbf542731560644a72"
    assert b.OWNER_SOURCE == "5ad7d5ed72d1b72edc767a658de28506791a74d4"
    assert b.ROOT_PROVIDER_SOURCE != "b0aea19bd265bbf1bdcf0b90eec18269e3276458"
    assert b.BROKER_SOURCE != "76416b9d7ef64aac17b75b6ce06b98244fd487e0"

def test_new_root40_constructor_is_exact_only_in_synthetic_source_seam(monkeypatch):
    from zog.root_control import graphical_task_c_trust_authority as provider
    from zog.host_deploy.gateway import graphics_owner_trust_daemon as daemon
    from zog.host_deploy.gateway import graphics_owner_trust_history as history

    assert provider.BROKER_SOURCE == b.BROKER_SOURCE
    assert provider.OWNER_SOURCE == b.OWNER_SOURCE
    assert daemon.NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED is False
    assert history.APPROVED_PIN_SHA256 is None

    with pytest.raises(history.TrustUnavailable):
        daemon.installed_runtime()

    chosen = daemon.InstalledReadOnlyAuthority(
        registry=object(), issuer_evidence={}, issuer_public_key=b"a"*32,
        observation_public_key=b"b"*32, checkpoint=object(), signed_pin={},
        broker_signer=object(), installed_source_sha256="c"*64,
        original_checkpoint={}, gateway_uid=15310, gateway_gid=15311,
        gateway_executable_sha256="sha256:"+"d"*64,
        gateway_cgroup="/system.slice/zog-graphical-gateway.service")
    calls=[]
    monkeypatch.setattr(provider, "installed_readonly_authority",
                        lambda: calls.append("exact-root40") or chosen)
    # This explicit monkeypatch verifies the code seam, not native activation.
    monkeypatch.setattr(daemon, "NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED", True)
    assert daemon.installed_runtime() is chosen
    assert calls == ["exact-root40"]
    assert history.APPROVED_PIN_SHA256 is None


def test_exact_host_deploy_constructor_delegates_only_to_pinned_root_authority(monkeypatch):
    """Interop against the actual selected PR26 daemon and PR40 provider.

    A synthetic source seam proves the delegation and strict returned type;
    it does not bypass native gating or establish genuine AWS authority.
    """
    from zog.host_deploy.gateway import graphics_owner_trust_daemon as daemon
    from zog.host_deploy.gateway import graphics_owner_trust_history as history
    from zog.root_control import graphical_task_c_trust_authority as root

    assert root.BROKER_SOURCE == b.BROKER_SOURCE
    assert root.OWNER_SOURCE == b.OWNER_SOURCE
    assert daemon.NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED is False
    assert history.APPROVED_PIN_SHA256 is None

    events = []
    monkeypatch.setattr(
        root, "installed_readonly_authority",
        lambda: events.append("protected-provider") or pytest.fail(
            "hard-disabled broker invoked protected authority"))
    with pytest.raises(history.TrustUnavailable):
        daemon.installed_runtime()
    assert events == []

    selected = daemon.InstalledReadOnlyAuthority(
        registry=object(), issuer_evidence={},
        issuer_public_key=b"a" * 32,
        observation_public_key=b"b" * 32,
        checkpoint=object(), signed_pin={}, broker_signer=object(),
        installed_source_sha256="sha256:" + "c" * 64,
        original_checkpoint={}, gateway_uid=15310, gateway_gid=15311,
        gateway_executable_sha256="sha256:" + "d" * 64,
        gateway_cgroup="/system.slice/zog-graphical-gateway.service",
    )
    monkeypatch.setattr(root, "installed_readonly_authority",
                        lambda: events.append("protected-provider") or selected)
    monkeypatch.setattr(daemon, "NATIVE_TRUST_BROKER_ADMISSION_IMPLEMENTED", True)
    assert daemon.installed_runtime() is selected
    assert events == ["protected-provider"]

    monkeypatch.setattr(root, "installed_readonly_authority", lambda: {})
    with pytest.raises(history.TrustUnavailable):
        daemon.installed_runtime()
    assert history.APPROVED_PIN_SHA256 is None


def test_mount_readiness_dependencies_are_effective_systemd_unit_properties():
    service = _unit(b.SERVICE)
    assert service.count(b"RequiresMountsFor=") == 2
    unit, service_section = service.split(b"[Service]\\n", 1)
    assert b"[Unit]\\n" in unit
    for mount in (b.ORIGINAL_LEDGER.encode(), b.ROOT_AUTHORITY.encode()):
        directive = b"RequiresMountsFor=" + mount
        assert unit.count(directive + b"\\n") == 1
        assert directive not in service_section
    selected = fixture()
    assert selected[0]["broker_service_sha256"] == b.sha(service)
    assert selected[6]["service_sha256"] == b.sha(service)
    assert verify(selected)["service_activation_accepted"] is False


@pytest.mark.parametrize("mutation", (
    "both_in_service", "ledger_in_service", "authority_in_service",
    "duplicate_in_service", "duplicate_in_unit", "missing_ledger",
    "missing_authority", "wrong_section", "old_unit_manifest_hash",
))
def test_mount_readiness_never_admits_ignored_or_unreviewed_dependencies(mutation):
    selected = list(fixture())
    selection, root, modules, unit, sock, original, gateway = selected
    ledger = b"RequiresMountsFor=" + b.ORIGINAL_LEDGER.encode() + b"\\n"
    authority = b"RequiresMountsFor=" + b.ROOT_AUTHORITY.encode() + b"\\n"
    if mutation == "both_in_service":
        unit = unit.replace(ledger, b"").replace(authority, b"")
        unit = unit.replace(b"[Service]\\n", b"[Service]\\n" + ledger + authority)
    elif mutation == "ledger_in_service":
        unit = unit.replace(ledger, b"").replace(b"[Service]\\n", b"[Service]\\n" + ledger)
    elif mutation == "authority_in_service":
        unit = unit.replace(authority, b"").replace(b"[Service]\\n", b"[Service]\\n" + authority)
    elif mutation == "duplicate_in_service":
        unit = unit.replace(b"[Service]\\n", b"[Service]\\n" + ledger)
    elif mutation == "duplicate_in_unit":
        unit = unit.replace(ledger, ledger + ledger)
    elif mutation == "missing_ledger":
        unit = unit.replace(ledger, b"")
    elif mutation == "missing_authority":
        unit = unit.replace(authority, b"")
    elif mutation == "wrong_section":
        unit = unit.replace(b"[Unit]\\n", b"[Service]\\n", 1)
    elif mutation == "old_unit_manifest_hash":
        # Even equal-value, wrong-section old bytes must not be accepted.
        old = unit.replace(ledger, b"").replace(authority, b"")
        old = old.replace(b"[Service]\\n", b"[Service]\\n" + ledger + authority)
        selection["broker_service_sha256"] = b.sha(old)
        gateway["service_sha256"] = b.sha(old)
    if mutation != "old_unit_manifest_hash":
        selection["broker_service_sha256"] = b.sha(unit)
        gateway["service_sha256"] = b.sha(unit)
    selected[3] = unit
    with pytest.raises(b.BrokerInstallHeld):
        verify(selected)
