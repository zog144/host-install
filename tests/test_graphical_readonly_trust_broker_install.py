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
    assert b.ROOT_PROVIDER_SOURCE == "cb3d19febad0dbd0fa86094182b6c6f6e2a67cea"
    assert b.BROKER_SOURCE == "0ea6d583fa441527f45dabbbf542731560644a72"
    assert b.OWNER_SOURCE == "5ad7d5ed72d1b72edc767a658de28506791a74d4"
    assert b.ROOT_PROVIDER_SOURCE != "b0aea19bd265bbf1bdcf0b90eec18269e3276458"
    assert b.BROKER_SOURCE != "76416b9d7ef64aac17b75b6ce06b98244fd487e0"
