"""Source-only Task C S3 owner installation successor checks.

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.
Every address, role and SHA below is a synthetic fixture, not an installed
credential, authority pin, rootfs manifest, AWS role or accepted Host.
"""
import copy
from pathlib import Path

import pytest
from zog.host_install import graphical_native_owner_install as c

ROOT = Path(__file__).resolve().parents[1]


def row():
    return {
        "schema": c.SCHEMA,
        "root_source_revision": c.SELECTED_ROOT_SHA,
        "root_modules": list(c.ROOT_MODULES),
        "host_id": "a"*64, "installation_id": "b"*64,
        "state_volume_id": "c"*64, "boot_id": "not-a-verified-boot",
        "owner_identity": "root-owner-only",
        "gateway_identity": "unprivileged-gateway",
        "gateway_uid": 1200, "gateway_gid": 1210,
        "gateway_cgroup": "/system.slice/zog-host-deploy.service",
        "gateway_executable_sha256": "sha256:"+"1"*64,
        "root_uid": 0, "socket": c.SOCKET,
        "socket_mode": "0660", "socket_group": "zog-graphical-client",
        "ledger": c.LEDGER, "checkpoint": c.CHECKPOINT,
        "gateway_state_mount": "/state",
        "owner_config": c.OWNER_CONFIG, "operator_pin": c.OPERATOR_PIN,
        "origin_issuer_pin": c.ORIGIN_ISSUER_PIN,
        "origin_evidence": c.ORIGIN_EVIDENCE,
        "observation_private": c.OBSERVATION_PRIVATE,
        "credential_source": c.CREDS, "credential_target": c.CRED_MOUNT,
        "checkpoint_credential_source": c.CHECKPOINT_CREDS,
        "checkpoint_credential_target": c.CHECKPOINT_CRED_MOUNT,
        "checkpoint_policy": {
            "bucket": "fixture-owner-bucket",
            "prefix": "fixture/original/",
            "account_id": "123456789012",
            "region": "us-east-1",
            "genesis_sha256": "sha256:"+"2"*64,
            "role_arn": "arn:aws:iam::123456789012:role/FixtureCheckpointRole"},
        "ssm_policy": {
            "account_id": "123456789012", "region": "us-east-1",
            "instance_id": "i-0123456789abcdef0",
            "role_arn": "arn:aws:iam::123456789012:role/FixtureSsmSenderRole"},
        "operator_public_sha256": "sha256:"+"3"*64,
        "origin_issuer_public_sha256": "sha256:"+"4"*64,
        "origin_evidence_sha256": "sha256:"+"5"*64,
        "observation_public_sha256": "sha256:"+"6"*64,
        "separate_mounts_verified": False,
        "source_record_verified": False,
        "original_github_verified": False,
        "operator_identity_approved": False,
        "gateway_iam_explicit_deny_verified": False,
        "gateway_imds_and_sts_denial_verified": False,
        "owner_aws_session_separate_verified": False,
        "nonrollbackable_highwater_verified": False,
        "checkpoint_iam_verified": False,
        "status": "NOT_ACTIVATED", "socket_enabled": False,
        "service_enabled": False, "ssm_admitted": False,
    }


def units():
    root = ROOT / "src/zog/host_install/systemd"
    return {
        c.SERVICE: (root / c.SERVICE).read_text(),
        c.SOCKET_UNIT: (root / c.SOCKET_UNIT).read_text(),
    }


def evidence(**overrides):
    native = {
        "gateway_principal": "synthetic-gateway",
        "checkpoint_principal": "synthetic-checkpoint",
        "ssm_principal": "synthetic-ssm",
        "gateway_send_denied": False,
        "gateway_checkpoint_denied": False,
        "owner_only_session": False,
    }
    native.update(overrides)
    return c.inspect_installed_evidence(
        manifest=row(),
        installed_root_sha256={m:"b"*64 for m in c.ROOT_MODULES},
        units=units(),
        mount_identities={"gateway":"fake-state","ledger":"fake-ledger"},
        aws_identity=native)


def test_disabled_exact_source_manifest_only():
    assert c.SELECTED_ROOT_SHA == "5ad7d5ed72d1b72edc767a658de28506791a74d4"
    assert c.validate_install_contract(row())["status"] == "NOT_ACTIVATED"
    status = evidence()
    assert status["enabled"] is False
    assert status["external_highwater_accepted"] is False
    assert status["aws_send_admitted"] is False
    assert len(c.ROOT_MODULES) >= 9
    assert "zog.root_control.graphical_s3_checkpoint" in c.ROOT_MODULES
    assert "zog.root_control.graphical_task_c_origin" in c.ROOT_MODULES


@pytest.mark.parametrize("key,value", (
    ("root_uid", 1000), ("gateway_uid", 0), ("gateway_gid", 0),
    ("owner_identity", "unprivileged-gateway"),
    ("socket", "/tmp/attacker.sock"), ("socket_mode", "0666"),
    ("socket_group", "users"), ("ledger", "/state/gateway-ledger"),
    ("checkpoint", "/var/lib/zog-graphical-owner-checkpoint"),
    ("owner_config", "/state/untrusted-task-c.json"),
    ("operator_pin", "/home/gateway/pin"),
    ("origin_issuer_pin", "/state/issuer.pub"),
    ("origin_evidence", "/state/original-github-evidence.json"),
    ("observation_private", "/state/owner-private.key"),
    ("credential_source", "/home/gateway/.aws"),
    ("checkpoint_credential_source", "/state/owner-credential.json"),
    ("checkpoint_credential_target", "/tmp/owner-credential.json"),
    ("operator_public_sha256", "sha256:malformed"),
    ("gateway_cgroup", "/user.slice/untrusted.service"),
    ("status", "READY"), ("socket_enabled", True),
    ("service_enabled", True), ("ssm_admitted", True),
    ("original_github_verified", True),
    ("gateway_iam_explicit_deny_verified", True),
    ("gateway_imds_and_sts_denial_verified", True),
    ("nonrollbackable_highwater_verified", True),
    ("checkpoint_iam_verified", True),
    ("owner_aws_session_separate_verified", True),
    ("root_source_revision", "0"*40),
))
def test_gateway_or_untrusted_installer_cannot_expand_authority(key,value):
    test = row()
    test[key] = value
    with pytest.raises(c.InstallationHold):
        c.validate_install_contract(test)


@pytest.mark.parametrize("which", (
    "same_role", "wrong_s3_account", "wrong_ssm_instance", "bad_genesis",
    "wrong_region", "wrong_bucket", "wrong_role_account",
))
def test_exact_s3_checkpoint_and_separate_ssm_role_required(which):
    source = row()
    s3 = source["checkpoint_policy"]
    ssm = source["ssm_policy"]
    if which == "same_role":
        ssm["role_arn"] = s3["role_arn"]
    elif which == "wrong_s3_account":
        s3["account_id"] = "999999999999"
    elif which == "wrong_ssm_instance":
        ssm["instance_id"] = "i-invalid"
    elif which == "bad_genesis":
        s3["genesis_sha256"] = "sha256:missing"
    elif which == "wrong_region":
        ssm["region"] = "eu-west-1"
    elif which == "wrong_bucket":
        s3["bucket"] = "A/illegal"
    elif which == "wrong_role_account":
        ssm["role_arn"] = "arn:aws:iam::999999999999:role/FixtureSsmSenderRole"
    with pytest.raises(c.InstallationHold):
        c.validate_install_contract(source)


def test_task_c_one_stream_service_with_two_explicit_roles_no_local_checkpoint():
    unit = units()
    service = unit[c.SERVICE]
    socket = unit[c.SOCKET_UNIT]
    assert c.verify_unit_sources(service, socket).endswith("not-enabled")
    assert service.count("LoadCredential=") == 2
    assert "LoadCredential=checkpoint-session.json:"+c.CHECKPOINT_CREDS in service
    assert "LoadCredential=aws-session.json:"+c.CREDS in service
    assert "RequiresMountsFor="+c.LEDGER in service
    assert "/var/lib/zog-graphical-owner-checkpoint" not in service
    assert "ListenStream="+c.SOCKET in socket
    assert "ListenSequentialPacket=" not in socket
    assert "[Install]" not in service + socket
    for modified in (
        service.replace("User=root","User=host-deploy"),
        service.replace("LoadCredential=checkpoint-session.json:",
                        "# LoadCredential=checkpoint-session.json:"),
        service.replace("LoadCredential=aws-session.json:",
                        "# LoadCredential=aws-session.json:"),
        service.replace("ReadWritePaths=", "# ReadWritePaths="),
        service+"\nWantedBy=multi-user.target",
        service+"\nEnvironmentFile=/home/gateway/aws",
        service.replace("graphical_task_c_service","graphical_owner_service"),
        service+"\nLoadCredential=untrusted:/state/credentials.json",
    ):
        with pytest.raises(c.InstallationHold):
            c.verify_unit_sources(modified, socket)
    for modified in (
        socket.replace("SocketMode=0660", "SocketMode=0666"),
        socket.replace("ListenStream=", "ListenSequentialPacket="),
        socket+"\nWantedBy=sockets.target",
    ):
        with pytest.raises(c.InstallationHold):
            c.verify_unit_sources(service, modified)


def test_no_self_issued_aws_acceptance_or_equivalent_local_highwater():
    for change in (
        {"gateway_send_denied": True},
        {"gateway_checkpoint_denied": True},
        {"owner_only_session": True},
        {"checkpoint_principal": "synthetic-gateway"},
        {"ssm_principal": "synthetic-checkpoint"},
    ):
        with pytest.raises(c.InstallationHold):
            evidence(**change)
    with pytest.raises(c.InstallationHold):
        c.inspect_installed_evidence(
            manifest=row(),
            installed_root_sha256={m:"b"*64 for m in c.ROOT_MODULES},
            units=units(),
            mount_identities={"gateway":"same","ledger":"same"},
            aws_identity={
                "gateway_principal":"one","checkpoint_principal":"two",
                "ssm_principal":"three","gateway_send_denied":False,
                "gateway_checkpoint_denied":False,
                "owner_only_session":False,
            })


def test_selected_gateway_policy_must_deny_direct_ssm_and_escalation():
    policy = c.required_gateway_denial()
    assert c.verify_gateway_denial_policy(policy)["aws_iam_verified"] is False
    for action in ("ssm:SendCommand", "sts:AssumeRole", "iam:PassRole"):
        test = copy.deepcopy(policy)
        test["Statement"][0]["Action"].remove(action)
        with pytest.raises(c.InstallationHold):
            c.verify_gateway_denial_policy(test)
    policy["Statement"][0]["Effect"] = "Allow"
    with pytest.raises(c.InstallationHold):
        c.verify_gateway_denial_policy(policy)


@pytest.mark.parametrize("replacement", (
    "/usr/bin/python3", "/usr/bin/python3.11", "/home/gateway/venv/bin/python3",
))
def test_owner_cannot_select_ambient_or_gateway_interpreter(replacement):
    unit = units()
    assert c.OWNER_PYTHON == "/opt/zog/graphical-owner/venv/bin/python3"
    with pytest.raises(c.InstallationHold):
        c.verify_unit_sources(unit[c.SERVICE].replace(c.OWNER_PYTHON, replacement),
                              unit[c.SOCKET_UNIT])


def test_extra_execstart_cannot_override_protected_interpreter():
    unit = units()
    with pytest.raises(c.InstallationHold):
        c.verify_unit_sources(unit[c.SERVICE] +
            "\nExecStart=\nExecStart=/usr/bin/python3 -m attacker\n",
            unit[c.SOCKET_UNIT])
