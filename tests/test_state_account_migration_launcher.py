"""Exact root-owned completion and two-FD beacon launcher regression."""
import copy
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from zog.host_install import state_account_migration_launcher as launcher
from zog.host_install import state_account_migration_completion as complete
from zog.host_install.state_account_migration_consumer import CONSUMER_SELECTION
from zog.host_install.state_contract import StateError, canonical, digest
from test_state_account_migration import fixture as migration_fixture
from test_state_account_migration_completion import retained, run_issue


def runtime(retained, monkeypatch):
    plan,moved,evidence,witness,journal,_,fingerprint=retained
    bundle=migration_fixture()["bundle"]
    bundle["bootstrap"]["initialization"]["expected_fingerprint"]=fingerprint
    plan["bundle_sha256"]=digest(bundle)
    witness["plan_sha256"]=digest(plan)
    journal["plan_sha256"]=digest(plan)
    (evidence/"original.json").write_bytes(canonical(witness))
    (evidence/"transaction.json").write_bytes(canonical(journal))
    (evidence/"plan.json").write_bytes(canonical(plan))
    (evidence/"plan.json").chmod(0o600)
    receipt=run_issue(retained)
    folder=os.open(evidence,os.O_RDONLY|os.O_DIRECTORY)
    try:complete.publish_completion(folder,receipt)
    finally:os.close(folder)
    monkeypatch.setattr(launcher,"IDENTITY_DIRECTORY",str(moved))
    state=moved.parents[1]
    ctx=SimpleNamespace(
        fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW),
        bundle=bundle,
        mount={"backend":"root-directory"},
        recheck=lambda:None)
    def openall():
        return [
            os.open(evidence/"plan.json",os.O_RDONLY|os.O_NOFOLLOW),
            os.open(evidence/"transaction.json",os.O_RDONLY|os.O_NOFOLLOW),
            os.open(evidence/complete.COMPLETION_FILE,os.O_RDONLY|os.O_NOFOLLOW),
            os.open(moved,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW),
        ]
    return plan,moved,evidence,ctx,openall,receipt


def test_launcher_freshly_validates_exact_transaction_and_no_key_bytes(
        retained,monkeypatch):
    plan,moved,evidence,ctx,openall,receipt=runtime(retained,monkeypatch)
    handles=openall()
    try:
        result=launcher.validate_relaunch_fds(
            ctx,*handles,expected_uid=0,expected_gid=0)
        assert result["status"]=="reviewed-retained-identity-relaunch"
        assert result["public_fingerprint"]==plan["public_fingerprint"]
        assert result["remote_control_authorized"] is False
        argv=launcher.selected_beacon_argv(handles[-1],handles[-2],
                                           result["public_fingerprint"])
        assert "--existing-legacy-migration" in argv
        assert "--migration-completion-fd" in argv
        assert "--retained-identity-fd" in argv
        assert "synthetic-key-only" not in " ".join(argv)
        assert "retained_fingerprint" not in " ".join(argv)
    finally:
        for fd in handles:os.close(fd)
        os.close(ctx.fd)


@pytest.mark.parametrize("attack",(
    "wrong-host","wrong-registry","wrong-bootstrap-fingerprint",
    "wrong-plan","wrong-receipt","rolled-back","wrong-uuid",
    "wrong-completion-fingerprint","wrong-fd-path",
))
def test_launcher_denies_foreign_source_installation_or_rollback(
        retained,monkeypatch,attack):
    plan,moved,evidence,ctx,openall,receipt=runtime(retained,monkeypatch)
    if attack=="wrong-host":
        ctx.bundle["bootstrap"]["initialization"]["expected_host_uuid"]=str(uuid.uuid4())
    elif attack=="wrong-registry":
        ctx.bundle["bootstrap"]["registries"][0]["origin"]="https://foreign.invalid"
    elif attack=="wrong-bootstrap-fingerprint":
        ctx.bundle["bootstrap"]["initialization"]["expected_fingerprint"]="f"*64
    elif attack=="wrong-plan":
        plan["installation_id"]=str(uuid.uuid4())
        (evidence/"plan.json").write_bytes(canonical(plan))
    elif attack=="wrong-receipt":
        receipt["plan_sha256"]="0"*64
        (evidence/complete.COMPLETION_FILE).write_bytes(canonical(receipt))
    elif attack=="rolled-back":
        journal=__import__("json").loads((evidence/"transaction.json").read_text())
        journal["status"]="rolled-back"
        (evidence/"transaction.json").write_bytes(canonical(journal))
    elif attack=="wrong-uuid":
        ctx.bundle["bootstrap"]["state"]["filesystem_uuid"]=str(uuid.uuid4())
    elif attack=="wrong-completion-fingerprint":
        receipt["fingerprint"]="0"*64
        (evidence/complete.COMPLETION_FILE).write_bytes(canonical(receipt))
    elif attack=="wrong-fd-path":
        replacement=moved.parent/"other-identity"
        replacement.mkdir(mode=0o700)
        (moved).rename(replacement)
        moved.mkdir(mode=0o700)
    handles=openall()
    try:
        with pytest.raises((StateError,OSError)):
            launcher.validate_relaunch_fds(
                ctx,*handles,expected_uid=0,expected_gid=0)
    finally:
        for fd in handles:os.close(fd)
        os.close(ctx.fd)


def test_launcher_unit_is_selected_and_requires_native_inspection(monkeypatch):
    assert launcher.RUNTIME_ENABLED is True
    unit=launcher.reviewed_launcher_dropin_template()
    assert b"User=root" in unit and b"Group=root" in unit
    assert b"ExecStart=" in unit and b"@PINNED_HOST_INSTALL_PYTHON312@" in unit
    assert b"ReadWritePaths=/state/host-discover/identity" in unit
    assert b"WantedBy=" not in unit
    actual=launcher.render_launcher_dropin(
        "/opt/host-install/venv/bin/python3.12")
    assert b"@PINNED_" not in actual
    assert b"state_account_migration_launcher" in actual
    with pytest.raises(StateError):
        launcher.render_launcher_dropin("/usr/bin/python3")
    monkeypatch.setattr(launcher.os,"geteuid",lambda:1000)
    with pytest.raises(StateError,match="root-required|migration-native-hold"):
        launcher.run_selected_once()


def test_launcher_accepts_committed_prestart_then_complete_without_new_receipt(
        retained, monkeypatch):
    """Selected original key works before systemd start and after journal commit."""
    from zog.host_install import state_account_migration as migration
    plan,moved,evidence,ctx,openall,_ = runtime(retained, monkeypatch)
    intent = migration.service_start_intent(plan)
    (evidence/"transaction.json").write_bytes(canonical(intent))
    handles = []
    try:
        handles = [
            os.open(evidence/"original.json",os.O_RDONLY|os.O_NOFOLLOW),
            os.open(evidence/"transaction.json",os.O_RDONLY|os.O_NOFOLLOW),
            os.open(moved,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW),
        ]
        receipt = complete.completion_from_observed_fds(
            plan=plan, original_witness_fd=handles[0],
            journal_fd=handles[1], identity_fd=handles[2],
            identity_directory=str(moved),
            expected_uid=0,expected_gid=0,prestart=True)
    finally:
        for fd in handles: os.close(fd)
    (evidence/complete.COMPLETION_FILE).write_bytes(canonical(receipt))
    for status in ("applying","complete"):
        if status=="complete":
            completed={**intent, "status":"complete", "active":None,
                       "completed":list(migration.STAGES)}
            (evidence/"transaction.json").write_bytes(canonical(completed))
        fds=openall()
        try:
            outcome=launcher.validate_relaunch_fds(
                ctx,*fds,expected_uid=0,expected_gid=0)
            assert outcome["status"]=="reviewed-retained-identity-relaunch"
        finally:
            for fd in fds: os.close(fd)
    (evidence/"transaction.json").write_bytes(canonical(
        {**intent, "status":"rolling-back"}))
    fds=openall()
    try:
        with pytest.raises(StateError):
            launcher.validate_relaunch_fds(
                ctx,*fds,expected_uid=0,expected_gid=0)
    finally:
        for fd in fds: os.close(fd)
        os.close(ctx.fd)
