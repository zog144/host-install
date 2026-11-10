"""Review-only executable transaction selection with source-backed fixtures.

No native account, service or /state mutation. The candidate exec entrypoint
remains fail-closed for production until rollback/reboot acceptance.
"""
import copy
import os

import pytest

from test_state_account_migration_issuer import (
    selection_and_evidence, _witness,
)
from zog.host_install import state_account_migration_issuer as issuer
from zog.host_install import state_account_migration_execution as executor
from zog.host_install import state_account_migration_native as native
from zog.host_install import state_account_migration_launcher as launcher
from zog.host_install.state_contract import StateError, canonical, digest
from zog.host_install.state_io import lock


@pytest.fixture
def admitted(tmp_path, monkeypatch):
    if os.geteuid()!=0:
        pytest.skip("protected disposable review requires root")
    selection,observation=selection_and_evidence()
    bundle,admission=issuer.evaluate(selection,observation)
    selection["approved_admission_sha256"]=digest(admission)
    path=tmp_path/"migrations"
    path.mkdir(mode=0o700)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        with lock(fd,".admission.lock"):
            issuer._publish_records(
                fd,selection["migration_id"],selection=selection,
                bundle=bundle,admission=admission,
                witness=_witness(admission),
                file_inventory=observation["source_inputs"]["file_inventory"])
    finally:
        os.close(fd)
    monkeypatch.setattr(executor,"select_runtime",lambda *args:admission["runtime"])
    return path,selection,observation,bundle,admission


def read(parent, migration):
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        return executor.review_protected_transaction(fd,migration)
    finally:
        os.close(fd)


def test_exact_issued_transaction_selects_original_metadata_and_runtime(admitted):
    path,selected,observation,bundle,admission=admitted
    result=read(path,selected["migration_id"])
    assert result["plan"]==admission["plan"]
    assert result["bundle"]==bundle
    assert result["admission"]==admission
    assert result["file_inventory"]==observation["source_inputs"]["file_inventory"]
    assert executor._selected_file_inventory(
        admission["plan"],result)==result["file_inventory"]


@pytest.mark.parametrize("tamper",(
    "inventory","operator","bundle","journal","extra-file",
))
def test_conflicting_native_records_deny_without_activating_host(admitted,tamper):
    path,selected,observation,bundle,admission=admitted
    folder=path/selected["migration_id"]
    if tamper=="extra-file":
        (folder/"unreviewed.json").write_text("{}")
    else:
        name={
            "inventory":"source-inventory.json",
            "operator":"operator-selection.json",
            "bundle":"bundle.json",
            "journal":"transaction.json",
        }[tamper]
        (folder/name).write_bytes(canonical({"foreign":"selection"}))
    with pytest.raises((StateError,KeyError,TypeError)):
        read(path,selected["migration_id"])


def test_root_executor_does_not_mutate_while_native_gates_held():
    assert native.NATIVE_ACTIVATION_ENABLED is False
    assert launcher.RUNTIME_ENABLED is False
    with pytest.raises(StateError,match="migration-native-hold"):
        executor.execute(
            "11111111-1111-4111-8111-111111111111",
            expected_admission_sha256="a"*64)
