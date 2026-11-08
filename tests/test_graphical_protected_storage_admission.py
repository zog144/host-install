"""Source-only protected mounts adoption and new-scope separation tests."""
import copy
import pytest
from zog.host_install import graphical_protected_storage_admission as s
from zog.host_install import graphical_readonly_trust_broker_install as broker

def fixture():
    return {
      "schema":s.SCHEMA, "mode":"adopt-existing-original",
      "host_id":"a"*64,"installation_id":"b"*64,"state_volume_id":"c"*64,
      "state_fs_uuid":"c9a14c15-c513-43bc-bb4b-345fe74ce960",
      "scope_sha256":"sha256:"+"d"*64,
      "original_record_sha256":"sha256:"+"e"*64,
      "external_authorization_sha256":None,
      "history_authenticated":False,"anchor_authenticated":False,
      "operator_approved":False,
      "mounts":[{
        "path":broker.ORIGINAL_LEDGER,
        "filesystem_uuid":"11111111-1111-4111-8111-111111111111",
        "block_partuuid":"22222222-2222-4222-8222-222222222222",
        "expected_source":"/dev/disk/by-uuid/11111111-1111-4111-8111-111111111111",
        "filesystem_type":"ext4","writable":True,
        "mount_options":["nodev","nosuid"]},
        {"path":broker.ROOT_AUTHORITY,
         "filesystem_uuid":"33333333-3333-4333-8333-333333333333",
         "block_partuuid":"44444444-4444-4444-8444-444444444444",
         "expected_source":"/dev/disk/by-uuid/33333333-3333-4333-8333-333333333333",
         "filesystem_type":"ext4","writable":True,
         "mount_options":["nodev","nosuid"]}]
    }

def test_existing_history_adoption_is_not_authentication():
    p=fixture()
    output=s.plan_protected_mounts(p)
    assert output["status"]=="ORIGINAL_HISTORY_AND_INDEPENDENT_ANCHOR_REQUIRED"
    assert all(v is False for k,v in output.items() if k!="status")

def test_missing_real_mounts_block_before_any_provisioning():
    with pytest.raises(broker.BrokerInstallHeld):
        s.inspect_actual_mounts(fixture())

@pytest.mark.parametrize("mutation", [
 "same_fs", "state_fs", "same_partuuid", "same_path", "missing_mount",
 "source_state", "tmpfs", "bind_fs", "writable", "uid", "unexpected",
 "history_self_claim", "anchor_self_claim", "operator_self_claim",
 "missing_original_record", "incorrect_scope",
])
def test_no_empty_directory_fake_independence_or_fake_original(mutation):
    p=fixture()
    if mutation=="same_fs":p["mounts"][1]["filesystem_uuid"]=p["mounts"][0]["filesystem_uuid"]
    if mutation=="state_fs":p["mounts"][0]["filesystem_uuid"]=p["state_fs_uuid"]
    if mutation=="same_partuuid":p["mounts"][0]["block_partuuid"]=p["mounts"][1]["block_partuuid"]
    if mutation=="same_path":p["mounts"][1]["path"]=p["mounts"][0]["path"]
    if mutation=="missing_mount":p["mounts"].pop()
    if mutation=="source_state":p["mounts"][0]["expected_source"]="/state/ledger"
    if mutation=="tmpfs":p["mounts"][0]["filesystem_type"]="tmpfs"
    if mutation=="bind_fs":p["mounts"][0]["mount_options"]=["bind"]
    if mutation=="writable":p["mounts"][0]["writable"]=False
    if mutation=="uid":p["mounts"][0]["filesystem_uuid"]="uuid-generated"
    if mutation=="unexpected":p["mounts"][0]["owner"]=0
    if mutation=="history_self_claim":p["history_authenticated"]=True
    if mutation=="anchor_self_claim":p["anchor_authenticated"]=True
    if mutation=="operator_self_claim":p["operator_approved"]=True
    if mutation=="missing_original_record":p["original_record_sha256"]=None
    if mutation=="incorrect_scope":p["scope_sha256"]="sha256:"+"0"*64
    with pytest.raises(broker.BrokerInstallHeld):
        s.plan_protected_mounts(p)

def test_new_scope_requires_separate_approval_not_original_claim():
    p=fixture()
    p["mode"]="provision-separately-approved-new-scope"
    p["scope_sha256"]="sha256:"+"9"*64
    p["original_record_sha256"]=None
    p["external_authorization_sha256"]="sha256:"+"8"*64
    out=s.plan_protected_mounts(p)
    assert out["status"]=="NEW_SCOPE_NOT_ORIGINAL_CONTINUITY"
    assert out["new_scope_authorized"] is False
    for bad in [
      {"original_record_sha256":"sha256:"+"e"*64},
      {"external_authorization_sha256":None},
      {"operator_approved":True},
    ]:
      q=copy.deepcopy(p);q.update(bad)
      with pytest.raises(broker.BrokerInstallHeld):
          s.plan_protected_mounts(q)

def test_rendered_mount_units_bind_distinct_exact_devices_and_remain_disabled():
    plan=fixture()
    units=s.disabled_mount_unit_candidates(plan)
    assert set(units) == {
        "var-lib-zog-graphical-owner-ledger.mount",
        "var-lib-zog-graphical-owner-authority.mount",
    }
    for row in plan["mounts"]:
        name=row["path"].strip("/").replace("/","-")+".mount"
        text=units[name]
        assert "[Unit]\n" in text and "[Mount]\n" in text
        assert "What="+row["expected_source"]+"\n" in text
        assert "Where="+row["path"]+"\n" in text
        assert "DirectoryMode=0700" in text
        assert "[Install]" not in text and "WantedBy=" not in text
    plan["mounts"][0]["expected_source"]="/dev/nvme1n1p1"
    with pytest.raises(broker.BrokerInstallHeld):
        s.disabled_mount_unit_candidates(plan)
