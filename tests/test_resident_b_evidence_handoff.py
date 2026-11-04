"""Synthetic cross-owner Resident B handoff, no real mounts or authority."""
import base64
import copy
from uuid import UUID
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from zog.host_install import resident_b_evidence_handoff as h
from zog.host_install.bootable_image_contract import contract, digest

HOST="d3e1a1ef-c0cb-47c9-91d2-58af91e0b101"
INSTALL="a7e2f1c1-f0a7-4268-9458-fd35e6e0a001"
STATE="d6e4d3b3-7d85-4fd8-b056-8ee24b1e0001"
OP="29e2ca5e-97a9-4e16-9c23-d1d56bdc0020"
ROOT_PART="135f649d-73c9-4f35-a30c-f0a51a350001"
STATE_PART="26ca2a28-9ff0-4b9c-8065-d1382e1c0002"
STATE_FS="37c24ca7-ef9b-4f16-86b0-5de1354a0003"
APPS_PART="b9d263c7-cc11-41e3-92bd-6f9509ef0004"
GEN="a"*64
SOURCE="b"*64
ROOT_MANIFEST="c"*64
UNIT="d"*64

def fixture():
    keys={k:Ed25519PrivateKey.generate() for k in ("selection","installed","mount")}
    def pub(k):
        return keys[k].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
    pins={
        "schema":"zog-host-install-resident-b-external-pins-v1",
        "host_id":HOST,"installation_id":INSTALL,"operation_id":OP,
        "state_volume_id":STATE,"selected_slot":"HOST-B",
        "generation_id":GEN,"source_receipt_sha256":SOURCE,
        "rootfs_manifest_sha256":ROOT_MANIFEST,
        "root_partuuid":ROOT_PART,"root_devid":"253:4",
        "state_partuuid":STATE_PART,"state_filesystem_uuid":STATE_FS,
        "state_devid":"253:6","applications_partuuid":APPS_PART,
        "applications_devid":"253:7",
        "bootable_contract_sha256":digest(contract()),
        "selection_key":pub("selection"),"installed_key":pub("installed"),
        "mount_key":pub("mount"),"service_uid":0,"service_gid":0
    }
    selected={
        "generation_id":GEN,"source_generation_receipt_sha256":SOURCE,
        "selection_status":"accepted-as-input",
        "native_boot_authorized":False,
        "root_control_activation_authorized":False
    }
    paths=sorted(h.REQUIRED_OUTPUTS)
    files=[{"path":p,"sha256":UNIT if p.endswith(".service") else "e"*64,
            "size":64,"mode":0o644 if p.endswith(".service") else 0o755,
            "kind":"elf" if p.endswith(".so") or p.endswith(".so.1.0") or
                   p=="usr/bin/python3.12" else "data"} for p in paths]
    obs={
        "generation_id":GEN,"state_volume_id":STATE,
        "source_pins":copy.deepcopy(h.CONTROLLERS),
        "files":files,
        "modules":{name:"usr/lib/python3.12/lib-dynload/"+name+
            ".cpython-312-x86_64-linux-gnu.so" for name in ("_ssl","_sqlite3","_hashlib")},
        "python_version":"3.12.16",
        "state_permissions":{"state_mode":0o700,"private_uid":0,"state_authenticated":True},
        "service_permissions":{"unit_mode":0o644,"socket_mode":0o660,
                "socket_uid":0,"socket_gid_provisioned":True,"service_enabled":False},
        "wheels":{"box_control-0.1.0":{"record_sha256":"f"*64,"record_members":[]},
                  "root_control-0.1.0":{"record_sha256":"f"*64,"record_members":[]}},
        "native_observation":{"rootfs_slot":"HOST-B","rootfs_readonly":True,
            "state_mount_id":STATE,"source_generation_receipt_sha256":SOURCE,
            "observed_by":"synthetic-native-worker","observation_id":"synthetic-invocation-01"},
        "status":"observed","accepted":False
    }
    mount={
        "host_id":HOST,"installation_id":INSTALL,"operation_id":OP,
        "selected_slot":"HOST-B","generation_id":GEN,
        "source_receipt_sha256":SOURCE,"rootfs_manifest_sha256":ROOT_MANIFEST,
        "root_partuuid":ROOT_PART,"root_devid":"253:4","root_read_only":True,
        "state_volume_id":STATE,"state_partuuid":STATE_PART,
        "state_filesystem_uuid":STATE_FS,"state_devid":"253:6",
        "state_mount_verified":True,"applications_partuuid":APPS_PART,
        "applications_devid":"253:7","applications_mount_verified":True,
        "root_control_unit_sha256":UNIT,"root_control_unit_mode":0o644,
        "root_control_uid":0,"root_control_gid":0,"root_control_enabled":False,
        "state_uid":0,"state_gid":0,"state_mode":0o755,
        "physical_inspection_status":"PROTECTED_KERNEL_MOUNT_OBSERVED"
    }
    def envelope(kind,obj):
        domain=h.SIGNATURE_DOMAINS[kind]
        field="selection" if kind=="selection" else "claim"
        return {"schema":{"selection":h.SEL_SCHEMA,"installed":h.OBS_SCHEMA,
                           "mount":h.MOUNT_SCHEMA}[kind],
                field:copy.deepcopy(obj),
                "signature":base64.b64encode(keys[kind].sign(domain+h.canonical(obj))).decode()}
    handoff={"schema":h.SCHEMA,"status":"SOURCE_HANDOFF_NATIVE_NO_GO",
             "selection":envelope("selection",selected),
             "installed":envelope("installed",obs),
             "mount":envelope("mount",mount),
             "authority":{"generation_accepted":None,"boot_authorized":False,
                          "root_control_activation_allowed":False,
                          "worker_submission_allowed":False,"rights_approved":False}}
    return handoff,pins,keys,envelope

def test_cross_owner_synthetically_consistent_but_never_accepts_generation():
    handoff,pins,_,_=fixture()
    result=h.verify(handoff,pins)
    assert result["handoff"]=="EXACT_SOURCE_EVIDENCE_CROSS_OWNER_CONSISTENT"
    assert result["native_generation_accepted"] is None
    assert result["resident_b_boot_authorized"] is False

@pytest.mark.parametrize("role,field,value",[
    ("selection","generation_id","9"*64),
    ("selection","source_generation_receipt_sha256","8"*64),
    ("selection","native_boot_authorized",True),
    ("selection","root_control_activation_authorized",True),
    ("installed","generation_id","8"*64),
    ("installed","state_volume_id","977d490e-d776-482a-b952-91b542950001"),
    ("installed","python_version","3.15.0"),
    ("installed","accepted",True),
    ("mount","generation_id","8"*64),
    ("mount","selected_slot","HOST-A"),
    ("mount","root_partuuid","35b42799-fdf6-472b-bd02-e290b3220001"),
    ("mount","root_devid","253:9"),
    ("mount","state_devid","253:9"),
    ("mount","applications_partuuid","a545a1ac-a2a2-4308-854d-534ce4000000"),
    ("mount","root_read_only",False),
    ("mount","state_mount_verified",False),
    ("mount","applications_mount_verified",False),
    ("mount","root_control_enabled",True),
    ("mount","root_control_unit_sha256","1"*64),
    ("mount","state_mode",0o700),
    ("mount","state_mode",0o777)
])
def test_mismatched_generation_mount_rights_and_service_denied_with_valid_synthetic_signers(role,field,value):
    obj,pins,_,sign=fixture()
    name="selection" if role=="selection" else "claim"
    changed=copy.deepcopy(obj[role][name])
    changed[field]=value
    obj[role]=sign(role,changed)
    with pytest.raises(h.HandoffDenied):h.verify(obj,pins)

@pytest.mark.parametrize("path",[
    "usr/bin/python3.12",
    "usr/lib/python3.12/lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so",
    "usr/lib/python3.12/site-packages/box_control-0.1.0.dist-info/RECORD",
    "usr/lib/systemd/system/zog-root-control.service",
])
def test_missing_required_installed_byte_denied_even_if_native_witness_resigns(path):
    obj,pins,_,sign=fixture()
    claim=copy.deepcopy(obj["installed"]["claim"])
    claim["files"]=[item for item in claim["files"] if item["path"]!=path]
    obj["installed"]=sign("installed",claim)
    with pytest.raises(h.HandoffDenied,match="incomplete installed"):h.verify(obj,pins)

def test_installed_unit_byte_substitution_cross_checks_independent_mount_observer():
    obj,pins,_,sign=fixture()
    claim=copy.deepcopy(obj["installed"]["claim"])
    next(row for row in claim["files"] if row["path"].endswith("zog-root-control.service"))["sha256"]="0"*64
    obj["installed"]=sign("installed",claim)
    with pytest.raises(h.HandoffDenied,match="unverified physical"):h.verify(obj,pins)

def test_private_state_permissions_are_separate_from_mount_root():
    obj,pins,_,sign=fixture()
    assert obj["mount"]["claim"]["state_mode"]==0o755
    assert obj["installed"]["claim"]["state_permissions"]["state_mode"]==0o700
    witness=copy.deepcopy(obj["installed"]["claim"])
    witness["state_permissions"]["state_mode"]=0o755
    obj["installed"]=sign("installed",witness)
    with pytest.raises(h.HandoffDenied,match="private STATE"):h.verify(obj,pins)

def test_untrusted_ed25519_pins_or_transplant_are_denied():
    obj,pins,_,_=fixture()
    fake=copy.deepcopy(pins)
    fake["installed_key"]="e"*64
    with pytest.raises(h.HandoffDenied):h.verify(obj,fake)
    fake=copy.deepcopy(pins)
    fake["mount_key"]=fake["installed_key"]
    with pytest.raises(h.HandoffDenied):h.verify(obj,fake)
    fake=copy.deepcopy(pins)
    fake["state_partuuid"]="14f6c4aa-5026-4de4-8394-a457cbce0101"
    with pytest.raises(h.HandoffDenied):h.verify(obj,fake)
    fake=copy.deepcopy(pins)
    fake["generation_id"]=h.OLD_REJECTED
    with pytest.raises(h.HandoffDenied,match="previously rejected"):h.verify(obj,fake)

@pytest.mark.parametrize("field,value",[
    ("boot_authorized",True),
    ("worker_submission_allowed",True),
    ("root_control_activation_allowed",True),
    ("generation_accepted","a"*64),
    ("rights_approved",True),
])
def test_signed_looking_claim_never_confers_authority(field,value):
    obj,pins,_,_=fixture()
    obj["authority"][field]=value
    with pytest.raises(h.HandoffDenied,match="fabricated acceptance"):h.verify(obj,pins)

def test_tampered_signed_installed_claim_denied_before_cross_owner_comparison():
    obj,pins,_,_=fixture()
    obj["installed"]["claim"]["status"]="accepted"
    with pytest.raises(h.HandoffDenied,match="signature"):h.verify(obj,pins)


def test_live_verified_host_install_context_cannot_be_fabricated_from_json():
    _,pins,_,_=fixture()
    with pytest.raises(h.HandoffDenied,match="VerifiedState"):
        h.inspect_protected_host_generation_context({"mount":"looks-authentic"},pins)
    with pytest.raises(h.HandoffDenied,match="VerifiedState"):
        h.inspect_protected_host_generation_context(object(),pins)
