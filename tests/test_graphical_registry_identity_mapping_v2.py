"""V2 registrar maps one backend, never invents a Host identity or readiness."""
import base64
import copy
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zog.host_install import graphical_registry_identity_mapping as v1
from zog.host_install import graphical_registry_identity_mapping_v2 as v2
from zog.host_install.graphical_readonly_trust_broker_install import BrokerInstallHeld
from test_graphical_registry_identity_mapping import fixture

def source(backend):
    _,registry,legacy,_,registry_pub,_=fixture()
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    common={
        "host_uuid":legacy["host_uuid"],
        "aws_instance_id":"i-0123456789abcdef0",
        "aws_region":"us-east-1",
        "state_marker_sha256":"sha256:"+"a"*64,
        "filesystem_uuid":"44444444-4444-4444-8444-444444444444",
        "partuuid":"55555555-5555-4555-8555-555555555555",
        "mountpoint":"/state",
    }
    if backend=="root-directory":
        observation={**common,"mounted":False,"root_mount_id":19,
            "root_device":"259:1","state_device":"259:1",
            "state_inode":123456,"state_uid":0,"state_gid":0,
            "state_mode":0o755}
    else:
        observation={**common,"mounted":True,"state_mount_id":20,
            "state_device":"259:2","volume_id":"vol-0123456789abcdef0"}
    args=dict(legacy=legacy,registered_installation=registry,
              observation=observation,backend=backend,
              pinned_registrar_public=pub,pinned_registry_public=registry_pub)
    prepared=v2.prepare_unsigned(**args)
    signed={**prepared["body"],"signature_ed25519":base64.b64encode(
        key.sign(v2.DOMAIN+prepared["canonical_bytes"])).decode("ascii")}
    return args,signed,key

@pytest.mark.parametrize("backend",["root-directory","mounted-volume"])
def test_backends_require_distinct_signed_v2_domain_and_never_admit(backend):
    args,signed,key=source(backend)
    checked=v2.verify_signed(**args,signed_mapping=signed)
    assert checked["backend"]==backend
    assert checked["native_accepted"] is False
    assert checked["broker_admission"] is False
    assert checked["ssm_authorized"] is False
    assert v2.DOMAIN != v1.DOMAIN
    assert v2.prepare_unsigned(**args)["registrar_signature_present"] is False

@pytest.mark.parametrize("backend",["root-directory","mounted-volume"])
@pytest.mark.parametrize("attack",(
    "wrong_backend","removed_marker","alter_marker","changed_host",
    "changed_fingerprint","changed_root","changed_inode","changed_device",
    "unexpected_mount","different_uuid","copied_instance","extra_field",
    "missing_field","wrong_signature","v1_signature_domain",
    "different_registrar","registry_substitution","boolean_mount",
))
def test_v2_backend_replacements_and_signature_substitutions_hold(backend,attack):
    args,signed,key=source(backend)
    args=copy.deepcopy(args);signed=copy.deepcopy(signed)
    obs=args["observation"]
    if attack=="wrong_backend":args["backend"]="mounted-volume" if backend=="root-directory" else "root-directory"
    elif attack=="removed_marker":obs.pop("state_marker_sha256")
    elif attack=="alter_marker":obs["state_marker_sha256"]="sha256:"+"e"*64
    elif attack=="changed_host":obs["host_uuid"]="66666666-6666-4666-8666-666666666666"
    elif attack=="changed_fingerprint":args["legacy"]["fingerprint"]="f"*64
    elif attack=="changed_root":
        if backend=="root-directory":obs["root_mount_id"]=222
        else:obs["state_mount_id"]=222
    elif attack=="changed_inode":
        if backend=="root-directory":obs["state_inode"]=999
        else:obs["volume_id"]="vol-00000000000000000"
    elif attack=="changed_device":obs["state_device"]="259:3"
    elif attack=="unexpected_mount":obs["mounted"]=not obs["mounted"]
    elif attack=="different_uuid":obs["filesystem_uuid"]="66666666-6666-4666-8666-666666666666"
    elif attack=="copied_instance":obs["aws_instance_id"]="i-00000000000000000"
    elif attack=="extra_field":obs["unexpected"]="injection"
    elif attack=="missing_field":obs.pop("partuuid")
    elif attack=="wrong_signature":signed["signature_ed25519"]=base64.b64encode(b"0"*64).decode()
    elif attack=="v1_signature_domain":
        raw=v1.canonical({k:v for k,v in signed.items() if k!="signature_ed25519"})
        signed["signature_ed25519"]=base64.b64encode(key.sign(v1.DOMAIN+raw)).decode()
    elif attack=="different_registrar":args["pinned_registrar_public"]=b"0"*32
    elif attack=="registry_substitution":args["registered_installation"]["host_id"]="f"*64
    elif attack=="boolean_mount":obs["mounted"]=1
    with pytest.raises(BrokerInstallHeld):
        v2.verify_signed(**args,signed_mapping=signed)

def test_no_unverified_json_or_mount_backend_claim_can_be_a_native_receipt():
    args,signed,key=source("root-directory")
    for missing in ("observation","registered_installation","pinned_registrar_public"):
        other=dict(args);other[missing]=None
        with pytest.raises(BrokerInstallHeld):
            v2.verify_signed(**other,signed_mapping=signed)
