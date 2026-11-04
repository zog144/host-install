"""Synthetic cross-owner Resident B evidence: signatures, physical context, actual bytes.

No native mount, root filesystem installation, service activation or accepted
generation. The image-build verifier checks a disposable synthetic file tree.
"""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_install import resident_b_acceptance_handoff as host

ROOT=Path(__file__).resolve().parents[1]
IMAGE_BUILD=ROOT/"companion-image-build"
sys.path.insert(0,str(IMAGE_BUILD))
spec=importlib.util.spec_from_file_location(
    "resident_b_fixture",IMAGE_BUILD/"tests/test_resident_b_installed_evidence.py")
fixture_source=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_source)


def case(tmp_path):
    image,claim,byte_key,sign_bytes,selection,gen_key=fixture_source.fixture(tmp_path)
    host_key=Ed25519PrivateKey.generate()
    mount_key=Ed25519PrivateKey.generate()
    host_id=str(uuid.uuid4())
    install_id=str(uuid.uuid4())
    root_partuuid=str(uuid.uuid4())
    state_partuuid=str(uuid.uuid4())
    pinned={
        "host_id":host_id,"installation_id":install_id,
        "input_generation":fixture_source.GEN,
        "state_volume_id":fixture_source.STATE,
        "rootfs_partuuid":root_partuuid,"state_partuuid":state_partuuid}
    observed=dict(schema=host.OBS_SCHEMA,**pinned,
        rootfs_device=11,state_device=22,rootfs_readonly=True,state_mounted=True,
        rootfs_mount_id="synthetic-rootfs-v1",state_mount_id="synthetic-state-v1",
        state_uid=0,state_gid=0,state_mode=0o700,
        socket_uid=0,socket_gid=2345,socket_mode=0o660,
        service_enabled=False,observer_id="synthetic-physical-observer",
        observation_id=str(uuid.uuid4()))
    def sign_physical(value):
        return dict(schema=host.OBS_SCHEMA,claim=value,
            signature=base64.b64encode(mount_key.sign(
                b"zog-host-install-resident-b-physical-observation-v1\0"+
                host.canonical(value))).decode())
    evidence=dict(schema=host.SCHEMA,image_build_source_sha=host.SOURCE_IMAGE_BUILD,
        **pinned,selected_host_slot="HOST-B",rootfs_device=11,state_device=22,
        socket_gid=2345,controller_uid=0,controller_gid=0,service_enabled=False,
        accepted=False,native_authority=None,physical_observation=sign_physical(observed))
    def sign_host(value):
        raw={k:v for k,v in value.items() if k!="signature"}
        return {**raw,"signature":base64.b64encode(host_key.sign(
            b"zog-host-install-resident-b-native-acceptance-handoff-v1\0"+
            host.canonical(raw))).decode()}
    proof=sign_host(evidence)
    arguments=dict(expected_host=host_id,expected_installation=install_id,
       expected_generation=fixture_source.GEN,expected_state=fixture_source.STATE,
       expected_root_partuuid=root_partuuid,expected_state_partuuid=state_partuuid,
       trusted_host_install_key=host_key.public_key(),
       trusted_physical_observer_key=mount_key.public_key(),
       trusted_generation_key=gen_key.public_key(),
       trusted_installed_byte_key=byte_key.public_key(),
       source_selection=selection,byte_observation=sign_bytes(claim))
    return image,claim,proof,arguments,sign_host,sign_physical,observed,byte_key,gen_key


def test_selected_generation_and_installed_bytes_are_cross_owner_but_unaccepted(tmp_path):
    root,claim,evidence,args,*_=case(tmp_path)
    assert fixture_source.v.verify(root,args["byte_observation"],
        args["trusted_installed_byte_key"],
        expected_generation=args["expected_generation"],
        expected_state=args["expected_state"],
        selected_generation_receipt=args["source_selection"],
        trusted_generation_public_key=args["trusted_generation_key"])["accepted_generation"] is None
    output=host.validate_handoff(evidence,**args)
    assert output["status"]=="CROSS_OWNER_SIGNED_CLAIMS_MATCH_UNACCEPTED"
    assert output["generation_accepted"] is None
    assert output["physical_mounts_independently_verified"] is False


@pytest.mark.parametrize("field,substitute",[
    ("input_generation","b"*64),("state_volume_id","wrong-volume-id"),
    ("installation_id",str(uuid.uuid4())),("rootfs_device",22),
    ("state_device",11),("selected_host_slot","HOST-C"),
    ("socket_gid",0),("controller_uid",1000),("service_enabled",True),
    ("accepted",True),("native_authority",{"approved":True}),
])
def test_wrong_generation_state_or_fabricated_authorization_denied(tmp_path,field,substitute):
    root,claim,evidence,args,sign_host,*_=case(tmp_path)
    bad=sign_host({**evidence,field:substitute})
    with pytest.raises(host.NativeEvidenceHold):
        host.validate_handoff(bad,**args)


def test_substituted_signed_physical_mount_state_or_socket_denied(tmp_path):
    root,claim,evidence,args,sign_host,sign_physical,physical,*_=case(tmp_path)
    for key,bad_value in (
        ("state_device",99),("rootfs_device",99),("state_mounted",False),
        ("rootfs_readonly",False),("socket_gid",9999),
        ("socket_mode",0o666),("state_uid",1000),("rootfs_mount_id","same")):
        modified={**physical,key:bad_value}
        if key=="rootfs_mount_id":modified["state_mount_id"]="same"
        forged=sign_host({**evidence,"physical_observation":sign_physical(modified)})
        with pytest.raises(host.NativeEvidenceHold):
            host.validate_handoff(forged,**args)


def test_wrong_signature_or_self_selected_authority_denied(tmp_path):
    root,claim,evidence,args,sign_host,sign_physical,physical,byte_key,gen_key=case(tmp_path)
    tampered={**evidence,"socket_gid":1234}
    with pytest.raises(host.NativeEvidenceHold):
        host.validate_handoff(tampered,**args)
    fake={**args,"trusted_physical_observer_key":args["trusted_host_install_key"]}
    with pytest.raises(host.NativeEvidenceHold):
        host.validate_handoff(evidence,**fake)
    fake={**args,"trusted_generation_key":args["trusted_installed_byte_key"]}
    with pytest.raises(host.NativeEvidenceHold):
        host.validate_handoff(evidence,**fake)
    forged={**args,"source_selection":{
        **args["source_selection"],
        "selection":{**args["source_selection"]["selection"],
                     "native_boot_authorized":True}}}
    with pytest.raises(host.NativeEvidenceHold):
        host.validate_handoff(evidence,**forged)


def test_different_installed_bytes_fail_actual_image_build_verifier(tmp_path):
    root,claim,evidence,args,*_=case(tmp_path)
    path=root/"usr/bin/box-control"
    path.write_bytes(b"#!/usr/bin/python3.15\nforged\n")
    # Source handoff may still match signed CLAIMS; it never claims to have
    # measured the filesystem and cannot replace image-build's byte verifier.
    assert host.validate_handoff(evidence,**args)["physical_mounts_independently_verified"] is False
    with pytest.raises(fixture_source.v.EvidenceDenied):
        fixture_source.v.verify(root,args["byte_observation"],
            args["trusted_installed_byte_key"],
            expected_generation=args["expected_generation"],
            expected_state=args["expected_state"],
            selected_generation_receipt=args["source_selection"],
            trusted_generation_public_key=args["trusted_generation_key"])
