"""Disabled source handoff from independently pinned host-install evidence to
image-build Resident B's read-only installed-generation verifier.

Signatures and source identities are source-testable. Physical kernel mount,
installed wheel/RECORD and systemd ownership evidence still require native
observation by an independently protected owner; this API never accepts a Host.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
import uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA="zog-host-install-resident-b-native-acceptance-handoff-v1"
MOUNT_SCHEMA="zog-host-install-resident-b-native-mount-v1"
OBS_SCHEMA="zog-host-install-resident-b-physical-observation-v1"
SOURCE_IMAGE_BUILD="06e2714ff032dc8ca985d056a1e8800515847f65"
SHA=re.compile(r"[a-f0-9]{64}\Z")
REQUIRED={"schema","image_build_source_sha","input_generation","state_volume_id",
          "installation_id","host_id","selected_host_slot","rootfs_device",
          "state_device","rootfs_partuuid","state_partuuid","socket_gid",
          "controller_uid","controller_gid","service_enabled","accepted",
          "native_authority","physical_observation","signature"}
PHYSICAL={"schema","host_id","installation_id","input_generation",
          "state_volume_id","rootfs_device","state_device","rootfs_partuuid",
          "state_partuuid","rootfs_readonly","state_mounted","rootfs_mount_id",
          "state_mount_id","state_uid","state_gid","state_mode","socket_uid",
          "socket_gid","socket_mode","service_enabled","observer_id","observation_id"}

class NativeEvidenceHold(ValueError):
    pass

def _hold(reason):
    raise NativeEvidenceHold("Resident B native evidence HOLD: "+reason)

def canonical(payload):
    return json.dumps(payload,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True,allow_nan=False).encode("ascii")

def _verify(envelope, *, expected_schema, public_key, domain, keys):
    if type(envelope) is not dict or set(envelope)!={"schema","claim","signature"}:
        _hold("missing authenticated evidence envelope")
    if envelope["schema"]!=expected_schema or type(envelope["claim"]) is not dict:
        _hold("wrong signed evidence schema")
    claim=envelope["claim"]
    if set(claim)!=keys:
        _hold("incomplete native evidence")
    try:
        sig=base64.b64decode(envelope["signature"],validate=True)
        if len(sig)!=64 or base64.b64encode(sig).decode("ascii")!=envelope["signature"]:
            _hold("noncanonical evidence signature")
        public_key.verify(sig,domain+canonical(claim))
    except (TypeError,AttributeError,InvalidSignature,ValueError):
        _hold("evidence signer not independently authenticated")
    return claim

def validate_handoff(evidence, *, expected_host, expected_installation,
                     expected_generation, expected_state, expected_root_partuuid,
                     expected_state_partuuid, trusted_host_install_key,
                     trusted_physical_observer_key, trusted_generation_key,
                     trusted_installed_byte_key, source_selection, byte_observation):
    """Cross-owner preflight only; NEVER emits a native accepted generation."""
    if type(evidence) is not dict or set(evidence)!=REQUIRED:
        _hold("incomplete resident evidence handoff")
    if evidence["schema"]!=SCHEMA or evidence["image_build_source_sha"]!=SOURCE_IMAGE_BUILD:
        _hold("stale Resident B source verifier")
    if (type(expected_generation) is not str or not SHA.fullmatch(expected_generation)
            or not all(type(x) is str and x for x in
                       (expected_host,expected_installation,expected_state,
                        expected_root_partuuid,expected_state_partuuid))):
        _hold("missing independently selected Host/STATE/rootfs")
    pinned={"host_id":expected_host,"installation_id":expected_installation,
            "input_generation":expected_generation,"state_volume_id":expected_state,
            "rootfs_partuuid":expected_root_partuuid,"state_partuuid":expected_state_partuuid}
    if any(evidence[k]!=v for k,v in pinned.items()):
        _hold("wrong selected Host, generation, installation or STATE partition")
    if (evidence["selected_host_slot"] not in ("HOST-A","HOST-B")
            or type(evidence["rootfs_device"]) is not int
            or type(evidence["state_device"]) is not int
            or evidence["rootfs_device"]<=0 or evidence["state_device"]<=0
            or evidence["rootfs_device"]==evidence["state_device"]
            or type(evidence["socket_gid"]) is not int or evidence["socket_gid"]<=0
            or evidence["controller_uid"]!=0 or evidence["controller_gid"]!=0
            or evidence["service_enabled"] is not False
            or evidence["accepted"] is not False
            or evidence["native_authority"] is not None):
        _hold("claimed native authority or missing device and service isolation")
    raw={k:v for k,v in evidence.items() if k!="signature"}
    try:
        sig=base64.b64decode(evidence["signature"],validate=True)
        if len(sig)!=64 or base64.b64encode(sig).decode()!=evidence["signature"]:
            _hold("bad host-install selection signature")
        trusted_host_install_key.verify(sig,
                  b"zog-host-install-resident-b-native-acceptance-handoff-v1\0"+canonical(raw))
    except (TypeError,ValueError,InvalidSignature,AttributeError):
        _hold("untrusted host-install source context")
    observed=_verify(evidence["physical_observation"],expected_schema=OBS_SCHEMA,
                     public_key=trusted_physical_observer_key,
                     domain=b"zog-host-install-resident-b-physical-observation-v1\0",
                     keys=PHYSICAL)
    for k in pinned:
        if observed[k]!=pinned[k]:_hold("substituted physical Host, generation or STATE")
    for k in ("rootfs_device","state_device","rootfs_partuuid","state_partuuid",
              "socket_gid","service_enabled"):
        if observed[k]!=evidence[k]:_hold("physical mount or service ownership substituted")
    if (observed["rootfs_readonly"] is not True or observed["state_mounted"] is not True
            or observed["state_uid"]!=0 or observed["state_gid"]!=0
            or observed["state_mode"] not in (0o700,0o750)
            or observed["socket_uid"]!=0 or observed["socket_mode"]!=0o660
            or not isinstance(observed["rootfs_mount_id"],str)
            or not observed["rootfs_mount_id"]
            or not isinstance(observed["state_mount_id"],str)
            or not observed["state_mount_id"]
            or observed["rootfs_mount_id"]==observed["state_mount_id"]
            or not isinstance(observed["observer_id"],str) or not observed["observer_id"]
            or not isinstance(observed["observation_id"],str) or not observed["observation_id"]):
        _hold("unproven physical read-only root or STATE/service ownership")
    # image-build independently requires its own generation selection and byte
    # observation with TWO DIFFERENT signers, neither supplied as user claims.
    for envelope,expected in ((source_selection,
                               "zog-resident-b-selected-input-generation-v1"),
                              (byte_observation,
                               "zog-resident-b-installed-generation-evidence-v1")):
        if type(envelope) is not dict or envelope.get("schema")!=expected:
            _hold("wrong image-build authenticated handoff")
    selected=source_selection.get("selection")
    installed=byte_observation.get("claim")
    if (type(selected) is not dict or type(installed) is not dict or
            selected.get("generation_id")!=expected_generation or
            installed.get("generation_id")!=expected_generation or
            installed.get("state_volume_id")!=expected_state or
            installed.get("native_observation",{}).get("state_mount_id")!=expected_state or
            installed.get("native_observation",{}).get("rootfs_slot")!=evidence["selected_host_slot"] or
            selected.get("source_generation_receipt_sha256")!=
              installed.get("native_observation",{}).get("source_generation_receipt_sha256")):
        _hold("cross-owner generation/STATE receipt mismatch")
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    keys=[trusted_host_install_key,trusted_physical_observer_key,
          trusted_generation_key,trusted_installed_byte_key]
    raw_keys=[k.public_bytes(Encoding.Raw,PublicFormat.Raw) for k in keys]
    if len(set(raw_keys))!=4:
        _hold("native observer and authority keys must remain independently pinned")
    # Verify both independently signed image-build envelopes; merely checking
    # their fields would permit a forged generation/byte acceptance claim.
    for envelope, key, prefix, name in (
        (source_selection, trusted_generation_key,
         b"zog-resident-b-selected-input-generation-v1\0", "selection"),
        (byte_observation, trusted_installed_byte_key,
         b"zog-resident-b-installed-evidence-v1\0", "claim"),
    ):
        if set(envelope)!={"schema",name,"signature"}:
            _hold("incomplete image-build signed observation")
        try:
            raw=base64.b64decode(envelope["signature"],validate=True)
            if len(raw)!=64 or base64.b64encode(raw).decode()!=envelope["signature"]:
                _hold("invalid image-build signature encoding")
            key.verify(raw,prefix+canonical(envelope[name]))
        except (InvalidSignature,ValueError,TypeError,AttributeError):
            _hold("unverified source generation or installed-byte witness")
    # A source-level matching signed physical observation is NOT a kernel mount
    # inspection. Protected device/ownership attestation still awaits Work.
    return {"status":"CROSS_OWNER_SIGNED_CLAIMS_MATCH_UNACCEPTED",
            "generation_accepted":None,"native_activation_allowed":False,
            "physical_mounts_independently_verified":False}
