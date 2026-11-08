"""Versioned directory-backed registry identity mapping candidate.

The legacy mounted-volume v1 verifier remains unchanged. V2 binds a specific
native storage backend and rejects cross-mode observations. Registrar keys are
never present here: this source only prepares unsigned canonical bytes and
checks externally signed fixtures with separately pinned public keys.

Every returned authority flag is false: verification cannot install, admit a
native Host, mint IDs, create storage or enable Task C.
"""
from __future__ import annotations

import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from . import graphical_registry_identity_mapping as v1
from . import graphical_readonly_trust_broker_install as broker

SCHEMA="zog-registry-native-identity-mapping-v2"
DOMAIN=b"zog-registry-native-identity-mapping-v2\x00"
COMMON=frozenset((
    "schema","backend","legacy_host_uuid","legacy_fingerprint",
    "legacy_installation_uuid","legacy_state_uuid","aws_instance_id",
    "aws_region","registered_host_id","installation_id","state_volume_id",
    "registry_id","controller_id","registry_public_sha256",
    "registrar_public_sha256","signed_registry_sha256","state_marker_sha256",
))
VOLUME=frozenset(("volume_id","filesystem_uuid","partuuid",
                  "mountpoint","mounted","state_mount_id","state_device"))
DIRECTORY=frozenset(("filesystem_uuid","partuuid","root_mount_id",
                     "root_device","state_device","state_inode","state_uid",
                     "state_gid","state_mode","mountpoint","mounted"))
LEGACY=frozenset(("host_uuid","fingerprint","installation_uuid","state_uuid"))

def deny():
    broker.hold()

def _binding(observed,backend):
    if type(observed) is not dict:
        deny()
    allowed=(DIRECTORY if backend=="root-directory" else VOLUME)
    if set(observed)!=allowed|{"host_uuid","aws_instance_id","aws_region",
                              "state_marker_sha256"}:
        deny()
    if observed.get("mountpoint")!="/state" or type(observed.get("mounted")) is not bool:
        deny()
    if backend=="root-directory":
        if (observed["mounted"] is not False
                or type(observed["root_mount_id"]) is not int
                or observed["root_mount_id"]<=0
                or type(observed["root_device"]) is not str
                or not observed["root_device"]
                or observed["state_device"]!=observed["root_device"]
                or type(observed["state_inode"]) is not int
                or observed["state_inode"]<=0
                or (observed["state_uid"],observed["state_gid"],
                    observed["state_mode"])!=(0,0,0o755)):
            deny()
    else:
        if (observed["mounted"] is not True
                or type(observed["state_mount_id"]) is not int
                or observed["state_mount_id"]<=0
                or type(observed["state_device"]) is not str
                or not observed["state_device"]
                or type(observed["volume_id"]) is not str
                or not v1.AWS_VOLUME.fullmatch(observed["volume_id"])):
            deny()
    if (any(not v1.valid_uuid(observed.get(k)) for k in (
            "filesystem_uuid","partuuid"))
            or type(observed.get("state_marker_sha256")) is not str
            or not observed["state_marker_sha256"].startswith("sha256:")
            or not v1.HEX64.fullmatch(observed["state_marker_sha256"][7:])
            or observed["state_marker_sha256"]=="sha256:"+"0"*64):
        deny()
    return allowed

def _shared(legacy,registry,observed,registrar_public,registry_public,backend):
    if (backend not in ("mounted-volume","root-directory")
            or type(legacy) is not dict or set(legacy)!=LEGACY
            or any(not v1.valid_uuid(legacy.get(k)) for k in (
                "host_uuid","installation_uuid","state_uuid"))
            or type(legacy.get("fingerprint")) is not str
            or not v1.FINGERPRINT.fullmatch(legacy["fingerprint"])
            or type(registry) is not dict
            or type(registrar_public) is not bytes or len(registrar_public)!=32
            or type(registry_public) is not bytes or len(registry_public)!=32
            or registrar_public==registry_public):
        deny()
    from zog.root_control.graphical_installation_storage_authority import installation_scope
    from zog.root_control.graphical_operation_owner_source import OperationDenied
    try:
        installation_scope(registry,pinned_registry_public=registry_public)
    except (OperationDenied,KeyError,TypeError,ValueError):
        deny()
    if registry.get("host_fingerprint")!="sha256:"+legacy["fingerprint"]:
        deny()
    _binding(observed,backend)
    if (observed["host_uuid"]!=legacy["host_uuid"]
            or type(observed["aws_instance_id"]) is not str
            or not v1.AWS_INSTANCE.fullmatch(observed["aws_instance_id"])
            or type(observed["aws_region"]) is not str
            or not v1.re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]",observed["aws_region"])):
        deny()
    for key in ("host_id","installation_id","state_volume_id"):
        if (type(registry.get(key)) is not str
                or not v1.HEX64.fullmatch(registry[key])):
            deny()
    for key in ("registry_id","controller_id"):
        if (type(registry.get(key)) is not str
                or not v1.re.fullmatch("[0-9a-f]{32}",registry[key])):
            deny()
    body={
        "schema":SCHEMA,"backend":backend,
        "legacy_host_uuid":legacy["host_uuid"],
        "legacy_fingerprint":legacy["fingerprint"],
        "legacy_installation_uuid":legacy["installation_uuid"],
        "legacy_state_uuid":legacy["state_uuid"],
        "aws_instance_id":observed["aws_instance_id"],
        "aws_region":observed["aws_region"],
        "registered_host_id":registry["host_id"],
        "installation_id":registry["installation_id"],
        "state_volume_id":registry["state_volume_id"],
        "registry_id":registry["registry_id"],
        "controller_id":registry["controller_id"],
        "registry_public_sha256":v1.sha(registry_public),
        "registrar_public_sha256":v1.sha(registrar_public),
        "signed_registry_sha256":v1.sha(v1.canonical(registry)),
        "state_marker_sha256":observed["state_marker_sha256"],
    }
    body.update({k:observed[k] for k in (DIRECTORY if backend=="root-directory" else VOLUME)})
    return body

def prepare_unsigned(*, legacy,registered_installation,observation,
                     backend,pinned_registrar_public,pinned_registry_public):
    body=_shared(legacy,registered_installation,observation,
                 pinned_registrar_public,pinned_registry_public,backend)
    return {"status":"UNSIGNED_BACKEND_BOUND_IDENTITY_ONLY",
            "body":body,"domain":DOMAIN,
            "canonical_bytes":v1.canonical(body),"native_accepted":False,
            "registrar_signature_present":False,"broker_admission":False}

def verify_signed(*, signed_mapping, legacy, registered_installation,
                  observation, backend, pinned_registrar_public,
                  pinned_registry_public):
    body=_shared(legacy,registered_installation,observation,
                 pinned_registrar_public,pinned_registry_public,backend)
    if (type(signed_mapping) is not dict
            or set(signed_mapping)!=set(body)|{"signature_ed25519"}
            or any(signed_mapping.get(k)!=v for k,v in body.items())):
        deny()
    try:
        encoded=signed_mapping["signature_ed25519"]
        if type(encoded) is not str:
            deny()
        sig=base64.b64decode(encoded,validate=True)
        if len(sig)!=64 or base64.b64encode(sig).decode("ascii")!=encoded:
            deny()
        Ed25519PublicKey.from_public_bytes(pinned_registrar_public).verify(
            sig,DOMAIN+v1.canonical(body))
    except (ValueError,TypeError,InvalidSignature):
        deny()
    return {"status":"BACKEND_BOUND_MAPPING_SOURCE_VERIFIED_ONLY",
            "backend":backend,"native_accepted":False,
            "checkpoint_authorized":False,"broker_admission":False,
            "ssm_authorized":False}
