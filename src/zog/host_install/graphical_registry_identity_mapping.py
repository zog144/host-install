"""Authenticated registry UUID -> v3 opaque 64-hex identifier bridge.

Historical host-discover/host-identify UUIDs and host-key fingerprints are
NOT hashes, conversions or substitutes for 64-hex installation identifiers.
No mapping may be minted from a missing STATE mount or another Host's STATE.
This module constructs no identity, creates no keys and never installs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import graphical_readonly_trust_broker_install as broker

SCHEMA = "zog-registry-native-identity-mapping-v1"
DOMAIN = b"zog-registry-native-identity-mapping-v1\0"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
AWS_INSTANCE = re.compile(r"i-[0-9a-f]{8,17}\Z")
AWS_VOLUME = re.compile(r"vol-[0-9a-f]{8,17}\Z")
MAPPING_FIELDS = frozenset((
    "schema", "legacy_host_uuid", "legacy_fingerprint",
    "legacy_installation_uuid", "legacy_state_uuid", "aws_instance_id",
    "aws_region", "state_volume_aws_id", "state_filesystem_uuid",
    "state_partuuid", "state_receipt_sha256", "registered_host_id",
    "installation_id", "state_volume_id", "registry_id", "controller_id",
    "registry_public_sha256", "registrar_public_sha256",
    "signed_registry_sha256", "signature_ed25519",
))
UUID_FIELDS = ("legacy_host_uuid", "legacy_installation_uuid",
               "legacy_state_uuid", "state_filesystem_uuid", "state_partuuid")
HEX_FIELDS = ("registered_host_id", "installation_id", "state_volume_id")
REGISTRY_HEX = ("registry_id", "controller_id")
NULL_UUID = "00000000-0000-0000-0000-000000000000"


def hold():
    broker.hold()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def valid_uuid(value):
    try:
        return (type(value) is str and value != NULL_UUID
                and str(uuid.UUID(value)) == value)
    except (TypeError, ValueError, AttributeError):
        return False


def verify_mapping(*, signed_mapping, registered_installation,
                   original_discover_binding, pinned_registrar_public,
                   pinned_registry_public, independently_observed_state):
    """Only validates genuine signed evidence; it cannot produce IDs.

    `independently_observed_state` is a trusted native reader's record,
    NOT data from the signed mapping, other hosts, or the gateway. If absent,
    refuse even an otherwise valid signature. Work must prove its provenance,
    storage custody, block and mount identities separately.
    """
    m=signed_mapping
    if (type(m) is not dict or set(m) != MAPPING_FIELDS
            or m.get("schema") != SCHEMA
            or type(registered_installation) is not dict
            or type(original_discover_binding) is not dict
            or type(independently_observed_state) is not dict
            or type(pinned_registrar_public) is not bytes
            or type(pinned_registry_public) is not bytes
            or len(pinned_registrar_public) != 32
            or len(pinned_registry_public) != 32
            or pinned_registrar_public == pinned_registry_public
            or any(not valid_uuid(m.get(k)) for k in UUID_FIELDS)
            or any(type(m.get(k)) is not str or not HEX64.fullmatch(m[k])
                   for k in HEX_FIELDS)
            or any(type(m.get(k)) is not str or
                   not re.fullmatch(r"[0-9a-f]{32}", m[k])
                   for k in REGISTRY_HEX)
            or type(m.get("legacy_fingerprint")) is not str
            or not FINGERPRINT.fullmatch(m["legacy_fingerprint"])
            or type(m.get("aws_instance_id")) is not str
            or not AWS_INSTANCE.fullmatch(m["aws_instance_id"])
            or type(m.get("state_volume_aws_id")) is not str
            or not AWS_VOLUME.fullmatch(m["state_volume_aws_id"])
            or type(m.get("aws_region")) is not str
            or not re.fullmatch(r"[a-z]{2}-[a-z]+-[0-9]",m["aws_region"])
            or not isinstance(m.get("state_receipt_sha256"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", m["state_receipt_sha256"])
            or m["state_receipt_sha256"]=="sha256:"+"0"*64
            or m.get("registrar_public_sha256") != sha(pinned_registrar_public)
            or m.get("registry_public_sha256") != sha(pinned_registry_public)):
        hold()
    # This must be the same previously registered UUID/fingerprint as actually
    # seen by host-discover, not a UUID5/hash/truncation compatibility guess.
    if (set(original_discover_binding) != {
            "host_uuid", "fingerprint", "installation_uuid", "state_uuid"}
            or any(original_discover_binding[k] != m[v] for k,v in (
                ("host_uuid","legacy_host_uuid"),
                ("fingerprint","legacy_fingerprint"),
                ("installation_uuid","legacy_installation_uuid"),
                ("state_uuid","legacy_state_uuid")))):
        hold()
    keys=("host_id","installation_id","state_volume_id","registry_id","controller_id")
    mapping={"host_id":"registered_host_id","installation_id":"installation_id",
             "state_volume_id":"state_volume_id","registry_id":"registry_id",
             "controller_id":"controller_id"}
    if (any(registered_installation.get(k) != m[v] for k,v in mapping.items())
            or registered_installation.get("host_fingerprint") !=
                "sha256:" + m["legacy_fingerprint"]
            or m["signed_registry_sha256"] !=
                "sha256:" + hashlib.sha256(canonical(registered_installation)).hexdigest()):
        hold()
    # Native proof must independently attest /state mount from the SAME Host.
    # A cross-Host state receipt or absent mount cannot satisfy this contract.
    expected={
        "host_uuid":m["legacy_host_uuid"],"aws_instance_id":m["aws_instance_id"],
        "aws_region":m["aws_region"],"volume_id":m["state_volume_aws_id"],
        "filesystem_uuid":m["state_filesystem_uuid"],
        "partuuid":m["state_partuuid"],"state_receipt_sha256":m["state_receipt_sha256"],
        "mountpoint":"/state","mounted":True,
    }
    if set(independently_observed_state)!=set(expected) or independently_observed_state!=expected:
        hold()
    signed={k:v for k,v in m.items() if k!="signature_ed25519"}
    try:
        sig=m["signature_ed25519"]
        if type(sig) is not str:
            hold()
        raw=base64.b64decode(sig,validate=True)
        if len(raw)!=64 or base64.b64encode(raw).decode("ascii")!=sig:
            hold()
        Ed25519PublicKey.from_public_bytes(pinned_registrar_public).verify(
            raw, DOMAIN+canonical(signed))
    except (InvalidSignature, ValueError, TypeError):
        hold()
    # The mapping does not replace independent registry signing or source
    # scope verification. No conversion of UUID IDs is permitted.
    from zog.root_control.graphical_installation_storage_authority import installation_scope
    from zog.root_control.graphical_operation_owner_source import OperationDenied
    try:
        installation_scope(registered_installation,
            pinned_registry_public=pinned_registry_public)
    except OperationDenied:
        hold()
    return {"status":"REGISTRY_IDENTITY_MAPPING_SOURCE_VALIDATED_ONLY",
            "mapped_installation_scope":False,"native_state_accepted":False,
            "native_registry_accepted":False,"storage_authorized":False,
            "broker_activation_authorized":False,"ssm_authorized":False}


def prepare_mapping_for_registrar(*, original_discover_binding,
                                  registered_installation,
                                  independently_observed_state,
                                  pinned_registrar_public,
                                  pinned_registry_public):
    """Produce UNSIGNED candidate bytes for a separately enrolled registrar.

    IDs must already be present in the authentic signed registry. This cannot
    derive a v3 identifier from a UUID/fingerprint, choose a replacement STATE,
    or sign any mapping. Work must independently read STATE/device provenance.
    """
    legacy=original_discover_binding
    registry=registered_installation
    observed=independently_observed_state
    if (type(legacy) is not dict or set(legacy)!={
            "host_uuid","fingerprint","installation_uuid","state_uuid"}
            or type(registry) is not dict or type(observed) is not dict
            or type(pinned_registrar_public) is not bytes
            or type(pinned_registry_public) is not bytes
            or len(pinned_registrar_public)!=32 or len(pinned_registry_public)!=32
            or pinned_registrar_public==pinned_registry_public
            or any(not valid_uuid(legacy.get(k)) for k in (
                "host_uuid","installation_uuid","state_uuid"))
            or type(legacy.get("fingerprint")) is not str
            or not FINGERPRINT.fullmatch(legacy["fingerprint"])):
        hold()
    # Check independently signed registry before preparing a candidate.
    from zog.root_control.graphical_installation_storage_authority import installation_scope
    from zog.root_control.graphical_operation_owner_source import OperationDenied
    try:
        installation_scope(registry,pinned_registry_public=pinned_registry_public)
    except OperationDenied:
        hold()
    if registry["host_fingerprint"]!="sha256:"+legacy["fingerprint"]:
        hold()
    expected_fields={
        "host_uuid":legacy["host_uuid"],
        "aws_instance_id":observed.get("aws_instance_id"),
        "aws_region":observed.get("aws_region"),
        "volume_id":observed.get("volume_id"),
        "filesystem_uuid":observed.get("filesystem_uuid"),
        "partuuid":observed.get("partuuid"),
        "state_receipt_sha256":observed.get("state_receipt_sha256"),
        "mountpoint":"/state","mounted":True,
    }
    if (set(observed)!=set(expected_fields) or observed!=expected_fields
            or any(type(observed.get(k)) is not str or not observed[k]
                   for k in ("volume_id","filesystem_uuid","partuuid",
                             "state_receipt_sha256"))):
        hold()
    candidate={
        "schema":SCHEMA,
        "legacy_host_uuid":legacy["host_uuid"],
        "legacy_fingerprint":legacy["fingerprint"],
        "legacy_installation_uuid":legacy["installation_uuid"],
        "legacy_state_uuid":legacy["state_uuid"],
        "aws_instance_id":observed["aws_instance_id"],
        "aws_region":observed["aws_region"],
        "state_volume_aws_id":observed["volume_id"],
        "state_filesystem_uuid":observed["filesystem_uuid"],
        "state_partuuid":observed["partuuid"],
        "state_receipt_sha256":observed["state_receipt_sha256"],
        "registered_host_id":registry["host_id"],
        "installation_id":registry["installation_id"],
        "state_volume_id":registry["state_volume_id"],
        "registry_id":registry["registry_id"],
        "controller_id":registry["controller_id"],
        "registry_public_sha256":sha(pinned_registry_public),
        "registrar_public_sha256":sha(pinned_registrar_public),
        "signed_registry_sha256":sha(canonical(registry)),
    }
    # Check format before returning bytes, but never issue signature/acceptance.
    if (set(candidate)!=(MAPPING_FIELDS-{"signature_ed25519"})
            or any(not HEX64.fullmatch(candidate[k]) for k in HEX_FIELDS)
            or any(not valid_uuid(candidate[k]) for k in UUID_FIELDS)
            or not AWS_INSTANCE.fullmatch(candidate["aws_instance_id"])
            or not AWS_VOLUME.fullmatch(candidate["state_volume_aws_id"])):
        hold()
    return {"status":"UNSIGNED_REGISTRAR_CANDIDATE_ONLY",
            "body":candidate, "domain":DOMAIN,
            "canonical_bytes":canonical(candidate),
            "native_accepted":False,
            "mapping_signed":False,"storage_authorized":False}
