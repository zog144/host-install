"""Resident B cross-owner *source-only* signed evidence reconciliation.

Independent Host-install owns selected HOST slot/PARTUUID and protected STATE.
Image-build owns native installed-byte verifier. The three independently pinned
key roots and actual kernel/partition/ownership evidence MUST come from
protected Host-install native adapters, never receipt-controlled configuration.
This module cannot accept a generation, activate a service or write a device.
"""
from __future__ import annotations

import base64
import re
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .bootable_image_contract import contract as resident_contract, digest as contract_digest
from .state_contract import canonical

SCHEMA="zog-host-install-resident-b-native-handoff-v1"
OBS_SCHEMA="zog-resident-b-installed-generation-evidence-v1"
SEL_SCHEMA="zog-resident-b-selected-input-generation-v1"
MOUNT_SCHEMA="zog-host-install-resident-b-protected-live-mount-v1"
OLD_REJECTED="5af34ec67cbfdcd1e7936bf70e3cf2f5c6945c7e3de5f95993918325f6e29c44"
CONTROLLERS={"box-control":"b513a9bde79135c7569adc7cadb4d45a163c7841",
             "root-control":"0c217182d25f05b9cc0f7528ee614bb5669370d3"}
REQUIRED_OUTPUTS={
    "usr/bin/python3.12",
    "usr/lib/libpython3.12.so.1.0",
    "usr/lib/python3.12/lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so",
    "usr/lib/python3.12/lib-dynload/_sqlite3.cpython-312-x86_64-linux-gnu.so",
    "usr/lib/python3.12/lib-dynload/_hashlib.cpython-312-x86_64-linux-gnu.so",
    "usr/bin/box-control","usr/bin/root-control",
    "usr/lib/systemd/system/zog-root-control.service",
    "usr/lib/python3.12/site-packages/box_control-0.1.0.dist-info/METADATA",
    "usr/lib/python3.12/site-packages/box_control-0.1.0.dist-info/RECORD",
    "usr/lib/python3.12/site-packages/root_control-0.1.0.dist-info/METADATA",
    "usr/lib/python3.12/site-packages/root_control-0.1.0.dist-info/RECORD",
}
SHA=re.compile(r"[0-9a-f]{64}\Z")
PARTITION_DEVID=re.compile(r"[0-9]+:[0-9]+\Z")
SIGNATURE_DOMAINS={
    "selection":b"zog-resident-b-selected-input-generation-v1\x00",
    "installed":b"zog-resident-b-installed-evidence-v1\x00",
    "mount":b"zog-host-install-resident-b-protected-live-mount-v1\x00",
}

class HandoffDenied(ValueError):pass
def reject(text):raise HandoffDenied("Resident B protected handoff NO-GO: "+text)
def exact(value,fields,name):
    if type(value) is not dict or set(value)!=set(fields):
        reject("unexpected fields in "+name)
def sha(value):
    if type(value) is not str or SHA.fullmatch(value) is None:
        reject("missing original SHA-256 identity")
    return value
def ident(value):
    try:
        if type(value) is not str or str(UUID(value))!=value or UUID(value).int==0:
            reject("invalid canonical installation/STATE/PARTUUID")
    except (TypeError,AttributeError,ValueError):
        reject("invalid canonical installation/STATE/PARTUUID")
    return value
def device(value):
    if type(value) is not str or not PARTITION_DEVID.fullmatch(value):
        reject("missing actual kernel block-device major:minor identity")
    return value
def verify_signed(envelope,key,role,schema,shape):
    exact(envelope,("schema","claim" if role!="selection" else "selection","signature"),role)
    if envelope["schema"]!=schema:reject("wrong signed "+role+" schema")
    field="selection" if role=="selection" else "claim"
    claim=envelope[field]
    exact(claim,shape,role)
    if type(envelope["signature"]) is not str:reject("missing signed "+role)
    try:
        raw=base64.b64decode(envelope["signature"],validate=True)
        if len(raw)!=64 or base64.b64encode(raw).decode()!=envelope["signature"]:
            reject("malformed detached "+role+" signature")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            raw,SIGNATURE_DOMAINS[role]+canonical(claim))
    except (ValueError,TypeError,InvalidSignature,AttributeError) as error:
        raise HandoffDenied("unverified independent "+role+" signature") from error
    return claim

def verify(handoff,protected_pins):
    """Reconcile signed claims with separately protected pins, never grant admission.

    Caller MUST independently obtain protected_pins from an authenticated,
    root-owned host-install selection + STATE evidence. Its JSON shape here is
    NOT a substitute for verifying those source/permission/revocation facts.
    """
    exact(handoff,("schema","status","selection","installed","mount","authority"),"handoff")
    if handoff["schema"]!=SCHEMA or handoff["status"]!="SOURCE_HANDOFF_NATIVE_NO_GO":
        reject("unreviewed handoff status")
    exact(protected_pins,(
        "schema","host_id","installation_id","operation_id","state_volume_id",
        "selected_slot","generation_id","source_receipt_sha256","rootfs_manifest_sha256",
        "root_partuuid","root_devid","state_partuuid","state_filesystem_uuid",
        "state_devid","applications_partuuid","applications_devid",
        "bootable_contract_sha256","selection_key","installed_key","mount_key",
        "service_uid","service_gid"),"independently protected host-install pins")
    if protected_pins["schema"]!="zog-host-install-resident-b-external-pins-v1":
        reject("noncanonical protected selection schema")
    for key in ("host_id","installation_id","operation_id","state_volume_id",
                "root_partuuid","state_partuuid","state_filesystem_uuid",
                "applications_partuuid"):
        ident(protected_pins[key])
    for key in ("generation_id","source_receipt_sha256","rootfs_manifest_sha256","bootable_contract_sha256"):
        sha(protected_pins[key])
    if (protected_pins["generation_id"]==OLD_REJECTED or
        protected_pins["bootable_contract_sha256"]!=contract_digest(resident_contract()) or
        protected_pins["selected_slot"] not in ("HOST-A","HOST-B")):
        reject("previously rejected generation, wrong OS contract or unselected root slot")
    for key in ("root_devid","state_devid","applications_devid"):
        device(protected_pins[key])
    if len({protected_pins[k] for k in ("root_devid","state_devid","applications_devid")})!=3:
        reject("rootfs, STATE and APPLICATIONS cannot share device identity")
    if protected_pins["service_uid"]!=0 or protected_pins["service_gid"]!=0:
        reject("privileged root-control service not root-owned")
    keys=[]
    for key in ("selection_key","installed_key","mount_key"):
        try:
            raw=bytes.fromhex(protected_pins[key])
        except (TypeError,ValueError) as exc:
            raise HandoffDenied("missing protected signer key") from exc
        if len(raw)!=32:reject("wrong Ed25519 signer key length")
        keys.append(raw)
    if len(set(keys))!=3:reject("native worker, mount observer and generation selector share authority")
    selection=verify_signed(handoff["selection"],protected_pins["selection_key"],
        "selection",SEL_SCHEMA,("generation_id","source_generation_receipt_sha256",
                              "selection_status","native_boot_authorized",
                              "root_control_activation_authorized"))
    if (selection["generation_id"]!=protected_pins["generation_id"] or
        selection["source_generation_receipt_sha256"]!=protected_pins["source_receipt_sha256"] or
        selection["selection_status"]!="accepted-as-input" or
        selection["native_boot_authorized"] is not False or
        selection["root_control_activation_authorized"] is not False):
        reject("substituted generation or forged selection authorization")
    installed=verify_signed(handoff["installed"],protected_pins["installed_key"],
        "installed",OBS_SCHEMA,("generation_id","state_volume_id","source_pins","files",
          "modules","python_version","state_permissions","service_permissions",
          "wheels","native_observation","status","accepted"))
    if (installed["generation_id"]!=selection["generation_id"] or
        installed["state_volume_id"]!=protected_pins["state_volume_id"] or
        installed["source_pins"]!=CONTROLLERS or
        installed["python_version"]!="3.12.16" or
        installed["status"]!="observed" or installed["accepted"] is not False):
        reject("observed bytes mismatch original selected sources or generation")
    native=installed["native_observation"]
    exact(native,("rootfs_slot","rootfs_readonly","state_mount_id",
                  "source_generation_receipt_sha256","observed_by","observation_id"),
                  "native worker observation")
    if (native["rootfs_slot"]!=protected_pins["selected_slot"] or
        native["rootfs_readonly"] is not True or
        native["state_mount_id"]!=protected_pins["state_volume_id"] or
        native["source_generation_receipt_sha256"]!=protected_pins["source_receipt_sha256"] or
        not native["observed_by"] or not native["observation_id"]):
        reject("source generation or STATE identity disagrees with native worker")
    expected_modules={"_ssl","_sqlite3","_hashlib"}
    if type(installed["modules"]) is not dict or set(installed["modules"])!=expected_modules:
        reject("missing native SSL/SQLite/hashlib modules")
    for name,p in installed["modules"].items():
        if p!="usr/lib/python3.12/lib-dynload/"+name+".cpython-312-x86_64-linux-gnu.so":
            reject("wrong Python extension SOABI")
    files=installed["files"]
    if type(files) is not list or not files:reject("no native installed byte inventory")
    outputs={}
    for item in files:
        exact(item,("path","sha256","size","mode","kind"),"installed-byte file")
        name=item["path"]
        if name in outputs or type(name) is not str or ".." in name.split("/") or not name.startswith("usr/"):
            reject("unsafe or repeated installed file")
        sha(item["sha256"])
        if type(item["size"]) is not int or item["size"]<1:reject("unverified installed byte size")
        outputs[name]=item
    if not REQUIRED_OUTPUTS.issubset(outputs):
        reject("incomplete installed interpreter, wheel or systemd output")
    unit=outputs["usr/lib/systemd/system/zog-root-control.service"]
    if unit["mode"]!=0o644 or type(unit["sha256"]) is not str:
        reject("unexpected privileged root-control unit mode/hash")
    if installed["service_permissions"]!={"unit_mode":0o644,"socket_mode":0o660,
         "socket_uid":0,"socket_gid_provisioned":True,"service_enabled":False}:
        reject("root-control unit/socket ownership or activation evidence incomplete")
    if type(installed["wheels"]) is not dict or set(installed["wheels"])!={"box_control-0.1.0","root_control-0.1.0"}:
        reject("missing installed wheel RECORD evidence")
    for name, wheel in installed["wheels"].items():
        exact(wheel,("record_sha256","record_members"),"installed wheel")
        sha(wheel["record_sha256"])
        base=name+".dist-info/"
        must={base+"METADATA",base+"WHEEL",base+"entry_points.txt",
              base+"RECORD","../../../bin/"+name.split("-0.1.0")[0].replace("_","-")}
        members=wheel["record_members"]
        if (type(members) is not list or
            len(members)!=len(set(members)) or not must.issubset(set(members))):
            reject("incomplete wheel RECORD member inventory")
    mounted=verify_signed(handoff["mount"],protected_pins["mount_key"],
        "mount",MOUNT_SCHEMA,(
            "host_id","installation_id","operation_id","selected_slot","generation_id",
            "source_receipt_sha256","rootfs_manifest_sha256","root_partuuid",
            "root_devid","root_read_only","state_volume_id","state_partuuid",
            "state_filesystem_uuid","state_devid","state_mount_verified",
            "applications_partuuid","applications_devid","applications_mount_verified",
            "root_control_unit_sha256","root_control_unit_mode","root_control_uid",
            "root_control_gid","root_control_enabled","state_uid","state_gid",
            "state_mode","physical_inspection_status"))
    for field in ("host_id","installation_id","operation_id","selected_slot","generation_id",
                  "source_receipt_sha256","rootfs_manifest_sha256","root_partuuid",
                  "root_devid","state_volume_id","state_partuuid","state_filesystem_uuid",
                  "state_devid","applications_partuuid","applications_devid"):
        if mounted[field]!=protected_pins[field]:
            reject("protected live selected generation, root PARTUUID or mount changed: "+field)
    if (mounted["root_read_only"] is not True or
        mounted["state_mount_verified"] is not True or
        mounted["applications_mount_verified"] is not True or
        mounted["physical_inspection_status"]!="PROTECTED_KERNEL_MOUNT_OBSERVED" or
        mounted["root_control_unit_sha256"]!=unit["sha256"] or
        mounted["root_control_unit_mode"]!=0o644 or
        mounted["root_control_uid"]!=0 or mounted["root_control_gid"]!=0 or
        mounted["root_control_enabled"] is not False or
        mounted["state_uid"]!=0 or mounted["state_gid"]!=0 or
        mounted["state_mode"]!=0o755):
        reject("unverified physical root/STATE/APPLICATIONS or privileged service")
    # The mounted /state root is mode 0755 in host-install; the *separate*
    # private root-controlled directory carried by the worker claim stays 0700.
    # This field is not evidence that /state itself has mode 0700.
    if installed["state_permissions"]!={"state_mode":0o700,
                                        "private_uid":0,"state_authenticated":True}:
        reject("native worker did not observe protected private STATE")
    exact(handoff["authority"],("generation_accepted","boot_authorized",
                               "root_control_activation_allowed","worker_submission_allowed",
                               "rights_approved"),"handoff authority denial")
    if any(handoff["authority"][k] is not False for k in (
        "boot_authorized","root_control_activation_allowed",
        "worker_submission_allowed","rights_approved")) or (
        handoff["authority"]["generation_accepted"] is not None):
        reject("source-only handoff fabricated acceptance or authority")
    return {"handoff":"EXACT_SOURCE_EVIDENCE_CROSS_OWNER_CONSISTENT",
            "native_generation_accepted":None,"resident_b_boot_authorized":False,
            "root_control_service_enabled":False,"rights_approved":False}



def inspect_protected_host_generation_context(context, protected_pins):
    """Native-only reconciliation of actual host-install VerifiedState.

    Requires a live verified STATE fd and an independently determined live root
    PARTUUID, not an object reconstructed from an evidence receipt. This does
    not itself authenticate protected_pins or accept an installed generation.
    """
    from .state_inspect import VerifiedState, host_generation_report
    if type(context) is not VerifiedState:
        reject("real host-install VerifiedState context required, never caller JSON")
    context.recheck()
    bundle=context.bundle
    if bundle["installation"]["schema"] not in (1,2):
        reject("unselected installation record")
    report=host_generation_report(context)
    if (report["schema"]!=1 or
        report["source"]!="verified-host-install-state-v1" or
        report["installation"]["installation_id"]!=protected_pins["installation_id"] or
        report["selected_slot"]!=protected_pins["selected_slot"] or
        report["booted_slot"]!=protected_pins["selected_slot"] or
        report["slots"][protected_pins["selected_slot"]]!={"generation":protected_pins["generation_id"],
           "root_partuuid":protected_pins["root_partuuid"]}):
        reject("actual live selected HOST PARTUUID/generation differs")
    marker=bundle["marker"]
    if (marker["installation_id"]!=protected_pins["installation_id"] or
        marker["state_volume_id"]!=protected_pins["state_volume_id"] or
        marker["partition_partuuid"]!=protected_pins["state_partuuid"] or
        marker["filesystem_uuid"]!=protected_pins["state_filesystem_uuid"] or
        context.mount["target"]!="/state" or
        context.mount["device"]!=protected_pins["state_devid"] or
        "rw" not in context.mount["options"]):
        reject("actual verified persistent STATE partition differs")
    context.recheck()
    return {"native_root_partuuid":"HOST_INSTALL_VERIFIED",
            "state_context":"HOST_INSTALL_VERIFIED",
            "applications_mount":"REQUIRES_SEPARATE_PROTECTED_OBSERVATION",
            "generation_accepted":None,"service_authorized":False}
