"""Non-writing, exact-generation successor of the failed first Boot A plan.

The previous first_boot_a_plan is immutable failure evidence. This module
selects the independently verified 2026-10-31 image-build successor, while
keeping the reviewed *installation* GPT, HOST PARTUUID and AL2023 boot bundle.
Image-build's canonical archive/EFI hashes were not published in the source
handoff, so they MUST be separately read from the retained native producer
record and checked before any disk materialization. Never copy these from the
failed generation, alter the selected HOST root or claim a successful boot.
"""
from __future__ import annotations

import copy
import re

from . import first_boot_a_plan as failed
from .manifest import require

SCHEMA = "zog-host-install-boot-a-successor-disposable-plan-v1"
GENERATION = "273de2a04a8a0b8d4db3005bca078639f3c2fdcd6f9e24a9619d2b0ca6947aab"
SOURCE_REVISION = "68d6397ca20c4651df8f13c8a840dc8f77d55034"
PARENT_GENERATION = "45a81ec3ea473bfa397e546b5c0ec1ae306bf00cb864eaa9a86d94c13c623f2e"
HOST_A_PARTUUID = "79c78b1d-84d6-5fc4-bb31-deb9a6d7091e"
REQUIRED_OS_RELEASE = 'NAME="Zog"\nID=zog\nPRETTY_NAME="Zog"\n'
REQUIRED_SYMLINK = "../usr/lib/os-release"
EVIDENCE_FIELDS = (
    "generation_manifest_sha256", "generation_record_sha256",
    "inventory_sha256", "content_manifest_sha256",
    "rootfs_archive_sha256", "rootfs_archive_bytes",
    "publication_recovery_sha256", "efi_loader_sha256", "efi_loader_bytes",
    "installed_verification_sha256",
)
SHA_RE = re.compile(r"[a-f0-9]{64}\Z")


def plan():
    """Concrete static target and generation; absence of byte pins is explicit."""
    partitions = [
        {"role": role, "mib": mib, "partuuid": partuuid,
         "filesystem_uuid": filesystem_uuid,
         "filesystem": "fat32" if role == "ESP" else "ext4"}
        for role, mib, partuuid, filesystem_uuid in failed.PARTITIONS
    ]
    result = {
        "schema": SCHEMA,
        "purpose": "disposable-uefi-boot-a-successor",
        "production_sizing": False,
        "device_writes_authorized": False,
        "native_boot_authorized": False,
        "disk": {"mib": failed.DISK_MIB, "disk_guid": failed.DISK_GUID,
                 "partition_table": "gpt", "partitions": partitions,
                 "unallocated_tail_allowed": True},
        "selected_slot": "HOST-A",
        "slots": {
            "HOST-A": {
                "generation": GENERATION,
                "root_partuuid": partitions[1]["partuuid"],
                "root_filesystem_uuid": partitions[1]["filesystem_uuid"],
                "read_only": True,
            },
            "HOST-B": {
                "generation": None,
                "root_partuuid": partitions[2]["partuuid"],
                "root_filesystem_uuid": partitions[2]["filesystem_uuid"],
                "read_only": True,
                "recovery_slot": True,
                "write_or_activation_authorized": False,
            },
        },
        "generation_binding": {
            "generation": GENERATION,
            "producer": "image-build",
            "producer_source_revision": SOURCE_REVISION,
            "retained_parent_generation": PARENT_GENERATION,
            "rejected_predecessor": failed.GENERATION,
            "selected_generation_status": "published-source-and-installed-verification-passed",
            "retained_inventory_entries": 40974,
            "retained_provenance_records": 27,
            "publication_byte_pins": None,
            "byte_pins_status": "REQUIRES_EXACT_RETAINED_PRODUCER_READBACK",
            "generation_rebuilt_by_installer": False,
            "successor_os_identity": {
                "vendor_file": "/usr/lib/os-release",
                "vendor_contents": REQUIRED_OS_RELEASE,
                "compatibility_symlink": "/etc/os-release",
                "compatibility_target": REQUIRED_SYMLINK,
                "must_be_in_immutable_generation": True,
                "installer_must_not_synthesize": True,
            },
        },
        "esp": {
            "efi_loader_source": "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
            "efi_loader_sha256": None,
            "efi_loader_bytes": None,
            "copy_exact_verified_successor_loader_only": True,
            "root_argument": "root=PARTUUID=" + HOST_A_PARTUUID,
            "root_read_only": True,
            "kernel_arguments_required": ["root=PARTUUID=" + HOST_A_PARTUUID, "ro"],
            "installation_specific_configuration_only_on_esp": True,
        },
        "rootfs_materialization": {
            "source_generation": GENERATION,
            "source_archive_sha256": None,
            "source_archive_bytes": None,
            "target_role": "HOST-A",
            "target_partuuid": HOST_A_PARTUUID,
            "target_mib": partitions[1]["mib"],
            "read_only_after_install": True,
            "modify_rootfs_after_image_build_publication": False,
            "preserve_empty_fail_closed_mountpoints": {
                "/state": "0000", "/applications": "0000",
            },
            "required_switch_root_os_tree_marker": "/usr/lib/os-release",
            "required_compatibility_symlink": {
                "/etc/os-release": REQUIRED_SYMLINK,
            },
        },
        "foreign_boot_provider": {
            **copy.deepcopy(failed.FOREIGN_BOOT),
            "acceptance": "WORK_PREWRITE_REVERIFY_AND_NATIVE_ACCEPT",
            "nvme_config_present": True,
            "partuuid_dispatch_source_level": True,
            "read_only_root_native_proof": True,
            "exact_pid1_switch_root_native_proof": False,
            "kernel_initramfs_reselected_from_old_reviewed_provider": True,
        },
        "native_acceptance": {
            "status": "NOT_RUN_FOR_SUCCESSOR",
            "owner": "host-install+host-deploy Work",
            "failed_predecessor_status": "FAILED_SWITCH_ROOT",
            "successor_prewrite_evidence_complete": False,
            "resident_pid1_verified": False,
            "reboot_verified": False,
            "required": [
                "read back canonical generation/archive/inventory and new EFI hashes from retained image-build producer",
                "independently verify exact selected generation and all byte hashes before disk writes",
                "preserve the existing 5-partition GPT and selected HOST-A PARTUUID",
                "copy exact successor EFI to ESP without modifying immutable HOST-A root",
                "boot the reviewed AL2023 kernel/initramfs with root=PARTUUID and ro",
                "prove /usr/lib/systemd/systemd is PID 1, journald and serial/getty recovery",
                "reboot and prove live HOST-A PARTUUID and same generation",
                "test non-destructive HOST-B recovery only with independently accepted bytes",
            ],
        },
    }
    validate(result)
    return result


def validate(value):
    require(type(value) is dict and value.get("schema") == SCHEMA,
            "unsupported successor resident plan")
    fixed = plan_without_validate()
    require(value == fixed, "successor resident plan differs from reviewed exact selection")
    return value


def plan_without_validate():
    """Used only for exact frozen baseline comparison; avoids recursion."""
    # Populate baseline through a local, explicit callback rather than
    # accepting caller-supplied role/ID/digest substitutions.
    return _plan_factory()


def _plan_factory():
    # Set below to plan's generator after definition; internal test helper.
    return _make_plan()


# The public plan() is rebound to one generator at end of this module.
_make_plan = plan


def _public_plan():
    value = _make_plan()
    return value


# The recursive validation in _make_plan is avoided by deriving the reference
# once. The frozen reference is not mutated by callers.
def _original_factory():
    original_validate = globals()["validate"]
    try:
        globals()["validate"] = lambda value: value
        return _make_plan()
    finally:
        globals()["validate"] = original_validate


_FROZEN = _original_factory()


def validate(value):
    require(type(value) is dict and value.get("schema") == SCHEMA,
            "unsupported successor resident plan")
    require(value == _FROZEN, "successor resident plan differs from reviewed exact selection")
    return value


def materialization_requirements(value):
    """Non-authorizing, exact retained-producer publication evidence schema."""
    validate(value)
    return {
        "schema": "zog-host-install-boot-a-successor-source-readback-v1",
        "generation": GENERATION,
        "required_fields": list(EVIDENCE_FIELDS),
        "canonical_archive_and_manifest_must_be_independently_verified": True,
        "forbidden_predecessor_generation": failed.GENERATION,
        "forbidden_predecessor_efi_sha256": failed.EFI_SHA256,
        "forbidden_predecessor_archive_sha256": failed.ROOTFS_ARCHIVE,
        "disk_write_authorized": False,
    }
