"""Frozen first disposable Boot A plan with its observed switch-root failure."""
from __future__ import annotations

from .manifest import require

SCHEMA = "zog-host-install-first-boot-a-plan-v1"

GENERATION = "5af34ec67cbfdcd1e7936bf70e3cf2f5c6945c7e3de5f95993918325f6e29c44"
GENERATION_MANIFEST_SHA256 = "cf469ea6d717cd325f2e9b030faabb020a4e20081e89883f1bc756e511004b37"
GENERATION_RECORD = "sha256:44f9fbe6cae969b99744ef31ddc77291aac0627a57ba3fc7aacca1fd016e0a4e"
INVENTORY = "sha256:dbdae320d2399fa24a434e1cbf7e66ff8b560bf40a2d8723ccdeff52228876d8"
ROOTFS_ARCHIVE = "sha256:0949ed621ed990562d3ed0c89502042718b12a7469defc7aa5ed70b242d8c7db"
ROOTFS_ARCHIVE_BYTES = 4188794880
CONTENT_MANIFEST = "sha256:672d83767f6a8935d3371a5fdde3f47d698a46a30fa068a39dcafd59e90b09b6"
EFI_SHA256 = "bba527f3b3d1f4dadb6d82f369cd098c886056e997492bb08048a50c2d28dc68"
EFI_BYTES = 192000
PUBLICATION_RECOVERY = "sha256:f0c3d2512670f2a64351f2711c093713843b177168f3a33aa3e19745e3027b90"
INSTALLED_VERIFICATION = "5d07c4dc5cc157ebdaab6c2fc18f15753465110620fee713b99941222e50bf78"
VERIFICATION_INVOCATION_ID = "4d2714a011b44ca28ec1a1b4273f1708"

DISK_MIB = 32768
DISK_GUID = "cfa94099-d379-5c5a-9f98-384f941cf237"

PARTITIONS = (
    ("ESP", 512, "9d57e75e-93aa-50ec-9940-4c61ad99115c", None),
    ("HOST-A", 8192, "79c78b1d-84d6-5fc4-bb31-deb9a6d7091e",
     "f18601cd-d219-5d6b-a6b0-fa499489cb63"),
    ("HOST-B", 8192, "0e93acb9-77bb-5f87-91d3-8fc35d4ac6fa",
     "41dd3ee3-f027-5cf0-a5e4-f29874b724b4"),
    ("STATE", 2048, "8d6760a1-bfe2-5bbb-8bd9-063bfaedb871",
     "656042e5-d689-5141-b94d-d99171ddfe3d"),
    ("APPLICATIONS", 2048, "7c54dcb0-f0d9-5287-892b-0604c74e18f7",
     "b8d40caf-eea2-5159-9f35-4216f3eeef12"),
)

FOREIGN_BOOT = {
    "provider": "amazon-linux-2023",
    "architecture": "x86_64",
    "kernel_release": "6.18.44-99.149.amzn2023.x86_64",
    "kernel_sha256": "1faf0278011e0d62f01b28ddf81fc32af9e3fd032be0b805a1d38d981933431b",
    "kernel_bytes": 14207224,
    "initramfs_sha256": "06bca6e41de36109384ba019212ab1be72643a578d0afb9f3fa3c561a190f599",
    "initramfs_bytes": 21381902,
    "modules_inventory_sha256": "8dbf40e1497ff8857a6a0602e66626155e897cfd54b6731aa1eea8f842899da4",
    "kernel_config_sha256": "de3812ae0e81108f86550781cac8302c8b400bf7bfefe5ea23e115074b6e0ef6",
    "dracut_package": "102-3.amzn2023.0.4.x86_64",
}


def plan():
    partitions = [
        {
            "role": role,
            "mib": mib,
            "partuuid": partuuid,
            "filesystem_uuid": filesystem_uuid,
        }
        for role, mib, partuuid, filesystem_uuid in PARTITIONS
    ]
    value = {
        "schema": SCHEMA,
        "purpose": "first-disposable-uefi-boot-a",
        "production_sizing": False,
        "device_writes_authorized": False,
        "disk": {
            "mib": DISK_MIB,
            "disk_guid": DISK_GUID,
            "partition_table": "gpt",
            "partitions": partitions,
            "unallocated_tail_allowed": True,
        },
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
                "recovery_slot": True,
            },
        },
        "generation_binding": {
            "generation": GENERATION,
            "manifest_sha256": GENERATION_MANIFEST_SHA256,
            "canonical_record": GENERATION_RECORD,
            "inventory": INVENTORY,
            "rootfs_archive": {
                "digest": ROOTFS_ARCHIVE,
                "bytes": ROOTFS_ARCHIVE_BYTES,
            },
            "content_manifest": CONTENT_MANIFEST,
            "publication_recovery": PUBLICATION_RECOVERY,
            "historical_provenance_complete": False,
            "host_boot_ready_claimed": False,
            "native_boot_disposition": "REJECTED_SWITCH_ROOT_OS_TREE_MISSING",
        },
        "esp": {
            "efi_loader_source": "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
            "efi_loader_sha256": EFI_SHA256,
            "efi_loader_bytes": EFI_BYTES,
            "root_argument": f"root=PARTUUID={partitions[1]['partuuid']}",
            "root_read_only": True,
        },
        "rootfs_materialization": {
            "source_archive": ROOTFS_ARCHIVE,
            "target_role": "HOST-A",
            "target_mib": 8192,
            "preserve_empty_fail_closed_mountpoints": {
                "/state": "0000",
                "/applications": "0000",
            },
            "required_switch_root_os_tree_marker": "/usr/lib/os-release",
        },
        "foreign_boot_provider": {
            **FOREIGN_BOOT,
            "acceptance": "WORK_PREWRITE_REVERIFY_AND_NATIVE_ACCEPT",
            "nvme_config_present": True,
            "partuuid_dispatch_source_level": True,
            "read_only_root_native_proof": True,
            "exact_pid1_switch_root_native_proof": False,
        },
        "native_acceptance": {
            "status": "FAILED_SWITCH_ROOT",
            "owner": "host-install+host-deploy Work",
            "retry_same_generation_authorized": False,
            "successor_generation_required": True,
            "observed": {
                "uefi_loader": "PASS",
                "foreign_kernel_initramfs": "PASS",
                "selected_host_a_partuuid": "PASS",
                "selected_host_a_read_only": "PASS",
                "initrd_switch_root": "FAIL_EXIT_1",
                "resident_pid1": "NOT_REACHED",
            },
            "source_blocker": {
                "generation": GENERATION,
                "missing_path": "/usr/lib/os-release",
                "contract": "systemd-switch-root-os-tree",
                "correction_owner": "image-build Regular",
            },
            "required": [
                "publish a new immutable generation containing /usr/lib/os-release",
                "bind the exact successor generation into a new host-install plan",
                "reverify exact AL2023 kernel/initramfs/modules bytes and provenance",
                "boot UEFI to the successor HOST-A PARTUUID read-only",
                "prove PID1 is /usr/lib/systemd/systemd",
                "prove journald and serial/getty recovery",
                "reboot and prove the same selected generation/STATE identities",
                "exercise rollback/recovery using HOST-B without inventing a generation",
            ],
        },
        "evidence": {
            "installed_verification_sha256": INSTALLED_VERIFICATION,
            "installed_verification_invocation_id": VERIFICATION_INVOCATION_ID,
        },
    }
    validate(value)
    return value


def validate(value):
    require(isinstance(value, dict) and value.get("schema") == SCHEMA,
            "unsupported first Boot A plan")
    require(value["selected_slot"] == "HOST-A", "first boot must select HOST-A")
    parts = value["disk"]["partitions"]
    require([p["role"] for p in parts] ==
            ["ESP", "HOST-A", "HOST-B", "STATE", "APPLICATIONS"],
            "first boot partition order changed")
    require(parts[1]["mib"] == parts[2]["mib"], "HOST slots differ in capacity")
    require(sum(p["mib"] for p in parts) + 2 <= value["disk"]["mib"],
            "first boot partitions exceed disk")
    require(value["slots"]["HOST-A"]["generation"] == GENERATION,
            "first boot generation changed")
    require(value["slots"]["HOST-B"]["generation"] is None,
            "inactive recovery slot must not invent a generation")
    require(value["esp"]["root_argument"] ==
            f"root=PARTUUID={parts[1]['partuuid']}",
            "EFI root argument is not exact HOST-A PARTUUID")
    require(value["esp"]["root_read_only"] is True,
            "first boot root must be read-only")
    require(value["device_writes_authorized"] is False,
            "source plan cannot authorize device writes")
    require(value["native_acceptance"]["status"] == "FAILED_SWITCH_ROOT",
            "first Boot A native failure disposition changed")
    require(value["native_acceptance"]["retry_same_generation_authorized"] is False and
            value["native_acceptance"]["successor_generation_required"] is True,
            "failed first Boot A generation cannot be retried as accepted input")
    require(value["generation_binding"]["native_boot_disposition"] ==
            "REJECTED_SWITCH_ROOT_OS_TREE_MISSING",
            "failed first Boot A generation disposition changed")
    require(value["rootfs_materialization"]["required_switch_root_os_tree_marker"] ==
            "/usr/lib/os-release",
            "first Boot A switch-root marker requirement changed")
    return value
