"""Frozen corrected Boot A successor installation selection; no device writes."""
import copy
import json
import subprocess
import sys

import pytest

from zog.host_install import first_boot_a_plan as failed
from zog.host_install import successor_boot_a_plan as successor
from zog.host_install import InstallError


def test_exact_published_successor_replaces_only_selected_generation():
    old = failed.plan()
    value = successor.plan()
    assert value["generation_binding"]["generation"] == (
        "273de2a04a8a0b8d4db3005bca078639f3c2fdcd6f9e24a9619d2b0ca6947aab")
    assert value["slots"]["HOST-A"]["generation"] == successor.GENERATION
    assert value["slots"]["HOST-B"]["generation"] is None
    assert old["slots"]["HOST-A"]["generation"] == failed.GENERATION
    assert value["generation_binding"]["rejected_predecessor"] == failed.GENERATION
    assert value["generation_binding"]["producer_source_revision"] == (
        "68d6397ca20c4651df8f13c8a840dc8f77d55034")
    assert value["generation_binding"]["retained_parent_generation"] == (
        "45a81ec3ea473bfa397e546b5c0ec1ae306bf00cb864eaa9a86d94c13c623f2e")
    assert value["generation_binding"]["retained_inventory_entries"] == 40974
    assert value["generation_binding"]["retained_provenance_records"] == 27
    assert value["device_writes_authorized"] is False
    assert value["native_boot_authorized"] is False
    assert value["native_acceptance"]["status"] == "NOT_RUN_FOR_SUCCESSOR"


def test_exact_disposable_5_partition_selection_and_readonly_root():
    value = successor.plan()
    assert value["disk"]["partition_table"] == "gpt"
    assert value["disk"]["disk_guid"] == failed.DISK_GUID
    assert value["disk"]["mib"] == 32768
    assert [(p["role"], p["mib"]) for p in value["disk"]["partitions"]] == [
        ("ESP", 512), ("HOST-A", 8192), ("HOST-B", 8192),
        ("STATE", 2048), ("APPLICATIONS", 2048)]
    assert [(p["role"], p["partuuid"], p["filesystem_uuid"]) for p in
            value["disk"]["partitions"]] == [
        (role, partuuid, uuid) for role, _, partuuid, uuid in failed.PARTITIONS]
    assert [p["filesystem"] for p in value["disk"]["partitions"]] == [
        "fat32", "ext4", "ext4", "ext4", "ext4"]
    assert value["slots"]["HOST-A"]["root_partuuid"] == successor.HOST_A_PARTUUID
    assert value["slots"]["HOST-A"]["read_only"] is True
    assert value["slots"]["HOST-B"]["recovery_slot"] is True
    assert value["slots"]["HOST-B"]["write_or_activation_authorized"] is False
    assert value["esp"]["root_argument"] == (
        "root=PARTUUID=79c78b1d-84d6-5fc4-bb31-deb9a6d7091e")
    assert value["esp"]["kernel_arguments_required"] == [
        value["esp"]["root_argument"], "ro"]
    assert value["esp"]["root_read_only"] is True
    assert value["rootfs_materialization"]["target_partuuid"] == successor.HOST_A_PARTUUID
    assert value["rootfs_materialization"]["read_only_after_install"] is True
    assert value["rootfs_materialization"]["modify_rootfs_after_image_build_publication"] is False
    assert value["rootfs_materialization"]["preserve_empty_fail_closed_mountpoints"] == {
        "/state": "0000", "/applications": "0000"}
    assert value["disk"]["unallocated_tail_allowed"] is True
    assert sum(p["mib"] for p in value["disk"]["partitions"]) + 2 <= 32768


def test_boot_bundle_is_same_reviewed_al2023_kernel_initramfs_modules_not_fake_new():
    old = failed.plan()
    value = successor.plan()
    boot = value["foreign_boot_provider"]
    for field, expected in failed.FOREIGN_BOOT.items():
        assert boot[field] == expected
    assert boot["kernel_sha256"] == "1faf0278011e0d62f01b28ddf81fc32af9e3fd032be0b805a1d38d981933431b"
    assert boot["initramfs_sha256"] == "06bca6e41de36109384ba019212ab1be72643a578d0afb9f3fa3c561a190f599"
    assert boot["kernel_release"] == "6.18.44-99.149.amzn2023.x86_64"
    assert boot["modules_inventory_sha256"] == (
        "8dbf40e1497ff8857a6a0602e66626155e897cfd54b6731aa1eea8f842899da4")
    assert boot["read_only_root_native_proof"] is True
    assert boot["exact_pid1_switch_root_native_proof"] is False
    assert old["foreign_boot_provider"]["kernel_sha256"] == boot["kernel_sha256"]


def test_switchover_marker_and_exact_immutable_os_release_not_synthesized_by_installer():
    value = successor.plan()
    identity = value["generation_binding"]["successor_os_identity"]
    assert identity == {
        "vendor_file": "/usr/lib/os-release",
        "vendor_contents": 'NAME="Zog"\nID=zog\nPRETTY_NAME="Zog"\n',
        "compatibility_symlink": "/etc/os-release",
        "compatibility_target": "../usr/lib/os-release",
        "must_be_in_immutable_generation": True,
        "installer_must_not_synthesize": True}
    assert value["rootfs_materialization"]["required_switch_root_os_tree_marker"] == (
        "/usr/lib/os-release")


def test_failed_generation_byte_hashes_must_not_be_invented_or_reused():
    value = successor.plan()
    old = failed.plan()
    binding = value["generation_binding"]
    assert binding["publication_byte_pins"] is None
    assert binding["byte_pins_status"] == "REQUIRES_EXACT_RETAINED_PRODUCER_READBACK"
    assert value["esp"]["efi_loader_sha256"] is None
    assert value["esp"]["efi_loader_bytes"] is None
    assert value["rootfs_materialization"]["source_archive_sha256"] is None
    assert value["rootfs_materialization"]["source_archive_bytes"] is None
    assert old["esp"]["efi_loader_sha256"] != value["esp"]["efi_loader_sha256"]
    assert old["generation_binding"]["rootfs_archive"]["digest"] != (
        value["rootfs_materialization"]["source_archive_sha256"])
    evidence = successor.materialization_requirements(value)
    assert evidence["generation"] == successor.GENERATION
    assert evidence["disk_write_authorized"] is False
    assert evidence["forbidden_predecessor_generation"] == failed.GENERATION
    assert evidence["forbidden_predecessor_efi_sha256"] == failed.EFI_SHA256
    assert set(evidence["required_fields"]) == set(successor.EVIDENCE_FIELDS)


@pytest.mark.parametrize("field,new_value", [
    ("selected_slot", "HOST-B"),
    ("device_writes_authorized", True),
    ("native_boot_authorized", True),
    ("slots", {"HOST-A": {"generation": failed.GENERATION}}),
    ("esp", {"root_argument": "root=/dev/nvme0n1p2", "root_read_only": False}),
    ("generation_binding", {"generation": failed.GENERATION}),
    ("foreign_boot_provider", {"kernel_sha256": "a" * 64}),
    ("rootfs_materialization", {"modify_rootfs_after_image_build_publication": True}),
])
def test_any_unreviewed_changed_selection_fails(field, new_value):
    value = successor.plan()
    value[field] = new_value
    with pytest.raises(InstallError, match="differs"):
        successor.validate(value)


def test_returned_plan_is_a_copy_and_legacy_failure_evidence_unchanged():
    original = failed.plan()
    selected = successor.plan()
    selected["disk"]["partitions"][1]["partuuid"] = "not-original"
    assert successor.plan()["disk"]["partitions"][1]["partuuid"] == successor.HOST_A_PARTUUID
    assert failed.plan() == original


def test_cli_emits_concrete_nonwriting_successor_plan():
    run = subprocess.run(
        [sys.executable, "-m", "zog.host_install", "successor-boot-a-plan"],
        capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["result"] == successor.plan()


def test_repo_disposable_example_equals_programmatic_plan():
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / (
        "examples/resident-boot-a-successor-2026-10-31/plan.json")
    assert json.loads(path.read_text()) == successor.plan()
