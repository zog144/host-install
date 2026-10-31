import copy
import json
import subprocess
import sys

import pytest

from zog.host_install import bootable_image_contract as boot
from zog.host_install import InstallError


def entry(path, kind="file", mode=0o755):
    value = {"path": path, "kind": kind, "mode": mode, "uid": 0, "gid": 0}
    if kind == "file":
        value["sha256"] = "0" * 64
    return value


def complete_manifest():
    records = []
    seen = set()

    def add(path, kind="file", mode=0o755):
        if path not in seen:
            seen.add(path)
            records.append(entry(path, kind, mode))

    for path in boot.BOOT_A_EXECUTABLES + boot.RESIDENT_B_EXECUTABLES:
        add(path)
    for path in boot.BOOT_A_FILES + boot.RESIDENT_B_FILES:
        add(path, "file", 0o644)
    # EFI binaries are files, not POSIX executables; firmware consumes the bytes.
    efi = "usr/lib/systemd/boot/efi/systemd-bootx64.efi"
    for row in records:
        if row["path"] == efi:
            row["mode"] = 0o644
    for name, mode in boot.FAIL_CLOSED_MOUNTPOINTS.items():
        add(name, "directory", mode)

    return {
        "schema": 1,
        "kind": "host-install-artifact",
        "artifact_id": "a" * 64,
        "generation": {
            "generation": "b" * 64,
            "inputs": {"architecture": "x86_64"},
        },
        "rootfs": {"entries": records},
        "boot_bundle": {
            "origin": "foreign",
            "provenance": {
                "distribution": "amazon-linux",
                "release": "2023",
                "architecture": "x86_64",
                "kernel_release": "6.1.fixture",
            },
            "verified_boot": False,
        },
    }


def test_contract_separates_boot_and_certificate_work():
    value = boot.contract()
    assert value["schema"] == boot.SCHEMA
    assert value["disk"]["roles"] == [
        "ESP", "HOST-A", "HOST-B", "STATE", "APPLICATIONS"
    ]
    assert value["disk"]["selected_root_by"] == "PARTUUID"
    assert value["disk"]["selected_root_read_only"] is True
    assert value["boot_provider"]["firmware"] == "uefi"
    assert value["boot_provider"]["first_pass_kernel"][
        "zog_built_kernel_required"
    ] is False
    assert value["boot_provider"]["switch_root_contract"] == {
        "resident_init": "/usr/lib/systemd/systemd",
        "resident_os_tree_marker": "/usr/lib/os-release",
        "os_release_required_when_systemd_is_resident_init": True,
    }
    assert "usr/lib/os-release" in value["rootfs"]["boot_a_required_files"]
    assert value["acceptance"]["boot_a"]["requires_certificates"] is False
    assert value["acceptance"]["resident_b"]["requires_certificates"] is False
    excluded = value["acceptance"]["not_part_of_boot_acceptance"]
    assert "Certbot issuance" in excluded
    assert "nginx HTTPS cutover" in excluded
    assert value["production_activation_authorized"] is False


def test_contract_requires_fail_closed_state_and_applications_mountpoints():
    value = boot.contract()
    assert value["rootfs"]["fail_closed_empty_mountpoints"] == {
        "/state": {"owner": "root:root", "mode": "0000", "empty": True},
        "/applications": {"owner": "root:root", "mode": "0000", "empty": True},
    }
    assert value["runtime_mounts"]["/"]["read_only"] is True
    assert value["runtime_mounts"]["/state"]["read_only"] is False
    assert value["runtime_mounts"]["/applications"]["read_only"] is False
    assert value["runtime_mounts"]["/tmp"] == {
        "source": "tmpfs", "persistent": False, "mode": "1777"
    }


def test_complete_source_inventory_is_still_not_native_boot_acceptance():
    result = boot.assess_verified_artifact(complete_manifest())
    assert result["generation"] == "b" * 64
    assert result["boot_a"]["source_complete"] is True
    assert result["resident_b"]["source_complete"] is True
    assert result["boot_bundle"]["status"] == "structural-pass"
    assert result["boot_bundle"]["initramfs_capabilities"] == (
        "requires-image-build-verification"
    )
    assert result["native_boot_status"] == "NOT RUN"
    assert "native-uefi-boot-not-run" in result["blockers"]
    assert "image-build-verification-evidence-not-attached" in result["blockers"]
    assert result["production_activation_authorized"] is False


def test_missing_efi_loader_blocks_boot_a_source_gate():
    value = complete_manifest()
    value["rootfs"]["entries"] = [
        row for row in value["rootfs"]["entries"]
        if row["path"] != "usr/lib/systemd/boot/efi/systemd-bootx64.efi"
    ]
    result = boot.assess_verified_artifact(value)
    assert result["boot_a"]["source_complete"] is False
    assert "usr/lib/systemd/boot/efi/systemd-bootx64.efi" in (
        result["boot_a"]["missing_or_mismatched"]
    )


def test_missing_os_release_blocks_switch_root_source_gate():
    value = complete_manifest()
    value["rootfs"]["entries"] = [
        row for row in value["rootfs"]["entries"]
        if row["path"] != "usr/lib/os-release"
    ]
    result = boot.assess_verified_artifact(value)
    assert result["boot_a"]["source_complete"] is False
    assert result["boot_a"]["path_checks"]["usr/lib/os-release"]["status"] == "missing"
    assert "usr/lib/os-release" in result["boot_a"]["missing_or_mismatched"]
    assert "boot-a-rootfs-paths-incomplete" in result["blockers"]


def test_fail_closed_mountpoints_must_be_empty_and_mode_zero():
    value = complete_manifest()
    state = next(row for row in value["rootfs"]["entries"] if row["path"] == "state")
    state["mode"] = 0o755
    result = boot.assess_verified_artifact(value)
    assert result["boot_a"]["path_checks"]["state"]["status"] == "wrong-mode"

    value = complete_manifest()
    value["rootfs"]["entries"].append(entry("applications/unexpected"))
    result = boot.assess_verified_artifact(value)
    assert result["boot_a"]["path_checks"]["applications"]["status"] == "not-empty"


@pytest.mark.parametrize("path", [
    "usr/lib/systemd/systemd",
    "usr/sbin/agetty",
    "usr/bin/login",
    "usr/sbin/fsck.ext4",
])
def test_boot_a_executables_must_be_executable(path):
    value = complete_manifest()
    row = next(row for row in value["rootfs"]["entries"] if row["path"] == path)
    row["mode"] = 0o644
    result = boot.assess_verified_artifact(value)
    assert result["boot_a"]["path_checks"][path]["status"] == "not-executable"


def test_wrong_architecture_or_generation_identity_is_rejected():
    value = complete_manifest()
    value["generation"]["inputs"]["architecture"] = "aarch64"
    with pytest.raises(InstallError, match="architecture differs"):
        boot.assess_verified_artifact(value)

    value = complete_manifest()
    value["generation"]["generation"] = "not-a-generation"
    with pytest.raises(InstallError, match="generation identity"):
        boot.assess_verified_artifact(value)


def test_missing_foreign_boot_bundle_is_explicit_source_blocker():
    value = complete_manifest()
    value["boot_bundle"] = None
    result = boot.assess_verified_artifact(value)
    assert result["boot_bundle"]["status"] == "missing"
    assert "foreign-boot-bundle-incomplete" in result["blockers"]


def test_cli_emits_contract_without_authorizing_boot():
    run = subprocess.run(
        [sys.executable, "-m", "zog.host_install", "bootable-image-contract"],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)["result"]
    assert result == boot.contract()
    assert result["production_activation_authorized"] is False
