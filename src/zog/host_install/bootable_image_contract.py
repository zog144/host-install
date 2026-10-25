"""Host-install-owned bootable resident image contract.

This module defines what an immutable image-build rootfs generation and its
separate first-boot provider must contain before host-install may call the
composition a boot candidate.  It never writes a disk and source assessment is
not native boot acceptance.
"""
from __future__ import annotations

import hashlib
import json
import re

from . import InstallError
from .artifact import upstream_verify
from .manifest import canonical, require

SCHEMA = "zog-host-install-bootable-image-contract-v1"
ARCHITECTURE = "x86_64"
GENERATION_RE = re.compile(r"[0-9a-f]{64}\Z")

BOOT_A_EXECUTABLES = (
    "usr/lib/systemd/systemd",
    "usr/lib/systemd/systemd-journald",
    "usr/lib/systemd/systemd-udevd",
    "usr/bin/systemctl",
    "usr/bin/journalctl",
    "usr/bin/udevadm",
    "usr/bin/bash",
    "usr/sbin/agetty",
    "usr/bin/login",
    "usr/bin/findmnt",
    "usr/sbin/fsck.ext4",
    "usr/bin/kmod",
)
BOOT_A_FILES = (
    "usr/lib/systemd/system/getty@.service",
    "usr/lib/systemd/system/serial-getty@.service",
    "usr/lib/systemd/boot/efi/systemd-bootx64.efi",
)
RESIDENT_B_EXECUTABLES = (
    "usr/lib/systemd/systemd-networkd",
    "usr/lib/systemd/systemd-resolved",
    "usr/lib/systemd/systemd-timesyncd",
    "usr/bin/networkctl",
    "usr/bin/resolvectl",
    "usr/bin/python3",
    "usr/bin/dbus-daemon",
    "usr/sbin/ip",
    "usr/sbin/ss",
    "usr/sbin/tc",
    "usr/sbin/mkfs.ext4",
    "usr/sbin/e2fsck",
    "usr/bin/host-install",
    "usr/bin/host-discover",
    "usr/bin/box-control",
    "usr/bin/root-control",
)
RESIDENT_B_FILES = (
    "usr/lib/systemd/system/dbus.service",
)
FAIL_CLOSED_MOUNTPOINTS = {
    "state": 0o000,
    "applications": 0o000,
}

IMAGE_BUILD_VERIFICATIONS = (
    "canonical-generation-provenance",
    "rootfs-exact-inventory-and-hashes",
    "systemd-core-installed-plus-seccomp",
    "host-boot-packages-installed",
    "python-ssl-and-sqlite",
    "public-ca-trust-store",
    "kmod-native",
    "efi-loader-exact-bytes",
    "foreign-kernel-initramfs-modules-provenance",
    "initramfs-root-partuuid-readonly-switch-root",
)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def contract():
    value = {
        "schema": SCHEMA,
        "architecture": ARCHITECTURE,
        "generation": {
            "producer": "image-build",
            "kind": "rootfs",
            "immutable": True,
            "canonical_provenance_required": True,
            "host_specific_state_forbidden": True,
            "missing_rootfs_components_require_new_generation": True,
        },
        "disk": {
            "partition_table": "gpt",
            "roles": ["ESP", "HOST-A", "HOST-B", "STATE", "APPLICATIONS"],
            "filesystems": {
                "ESP": "fat32",
                "HOST-A": "ext4",
                "HOST-B": "ext4",
                "STATE": "ext4",
                "APPLICATIONS": "ext4",
            },
            "host_slots_equal_capacity": True,
            "selected_root_by": "PARTUUID",
            "selected_root_read_only": True,
            "state_mount": "/state",
            "applications_mount": "/applications",
            "state_and_applications_writable": True,
        },
        "boot_provider": {
            "firmware": "uefi",
            "efi_loader": {
                "source": "selected-rootfs-generation",
                "path": "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
                "installer_copies_exact_bytes_to_esp": True,
            },
            "first_pass_kernel": {
                "profile": "foreign-amazon-linux-2023-v1",
                "separate_boot_bundle": True,
                "required_members": ["kernel", "initramfs", "modules/<kernel-release>/"],
                "zog_built_kernel_required": False,
            },
            "kernel_command_line": {
                "root": "root=PARTUUID=<selected-HOST-partuuid>",
                "root_read_only_argument": "ro",
                "host_specific_generation_data_must_not_enter_rootfs": True,
            },
            "initramfs_required_capabilities": [
                "discover-selected-root-by-PARTUUID",
                "mount-ext4-root-read-only",
                "load-required-nvme-or-virtio-storage-driver",
                "switch-root-to-/usr/lib/systemd/systemd",
            ],
        },
        "rootfs": {
            "boot_a_required_executables": list(BOOT_A_EXECUTABLES),
            "boot_a_required_files": list(BOOT_A_FILES),
            "resident_b_required_executables": list(RESIDENT_B_EXECUTABLES),
            "resident_b_required_files": list(RESIDENT_B_FILES),
            "fail_closed_empty_mountpoints": {
                "/" + name: {"owner": "root:root", "mode": f"{mode:04o}", "empty": True}
                for name, mode in FAIL_CLOSED_MOUNTPOINTS.items()
            },
            "persistent_host_identity_forbidden": True,
            "machine_id_must_not_be_preprovisioned": True,
            "host_private_keys_forbidden": True,
        },
        "runtime_mounts": {
            "/": {"source": "selected-HOST-slot", "read_only": True},
            "/state": {"source": "STATE", "read_only": False, "required_for_resident_b": True},
            "/applications": {
                "source": "APPLICATIONS",
                "read_only": False,
                "required_for_resident_b": True,
            },
            "/run": {"source": "tmpfs-or-systemd-runtime", "persistent": False},
            "/tmp": {"source": "tmpfs", "persistent": False, "mode": "1777"},
            "/dev": {"source": "devtmpfs", "persistent": False},
            "/proc": {"source": "proc", "persistent": False},
            "/sys": {"source": "sysfs", "persistent": False},
        },
        "image_build_required_verifications": list(IMAGE_BUILD_VERIFICATIONS),
        "acceptance": {
            "boot_a": {
                "name": "uefi-to-systemd-pid1",
                "requires_network": False,
                "requires_station_enrollment": False,
                "requires_certificates": False,
                "success": [
                    "UEFI executes the exact reviewed loader",
                    "loader selects exact kernel/initramfs and HOST PARTUUID",
                    "kernel mounts selected HOST root read-only",
                    "PID 1 is /usr/lib/systemd/systemd",
                    "journald records the boot",
                    "serial/getty recovery path is available",
                    "host-generation report proves booted slot from live root PARTUUID",
                ],
            },
            "resident_b": {
                "name": "resident-storage-and-core-services",
                "requires_boot_a": True,
                "requires_certificates": False,
                "success": [
                    "STATE and APPLICATIONS are exact separately mounted partitions",
                    "host-install verifies STATE before private state is opened",
                    "host-install preparation succeeds without replacing identity",
                    "D-Bus/networkd/resolved and basic network tools start from the selected root",
                    "Python SSL/SQLite and CA trust checks pass",
                ],
            },
            "not_part_of_boot_acceptance": [
                "Certbot issuance",
                "ACME account creation",
                "Cloudflare credentials",
                "DNS mutation",
                "certificate publication",
                "nginx HTTPS cutover",
                "station-access graphical services",
            ],
        },
        "native_owner": "host-install+host-deploy Work",
        "source_verifier_owner": "image-build Regular",
        "production_activation_authorized": False,
    }
    validate_contract(value)
    return value


def validate_contract(value):
    require(isinstance(value, dict) and value.get("schema") == SCHEMA,
            "unsupported bootable-image contract")
    require(value.get("architecture") == ARCHITECTURE,
            "unsupported bootable-image architecture")
    require(value["disk"]["roles"] == ["ESP", "HOST-A", "HOST-B", "STATE", "APPLICATIONS"],
            "bootable-image partition roles changed")
    require(value["boot_provider"]["firmware"] == "uefi",
            "bootable-image firmware contract changed")
    require(value["boot_provider"]["efi_loader"]["path"] ==
            "/usr/lib/systemd/boot/efi/systemd-bootx64.efi",
            "bootable-image EFI loader contract changed")
    require(value["acceptance"]["boot_a"]["requires_certificates"] is False and
            value["acceptance"]["resident_b"]["requires_certificates"] is False,
            "certificate work cannot become a boot prerequisite")
    require(value["production_activation_authorized"] is False,
            "bootable-image source contract cannot authorize production")
    return value


def _entry_map(manifest):
    records = manifest.get("rootfs", {}).get("entries")
    require(isinstance(records, list), "verified host artifact lacks rootfs inventory")
    result = {}
    for record in records:
        require(isinstance(record, dict) and isinstance(record.get("path"), str),
                "invalid verified rootfs inventory record")
        require(record["path"] not in result, "duplicate verified rootfs path")
        result[record["path"]] = record
    return result


def _path_check(entries, path, kind, executable=False, mode=None):
    row = entries.get(path)
    if row is None:
        return {"status": "missing", "path": "/" + path}
    if row.get("kind") != kind:
        return {
            "status": "wrong-kind", "path": "/" + path,
            "expected_kind": kind, "observed_kind": row.get("kind"),
        }
    if executable and not (row.get("mode", 0) & 0o111):
        return {"status": "not-executable", "path": "/" + path}
    if mode is not None and row.get("mode") != mode:
        return {
            "status": "wrong-mode", "path": "/" + path,
            "expected_mode": f"{mode:04o}",
            "observed_mode": (
                f"{row.get('mode'):04o}" if isinstance(row.get("mode"), int) else None
            ),
        }
    return {"status": "pass", "path": "/" + path}


def assess_verified_artifact(manifest):
    """Assess a host_export.verify() result; never turns source evidence into boot PASS."""
    require(isinstance(manifest, dict) and manifest.get("schema") == 1 and
            manifest.get("kind") == "host-install-artifact",
            "unsupported verified image-build host artifact")
    generation = manifest.get("generation")
    require(isinstance(generation, dict), "verified host artifact lacks generation")
    generation_id = generation.get("generation")
    require(isinstance(generation_id, str) and GENERATION_RE.fullmatch(generation_id),
            "invalid image-build generation identity")
    inputs = generation.get("inputs")
    require(isinstance(inputs, dict) and inputs.get("architecture") == ARCHITECTURE,
            "image-build generation architecture differs")

    entries = _entry_map(manifest)
    boot_a = {}
    resident_b = {}
    for path in BOOT_A_EXECUTABLES:
        boot_a[path] = _path_check(entries, path, "file", executable=True)
    for path in BOOT_A_FILES:
        boot_a[path] = _path_check(entries, path, "file")
    for path, mode in FAIL_CLOSED_MOUNTPOINTS.items():
        check = _path_check(entries, path, "directory", mode=mode)
        if check["status"] == "pass":
            prefix = path + "/"
            if any(name.startswith(prefix) for name in entries):
                check = {"status": "not-empty", "path": "/" + path}
        boot_a[path] = check
    for path in RESIDENT_B_EXECUTABLES:
        resident_b[path] = _path_check(entries, path, "file", executable=True)
    for path in RESIDENT_B_FILES:
        resident_b[path] = _path_check(entries, path, "file")

    boot = manifest.get("boot_bundle")
    if boot is None:
        boot_bundle = {
            "status": "missing",
            "profile": "foreign-amazon-linux-2023-v1",
        }
    else:
        provenance = boot.get("provenance", {})
        structurally_matching = (
            boot.get("origin") == "foreign"
            and provenance.get("distribution") == "amazon-linux"
            and provenance.get("release") == "2023"
            and provenance.get("architecture") == ARCHITECTURE
            and isinstance(provenance.get("kernel_release"), str)
            and bool(provenance.get("kernel_release"))
        )
        boot_bundle = {
            "status": "structural-pass" if structurally_matching else "mismatch",
            "profile": "foreign-amazon-linux-2023-v1",
            "kernel_release": provenance.get("kernel_release"),
            "verified_boot_claim": boot.get("verified_boot"),
            "initramfs_capabilities": "requires-image-build-verification",
        }

    boot_missing = sorted(
        key for key, value in boot_a.items() if value["status"] != "pass"
    )
    resident_missing = sorted(
        key for key, value in resident_b.items() if value["status"] != "pass"
    )
    blockers = []
    if boot_missing:
        blockers.append("boot-a-rootfs-paths-incomplete")
    if boot_bundle["status"] != "structural-pass":
        blockers.append("foreign-boot-bundle-incomplete")
    blockers.extend([
        "image-build-verification-evidence-not-attached",
        "initramfs-root-partuuid-compatibility-not-proven",
        "native-uefi-boot-not-run",
    ])

    return {
        "schema": "zog-host-install-bootable-image-assessment-v1",
        "contract_sha256": digest(contract()),
        "artifact_id": manifest.get("artifact_id"),
        "generation": generation_id,
        "architecture": ARCHITECTURE,
        "boot_a": {
            "path_checks": boot_a,
            "missing_or_mismatched": boot_missing,
            "source_complete": not boot_missing and boot_bundle["status"] == "structural-pass",
        },
        "resident_b": {
            "path_checks": resident_b,
            "missing_or_mismatched": resident_missing,
            "source_complete": not resident_missing,
        },
        "boot_bundle": boot_bundle,
        "image_build_required_verifications": list(IMAGE_BUILD_VERIFICATIONS),
        "blockers": blockers,
        "native_boot_status": "NOT RUN",
        "production_activation_authorized": False,
    }


def assess_artifact(directory, expected_id):
    return assess_verified_artifact(upstream_verify(directory, expected_id))
