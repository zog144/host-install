import json
import subprocess
import sys

from zog.host_install import first_boot_a_plan as first


def test_first_boot_generation_and_layout_are_frozen():
    value = first.plan()
    assert value["slots"]["HOST-A"]["generation"] == (
        "5af34ec67cbfdcd1e7936bf70e3cf2f5c6945c7e3de5f95993918325f6e29c44"
    )
    assert value["slots"]["HOST-B"]["generation"] is None
    assert [p["role"] for p in value["disk"]["partitions"]] == [
        "ESP", "HOST-A", "HOST-B", "STATE", "APPLICATIONS"
    ]
    assert value["disk"]["mib"] == 32768
    assert [p["mib"] for p in value["disk"]["partitions"]] == [
        512, 8192, 8192, 2048, 2048
    ]
    assert value["esp"]["root_argument"] == (
        "root=PARTUUID=79c78b1d-84d6-5fc4-bb31-deb9a6d7091e"
    )
    assert value["esp"]["root_read_only"] is True


def test_publication_and_efi_are_exact():
    value = first.plan()
    binding = value["generation_binding"]
    assert binding["manifest_sha256"] == (
        "cf469ea6d717cd325f2e9b030faabb020a4e20081e89883f1bc756e511004b37"
    )
    assert binding["canonical_record"] == (
        "sha256:44f9fbe6cae969b99744ef31ddc77291aac0627a57ba3fc7aacca1fd016e0a4e"
    )
    assert binding["rootfs_archive"] == {
        "digest": "sha256:0949ed621ed990562d3ed0c89502042718b12a7469defc7aa5ed70b242d8c7db",
        "bytes": 4188794880,
    }
    assert value["esp"]["efi_loader_sha256"] == (
        "bba527f3b3d1f4dadb6d82f369cd098c886056e997492bb08048a50c2d28dc68"
    )
    assert binding["historical_provenance_complete"] is False
    assert binding["host_boot_ready_claimed"] is False


def test_foreign_boot_provider_is_frozen_but_not_native_accepted():
    value = first.plan()
    boot = value["foreign_boot_provider"]
    assert boot["kernel_release"] == "6.18.44-99.149.amzn2023.x86_64"
    assert boot["kernel_sha256"] == (
        "1faf0278011e0d62f01b28ddf81fc32af9e3fd032be0b805a1d38d981933431b"
    )
    assert boot["initramfs_sha256"] == (
        "06bca6e41de36109384ba019212ab1be72643a578d0afb9f3fa3c561a190f599"
    )
    assert boot["acceptance"] == "WORK_PREWRITE_REVERIFY_AND_NATIVE_ACCEPT"
    assert boot["read_only_root_native_proof"] is False
    assert boot["exact_pid1_switch_root_native_proof"] is False
    assert value["device_writes_authorized"] is False
    assert value["native_acceptance"]["status"] == "NOT RUN"


def test_cli_emits_exact_first_boot_plan():
    run = subprocess.run(
        [sys.executable, "-m", "zog.host_install", "first-boot-a-plan"],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["result"] == first.plan()
