"""Real systemd-sysusers --root acceptance against an unpublished disposable HOST.

Never make a system user on the GitHub Actions runner; sysusers edits only
the ephemeral rootfs fixture. The actual native successor generation is
built separately from these source tests.
"""
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from zog.host_install import resident_accounts as service


@pytest.fixture
def rootfs(tmp_path):
    root = tmp_path / "candidate-unpublished-HOST"
    for directory in ("etc", "usr/lib/sysusers.d", "usr/lib/systemd", "usr/bin"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "usr/lib/os-release").write_text('NAME="Zog"\nID=zog\nPRETTY_NAME="Zog"\n')
    (root / "etc/os-release").symlink_to("../usr/lib/os-release")
    (root / "usr/lib/systemd/systemd").write_bytes(b"dummy native executable name")
    (root / "usr/bin/dbus-daemon").write_bytes(b"dummy native executable name")
    (root / "usr/lib/systemd/systemd").chmod(0o755)
    (root / "usr/bin/dbus-daemon").chmod(0o755)
    (root / "etc/passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
        "zog-system:x:970:970:existing fixed service account:/var/lib/zog:/usr/sbin/nologin\n"
    )
    (root / "etc/group").write_text(
        "root:x:0:\n"
        "zog-system:x:970:\n"
    )
    (root / "usr/lib/sysusers.d/systemd-journal.conf").write_text(
        "# upstream systemd 261.2\n"
        "g systemd-journal - -\n"
    )
    (root / "usr/lib/sysusers.d/dbus.conf").write_text(
        "# upstream D-Bus 1.16.2\n"
        'u messagebus - "System Message Bus" /nonexistent\n'
    )
    return root


def _tool():
    tool = shutil.which("systemd-sysusers")
    assert tool is not None, "offline systemd-sysusers needed for rootfs materialization test"
    return str(Path(tool).resolve())


def test_real_offline_sysusers_creates_only_journald_group_and_messagebus(rootfs):
    before_passwd = (rootfs / "etc/passwd").read_bytes()
    before_group = (rootfs / "etc/group").read_bytes()
    before = service.operation("inspect", rootfs)
    assert before["materialized"] is False
    assert before["before"]["messagebus_user"] is False
    assert before["before"]["systemd_journal_group"] is False
    assert before["vendor_declarations"]["systemd-journal"]["kind"] == "g"
    assert before["vendor_declarations"]["messagebus"]["kind"] == "u"

    published = service.operation("materialize", rootfs,
                                  sysusers_executable=_tool())
    assert published["materialized"] is True
    assert published["generation_published"] is False
    assert published["compiler_users_created"] is False
    assert published["after"]["all_preexisting_records_preserved"] is True
    assert published["after"]["created_users"] == ["messagebus"]
    assert published["after"]["created_groups"] == ["messagebus", "systemd-journal"]
    assert published["after"]["messagebus_uid"] > 0
    assert published["after"]["messagebus_gid"] > 0
    assert published["after"]["systemd_journal_gid"] > 0
    assert (rootfs / "etc/passwd").read_bytes().startswith(before_passwd)
    assert (rootfs / "etc/group").read_bytes().startswith(before_group)
    assert "certbot-build" not in (rootfs / "etc/passwd").read_text()
    assert "certbot-build" not in (rootfs / "etc/group").read_text()
    assert service.operation("verify", rootfs)["materialized"] is True

    # A second invocation must neither duplicate nor alter accounts.
    second = service.operation("materialize", rootfs,
                               sysusers_executable=_tool())
    assert second["after"]["created_users"] == []
    assert second["after"]["created_groups"] == []
    assert second["before"]["passwd_sha256"] == second["after"]["passwd_sha256"]
    assert second["before"]["group_sha256"] == second["after"]["group_sha256"]


def test_verify_blocks_missing_service_account_and_group(rootfs):
    with pytest.raises(service.AccountMaterializationHold,
                       match="systemd-journal group"):
        service.operation("verify", rootfs)


@pytest.mark.parametrize("fragment,replacement,match", [
    ("systemd-journal.conf", "g systemd-journal 101 -\n", "vendor sysusers directive"),
    ("dbus.conf", "u messagebus 990 \"D-Bus\" /nonexistent\n", "vendor sysusers directive"),
    ("dbus.conf", "u compiler-employee - \"D-Bus\" /nonexistent\n", "vendor sysusers directive"),
    ("dbus.conf", "u messagebus - \"D-Bus\" /nonexistent\nu extra -\n",
     "vendor sysusers directive"),
])
def test_unreviewed_vendor_declarations_refused_before_writes(
        rootfs, fragment, replacement, match):
    path = rootfs / "usr/lib/sysusers.d" / fragment
    path.write_text(replacement)
    prior = (rootfs / "etc/passwd").read_bytes()
    with pytest.raises(service.AccountMaterializationHold, match=match):
        service.operation("materialize", rootfs, sysusers_executable=_tool())
    assert (rootfs / "etc/passwd").read_bytes() == prior


def test_original_fixed_zog_accounts_preserved(rootfs):
    service.operation("materialize", rootfs, sysusers_executable=_tool())
    assert "zog-system:x:970:970:existing fixed service account" in (
        rootfs / "etc/passwd").read_text()
    assert "zog-system:x:970:" in (rootfs / "etc/group").read_text()


@pytest.mark.parametrize("relative", ("etc/passwd", "etc/group",
                                      "usr/lib/sysusers.d/dbus.conf"))
def test_symlinked_account_db_or_vendor_config_refused(rootfs, relative):
    file = rootfs / relative
    real = file.with_name(file.name + ".retained")
    file.rename(real)
    file.symlink_to(real.name)
    with pytest.raises(service.AccountMaterializationHold, match="linked"):
        service.operation("materialize", rootfs, sysusers_executable=_tool())


def test_account_databases_cannot_include_duplicate_names_or_uids(rootfs):
    with (rootfs / "etc/passwd").open("a") as stream:
        stream.write("reused:x:0:0:forged:/tmp:/bin/sh\n")
    with pytest.raises(service.AccountMaterializationHold, match="duplicate/invalid"):
        service.operation("inspect", rootfs)


def test_rejected_compiler_identity_cannot_leak_into_resident_root(rootfs):
    with (rootfs / "etc/group").open("a") as stream:
        stream.write("certbot-build-worker:x:24202:\n")
    with pytest.raises(service.AccountMaterializationHold, match="rejected dedicated compiler"):
        service.operation("inspect", rootfs)


def test_no_live_root_materialization_or_implicit_binary_selection(rootfs):
    with pytest.raises(service.AccountMaterializationHold, match="live root"):
        service.operation("materialize", Path("/"), sysusers_executable=_tool())
    with pytest.raises(service.AccountMaterializationHold,
                       match="explicit absolute"):
        service.operation("materialize", rootfs)
    with pytest.raises(service.AccountMaterializationHold, match="OS-managed"):
        service.operation("materialize", rootfs,
                          sysusers_executable=str(rootfs / "etc/passwd"))


def test_cli_requires_explicit_root_and_keeps_boot_authority_false(rootfs):
    cmd = [
        sys.executable, "-m", "zog.host_install.resident_accounts",
        "--inspect", "--root", str(rootfs),
    ]
    observed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    import json
    report = json.loads(observed.stdout)
    assert report["schema"] == service.SCHEMA
    assert report["native_boot_accepted"] is False
    assert report["generation_published"] is False


def test_materialization_source_uses_upstream_systemd_sysusers_not_useradd():
    import inspect
    source = inspect.getsource(service)
    for forbidden in (
        "useradd", "groupadd", "userdel", "runuser", "subprocess.run(user=",
        "chroot(", "sudo ", "os.chown(", "pwd.getpwuid(", "pwd.getpwnam(",
    ):
        assert forbidden not in source
    meta = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    assert 'host-install-resident-accounts = "zog.host_install.resident_accounts:main"' in meta


def test_non_zog_root_and_compatibility_symlink_refused(rootfs):
    marker = rootfs / "usr/lib/os-release"
    original = marker.read_bytes()
    marker.write_bytes(b"NAME=NotZog\nID=foreign\n")
    with pytest.raises(service.AccountMaterializationHold, match="not the reviewed Zog"):
        service.operation("inspect", rootfs)
    marker.write_bytes(original)
    link = rootfs / "etc/os-release"
    link.unlink()
    link.symlink_to("/etc/os-release")
    with pytest.raises(service.AccountMaterializationHold, match="compatibility link differs"):
        service.operation("materialize", rootfs,
                          sysusers_executable=_tool())
    assert "messagebus" not in (rootfs / "etc/passwd").read_text()


def test_world_writable_system_daemon_refused(rootfs):
    daemon = rootfs / "usr/bin/dbus-daemon"
    daemon.chmod(0o777)
    with pytest.raises(service.AccountMaterializationHold, match="system daemon"):
        service.operation("inspect", rootfs)
