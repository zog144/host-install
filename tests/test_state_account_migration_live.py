"""Verify the retained registry Host's existing systemd drop-in is not a false HOLD.

These source tests never access or alter the real systemd manager, live beacon,
privileged account database or /state. File ancestry is independently guarded
by state_account_migration_live._read_file.
"""
import pytest

from zog.host_install import state_account_migration_live as live
from zog.host_install.state_contract import StateError


PATH = "/etc/systemd/system/host-discover.service.d/registries.conf"
OVERRIDE = (
    "[Service]\n"
    "ExecStart=\n"
    "ExecStart=" + live.OLD_EXE
    + " --configuration " + live.LEGACY_CONFIG
    + " --destinations " + live.LEGACY_DESTINATIONS + "\n"
).encode()
UNIT = (
    "# /usr/lib/systemd/system/host-discover.service\n"
    "[Unit]\nDescription=Retained host-discover\n[Service]\n"
    "User=host-discover\nGroup=host-discover\n"
    "SupplementaryGroups=archive-consumers\n"
    "ReadWritePaths=/var/lib/host-discover/identity /var/lib/host-discover/credentials\n"
    "# " + PATH + "\n"
).encode() + OVERRIDE
ARGUMENTS = " ".join(live.LEGACY_ARGV)
EFFECTIVE = "{ path=" + live.OLD_EXE + " ; argv[]=" + ARGUMENTS + " ; ignore_errors=no ; }"


def observe(monkeypatch, *, dropins=PATH, source=OVERRIDE,
            effective=EFFECTIVE, published=UNIT,
            active="active", extra=None):
    values = {
        "ActiveState": active,
        "UnitFileState": "enabled",
        "User": "host-discover",
        "Group": "host-discover",
        "SupplementaryGroups": "archive-consumers",
        "ReadWritePaths": (
            "/var/lib/host-discover/identity "
            "/var/lib/host-discover/credentials"
        ),
        "DropInPaths": dropins,
        "ExecStart": effective,
        "NeedDaemonReload": "no",
    }
    if extra:
        values.update(extra)

    def systemctl(*args):
        if args[:2] == ("cat", "host-discover.service"):
            return published.decode()
        assert args[:2] == ("show", "host-discover.service")
        assert args[2].startswith("--property=")
        return values[args[2][len("--property="):]]
    opened = []
    def selected_source(path, *, size_limit=65536, required_mode=None):
        opened.append(path)
        assert size_limit == 8192
        assert path == PATH
        return source
    monkeypatch.setattr(live, "_systemctl", systemctl)
    monkeypatch.setattr(live, "_read_file", selected_source)
    return opened


def test_existing_root_controlled_legacy_dropin_preserves_beacon(monkeypatch):
    opened = observe(monkeypatch)
    unit, state = live._service()
    assert state == {"active": True, "enabled": True}
    assert opened == [PATH]
    assert unit == UNIT
    assert OVERRIDE in unit
    assert live.LEGACY_ARGV == live._effective_argv(EFFECTIVE)


def test_legacy_service_without_dropin_still_accepted(monkeypatch):
    opened = observe(monkeypatch, dropins="")
    _, state = live._service()
    assert state["active"]
    assert opened == []


@pytest.mark.parametrize("foreign_path", (
    "/run/systemd/system/host-discover.service.d/registries.conf",
    "/etc/systemd/system/other.service.d/registries.conf",
    "/etc/systemd/system/host-discover.service.d/../override.conf",
    "/etc/systemd/system/host-discover.service.d/override.service",
    "/etc/systemd/system/host-discover.service.d/malicious space.conf",
))
def test_dropin_must_be_in_selected_persistent_service_directory(
        monkeypatch, foreign_path):
    observe(monkeypatch, dropins=foreign_path)
    with pytest.raises(StateError):
        live._service()


@pytest.mark.parametrize("bad_source", (
    b"[Service]\nExecStart=/usr/bin/other --configuration original\n",
    b"[Service]\nExecStart=\nExecStart=/usr/bin/other\n",
    b"[Service]\nExecStart=\nExecStart=/usr/bin/true\n",
    b"[Service]\nExecStart=\nExecStart=/usr/bin/env " + OVERRIDE.split(b"ExecStart=")[-1],
    OVERRIDE + b"User=root\n",
    OVERRIDE + b"ReadWritePaths=/tmp\n",
    OVERRIDE + b"Environment=AUTH=alternate\n",
    OVERRIDE + b"[Unit]\nRequires=other.service\n",
    OVERRIDE + b"ExecStart=\n",
))
def test_altered_or_privilege_changing_dropin_denied(monkeypatch, bad_source):
    observe(monkeypatch, source=bad_source)
    with pytest.raises((StateError, ValueError)):
        live._service()


@pytest.mark.parametrize("effective", (
    "{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no ; }",
    "{ path=" + live.OLD_EXE + " ; argv[]=" + live.OLD_EXE
        + " --configuration /tmp/foreign.json --destinations "
        + live.LEGACY_DESTINATIONS + " ; ignore_errors=no ; }",
    "{ path=" + live.OLD_EXE + " ; argv[]=" + ARGUMENTS
        + " --once ; ignore_errors=no ; }",
    "{ path=" + live.OLD_EXE + " ; argv[]=" + ARGUMENTS
        + " ; ignore_errors=no ; } { path=" + live.OLD_EXE
        + " ; argv[]=" + ARGUMENTS + " ; ignore_errors=no ; }",
))
def test_effective_execstart_must_still_match_original(monkeypatch, effective):
    observe(monkeypatch, effective=effective)
    with pytest.raises(StateError):
        live._service()


def test_approved_file_must_appear_in_systemctl_cat(monkeypatch):
    observe(monkeypatch, published=UNIT.replace(OVERRIDE, b""))
    with pytest.raises(StateError):
        live._service()


def test_extra_dropin_or_service_mutation_denied(monkeypatch):
    observe(monkeypatch, dropins=PATH + " " + PATH)
    with pytest.raises(StateError):
        live._service()
    observe(monkeypatch, extra={"User": "root"})
    with pytest.raises(StateError):
        live._service()


def test_exact_legacy_cli_equals_forms_supported():
    value = (
        live.OLD_EXE + " --configuration=" + live.LEGACY_CONFIG
        + " --destinations=" + live.LEGACY_DESTINATIONS
    )
    assert live._legacy_argv(value) == live.LEGACY_ARGV


def test_equivalent_existing_cli_order_is_not_a_new_service(monkeypatch):
    command = (live.OLD_EXE + " --destinations " +
               live.LEGACY_DESTINATIONS + " --configuration " +
               live.LEGACY_CONFIG)
    assert live._legacy_argv(command) == live.LEGACY_ARGV
    alternate = (b"[Service]\nExecStart=\nExecStart=" +
                 command.encode() + b"\n")
    observe(monkeypatch, source=alternate,
            published=UNIT.replace(OVERRIDE, alternate),
            effective=EFFECTIVE.replace(ARGUMENTS, command))
    _, status = live._service()
    assert status["enabled"] is True


def test_extra_or_duplicate_cli_options_deny():
    for extra in (
        " --configuration " + live.LEGACY_CONFIG,
        " --once", " --managed-state", " --configuration",
    ):
        with pytest.raises(StateError):
            live._legacy_argv(ARGUMENTS + extra)


def test_systemctl_cat_preserves_final_newline_from_subprocess(monkeypatch):
    """The real subprocess path must not strip the retained drop-in's LF."""
    from types import SimpleNamespace
    calls = []
    def run(command, **kwargs):
        calls.append(tuple(command))
        if command[1] == "cat":
            data = UNIT
        else:
            data = b"active\n"
        return SimpleNamespace(returncode=0, stdout=data, stderr=b"")
    monkeypatch.setattr(live.subprocess, "run", run)
    assert live._systemctl("cat", "host-discover.service").encode() == UNIT
    assert live._systemctl("show", "host-discover.service",
                           "--property=ActiveState", "--value") == "active"
    assert UNIT.endswith(b"\n")
    assert len(calls) == 2


def test_real_systemctl_reader_does_not_false_reject_retained_dropin(monkeypatch):
    """End-to-end native observer uses untrimmed cat, normalized show."""
    from types import SimpleNamespace
    values = {
        "ActiveState": "active", "UnitFileState": "enabled",
        "User": "host-discover", "Group": "host-discover",
        "SupplementaryGroups": "archive-consumers",
        "ReadWritePaths": (
            "/var/lib/host-discover/identity "
            "/var/lib/host-discover/credentials"
        ),
        "DropInPaths": PATH, "ExecStart": EFFECTIVE,
        "NeedDaemonReload": "no",
    }
    def run(command, **kwargs):
        if command[1] == "cat":
            data = UNIT
        else:
            field = command[3].removeprefix("--property=")
            data = (values[field] + "\n").encode()
        return SimpleNamespace(returncode=0, stdout=data, stderr=b"")
    monkeypatch.setattr(live.subprocess, "run", run)
    def file_source(path, *, size_limit=65536, required_mode=None):
        assert path == PATH
        return OVERRIDE
    monkeypatch.setattr(live, "_read_file", file_source)
    data, status = live._service()
    assert data == UNIT
    assert OVERRIDE in data
    assert status == {"active": True, "enabled": True}
