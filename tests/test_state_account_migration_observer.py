"""Fresh NSS/systemd probes reject mismatched identities and unsafe status."""
from types import SimpleNamespace

import pytest
from zog.host_install import state_account_migration_observer as observer
from zog.host_install.state_contract import StateError


def rows(monkeypatch):
    accounts={
        "host-discover":SimpleNamespace(pw_uid=991,pw_gid=991,
             pw_dir="/home/host-discover",pw_shell="/sbin/nologin"),
    }
    groups={
        "archive-consumers":SimpleNamespace(
            gr_name="archive-consumers",gr_gid=990,gr_mem=["host-discover"]),
        "host-discover":SimpleNamespace(
            gr_name="host-discover",gr_gid=991,gr_mem=[]),
    }
    def user(name):
        if name not in accounts:raise KeyError(name)
        return accounts[name]
    def group(name):
        if name not in groups:raise KeyError(name)
        return groups[name]
    monkeypatch.setattr(observer.pwd,"getpwnam",user)
    monkeypatch.setattr(observer.grp,"getgrnam",group)
    monkeypatch.setattr(observer.grp,"getgrall",lambda:list(groups.values()))
    return accounts,groups


def test_real_nss_fields_have_before_after_and_unsafe_values(monkeypatch):
    accounts,groups=rows(monkeypatch)
    probe=observer.NativeNSSSystemdObserver()
    assert probe.stage_state("archive-consumers-gid-updated",{})=="before"
    groups["archive-consumers"].gr_gid=972
    assert probe.stage_state("archive-consumers-gid-updated",{})=="after"
    groups["archive-consumers"].gr_gid=975
    assert probe.stage_state("archive-consumers-gid-updated",{})=="conflict"
    assert probe.stage_state("host-discover-uid-updated",{})=="before"
    accounts["host-discover"].pw_uid=970
    assert probe.stage_state("host-discover-uid-updated",{})=="after"
    accounts["host-discover"].pw_uid=997
    assert probe.stage_state("host-discover-uid-updated",{})=="conflict"
    assert probe.stage_state("host-control-group-created",{})=="before"
    groups["host-control"]=SimpleNamespace(
        gr_name="host-control",gr_gid=973,gr_mem=[])
    assert probe.stage_state("host-control-group-created",{})=="after"
    assert probe.stage_state("box-control-user-created",{})=="before"
    accounts["box-control"]=SimpleNamespace(
        pw_uid=971,pw_gid=971,pw_dir="/state/box-control",
        pw_shell="/usr/sbin/nologin")
    assert probe.stage_state("box-control-user-created",{})=="after"


def test_membership_transition_exact_and_extra_groups_denied(monkeypatch):
    accounts,groups=rows(monkeypatch)
    probe=observer.NativeNSSSystemdObserver()
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="before"
    groups["host-control"]=SimpleNamespace(
        gr_name="host-control",gr_gid=973,gr_mem=["host-discover"])
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="after"
    groups["foreign"]=SimpleNamespace(
        gr_name="foreign",gr_gid=989,gr_mem=["host-discover"])
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="conflict"


def test_systemd_observer_queries_exact_unit_and_bounded_commands(monkeypatch):
    calls=[]
    active={"ActiveState":"active","NeedDaemonReload":"yes",
            "UnitFileState":"enabled"}
    def run(argv,**kwargs):
        calls.append(list(argv))
        if argv[:2]==["systemctl","show"]:
            name=argv[3].split("=",1)[-1]
            return SimpleNamespace(
                returncode=0,stdout=(active[name]+"\n").encode(),stderr=b"")
        if argv==["systemctl","stop","host-discover.service"]:
            active["ActiveState"]="inactive"
        elif argv==["systemctl","start","host-discover.service"]:
            active["ActiveState"]="active"
        elif argv==["systemctl","daemon-reload"]:
            active["NeedDaemonReload"]="no"
        else:raise AssertionError(argv)
        return SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
    monkeypatch.setattr(observer.subprocess,"run",run)
    probe=observer.NativeNSSSystemdObserver(
        journal_stage_reader=lambda:[])
    assert probe.stage_state("service-stopped",{})=="before"
    probe.transition("service-stopped")
    assert probe.stage_state("service-stopped",{})=="after"
    probe.transition("service-restored")
    assert probe.stage_state("service-restored",{})=="after"
    assert probe.stage_state("service-stopped",{})=="before"
    restored=observer.NativeNSSSystemdObserver(
        journal_stage_reader=lambda:["service-restored"])
    assert restored.stage_state("service-stopped",{})=="after"
    assert probe.stage_state("systemd-daemon-reloaded",{})=="before"
    probe.transition("systemd-daemon-reloaded")
    assert probe.stage_state("systemd-daemon-reloaded",{})=="after"
    assert all(argv[0]=="systemctl" for argv in calls)
    with pytest.raises(StateError):
        probe.transition("restart-everything")


def test_native_probe_denies_nonroot_and_unrecognized_stage(monkeypatch):
    with pytest.raises(StateError):
        observer.NativeNSSSystemdObserver(
            journal_stage_reader=lambda:[]).stage_state("foreign",{})
    monkeypatch.setattr(observer.os,"geteuid",lambda:1000)
    with pytest.raises(StateError,match="root-required"):
        observer.NativeNSSSystemdObserver()
