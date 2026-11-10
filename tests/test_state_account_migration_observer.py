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
            gr_name="archive-consumers",gr_gid=990,gr_mem=[]),
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
    # A lone archive-consumers NSS membership was never the original
    # service state; it must not be mistaken for a valid migration stage.
    groups["archive-consumers"].gr_mem=["host-discover"]
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="conflict"
    groups["archive-consumers"].gr_mem=[]
    groups["host-control"]=SimpleNamespace(
        gr_name="host-control",gr_gid=973,gr_mem=["host-discover"])
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="conflict"
    groups["archive-consumers"].gr_mem=["host-discover"]
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
    # Reload is meaningful only after the protected journal has committed
    # the selected unit change; no reload need may also mean no change yet.
    selected=observer.NativeNSSSystemdObserver(
        journal_stage_reader=lambda:["systemd-path-switched"])
    assert selected.stage_state("systemd-daemon-reloaded",{})=="before"
    selected.transition("systemd-daemon-reloaded")
    assert selected.stage_state("systemd-daemon-reloaded",{})=="after"
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


def test_legacy_systemd_group_grant_is_not_an_nss_membership(monkeypatch):
    _, groups=rows(monkeypatch)
    probe=observer.NativeNSSSystemdObserver()
    assert groups["archive-consumers"].gr_mem == []
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="before"
    groups["archive-consumers"].gr_mem=["host-discover"]
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="conflict"
    groups["archive-consumers"].gr_mem=[]
    assert probe.stage_state(
        "host-discover-supplementary-groups-updated",{})=="before"


def test_service_autostart_disabled_before_stop_and_reenabled_after_receipt(
        monkeypatch):
    """Durable enablement fence survives a reboot across all account stages."""
    values={"ActiveState":"active","UnitFileState":"enabled",
            "NeedDaemonReload":"no"}
    calls=[]
    def run(argv,**kwargs):
        calls.append(tuple(argv))
        if argv[0]=="systemctl" and argv[1]=="show":
            field=argv[3].split("=",1)[1]
            return SimpleNamespace(
                returncode=0,stdout=(values[field]+"\n").encode(),stderr=b"")
        if argv[1]=="disable":
            values["UnitFileState"]="disabled"
        elif argv[1]=="enable":
            values["UnitFileState"]="enabled"
        elif argv[1]=="stop":
            values["ActiveState"]="inactive"
        elif argv[1]=="start":
            values["ActiveState"]="active"
        else:
            raise AssertionError(argv)
        return SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
    monkeypatch.setattr(observer.subprocess,"run",run)
    journal={"status":"applying","active":None,"completed":[]}
    probe=observer.NativeNSSSystemdObserver(
        journal_record_reader=lambda:dict(journal),
        journal_stage_reader=lambda:journal["completed"])
    assert probe.stage_state("service-disabled",{})=="before"
    assert probe.stage_state("service-restored",{})=="before"
    probe.transition("service-disabled")
    assert values["ActiveState"]=="active"  # No downtime before boot fence.
    assert values["UnitFileState"]=="disabled"
    assert probe.stage_state("service-disabled",{})=="after"
    probe.transition("service-stopped")
    assert probe.stage_state("service-stopped",{})=="after"
    assert calls.index(("systemctl","disable","host-discover.service")) < (
        calls.index(("systemctl","stop","host-discover.service")))
    journal["completed"]=["service-disabled","service-stopped"]
    journal["active"]="service-restored"
    probe.transition("service-restored")
    assert values["UnitFileState"]=="enabled"
    assert values["ActiveState"]=="active"
    assert probe.stage_state("service-restored",{})=="after"
    assert probe.stage_state("service-disabled",{})=="after"
    journal["status"]="rolling-back"
    journal["active"]="service-restored"
    probe.transition("service-restored",rollback=True)
    assert values["UnitFileState"]=="disabled"
    assert values["ActiveState"]=="inactive"
    assert probe.stage_state("service-restored",{})=="before"
    journal["active"]="service-stopped"
    probe.transition("service-stopped",rollback=True)
    assert values["ActiveState"]=="active"
    journal["active"]="service-disabled"
    probe.transition("service-disabled",rollback=True)
    assert values["UnitFileState"]=="enabled"
    assert probe.stage_state("service-disabled",{})=="before"
