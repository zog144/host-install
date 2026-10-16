import json
import os
from pathlib import Path

import pytest

from zog.host_install import application_progress_profile as profile
from zog.host_install.state_contract import StateError


def empty_policy(tmp_path):
    path = tmp_path / "host-bindings.json"
    path.write_text(json.dumps({"schema": 1, "bindings": []}))
    return path


def test_merge_preserves_existing_entries_and_adds_exact_station_web_capability():
    existing = {
        "schema": 1,
        "bindings": [{
            "project": "/home/controller/project",
            "application": "archive-mirror",
            "program": "server",
            "capability": "mirror-live",
            "source": "/run/zog-host-export/mirror-live",
        }],
    }
    merged = profile.merge_host_bindings(
        json.dumps(existing).encode(), "/home/controller/project"
    )
    assert existing["bindings"][0] in merged["bindings"]
    progress = [row for row in merged["bindings"]
                if row["capability"] == "application-progress"]
    assert progress == [{
        "project": "/home/controller/project",
        "application": "station-access",
        "program": "web",
        "capability": "application-progress",
        "source": "/run/zog-host-export/application-progress",
    }]


def test_merge_is_idempotent_and_conflicting_capability_fails():
    project = "/home/controller/project"
    first = profile.merge_host_bindings(
        json.dumps({"schema": 1, "bindings": []}).encode(), project
    )
    second = profile.merge_host_bindings(
        json.dumps(first).encode(), project
    )
    assert second == first

    broken = json.loads(json.dumps(first))
    row = next(item for item in broken["bindings"]
               if item["capability"] == "application-progress")
    row["source"] = "/run/zog-host-export/wrong"
    with pytest.raises(StateError, match="disagrees"):
        profile.merge_host_bindings(json.dumps(broken).encode(), project)


def test_stage_uses_actual_numeric_station_uid_without_account_lookup(tmp_path, monkeypatch):
    policy = empty_policy(tmp_path)
    output = tmp_path / "overlay"
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)

    result = profile.stage(
        output=output,
        controller_project="/home/controller/zog-project",
        station_uid=12031,
        station_gid=12032,
        controller_uid=11021,
        controller_gid=11022,
        host_bindings_policy=policy,
        producer_source=Path(__file__).resolve().parents[1],
    )
    assert result["station_consumer_uid"] == 12031
    assert result["controller_uid"] == 11021
    units = output / "etc/systemd/system"
    socket = (units / profile.UNIT_SOCKET).read_text()
    service = (units / profile.UNIT_SERVICE).read_text()

    assert "SocketUser=12031" in socket
    assert "SocketGroup=12032" in socket
    assert "SocketMode=0600" in socket
    assert "host-welcome" not in socket
    assert "station-access" not in socket
    assert "User=11021" in service
    assert "Group=11022" in service
    assert "--authorized-uid 12031" in service
    assert "--project /home/controller/zog-project" in service
    assert "--root-control-socket /run/zog/root-control.sock" in service
    assert "User=root" not in service
    assert "regular" not in service

    manifest = json.loads((output / "profile.json").read_text())
    assert manifest["box_control_source_commit"] == profile.BOX_CONTROL_COMMIT
    assert manifest["station_consumer_uid"] == 12031
    assert manifest["controller_uid"] == 11021
    assert manifest["station_settings"] == {
        "STATION_ACCESS_APPLICATION_PROGRESS_ENABLED": "1",
        "STATION_ACCESS_APPLICATION_PROGRESS_SOCKET":
            "/run/zog-host/application-progress/application-progress.sock",
        "STATION_ACCESS_APPLICATION_PROGRESS_CONTROLLER_UID": "11021",
    }
    assert manifest["mutation_authority"] == {
        "controller_build": False,
        "application_launch": False,
        "login_manager": False,
        "reboot": False,
    }

    merged = json.loads((output / "etc/zog/host-bindings.json").read_text())
    row = next(item for item in merged["bindings"]
               if item["capability"] == "application-progress")
    assert row["project"] == "/home/controller/zog-project"
    assert row["application"] == "station-access"
    assert row["program"] == "web"
    assert row["source"] == "/run/zog-host-export/application-progress"


def test_stage_preserves_existing_host_binding_policy(tmp_path, monkeypatch):
    existing = {
        "schema": 1,
        "bindings": [{
            "project": "/home/controller/zog-project",
            "application": "archive-mirror",
            "program": "server",
            "capability": "mirror-live",
            "source": "/run/zog-host-export/mirror-live",
        }],
    }
    policy = tmp_path / "host-bindings.json"
    policy.write_text(json.dumps(existing))
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    profile.stage(
        output=tmp_path / "overlay",
        controller_project="/home/controller/zog-project",
        station_uid=12031, station_gid=12032,
        controller_uid=11021, controller_gid=11022,
        host_bindings_policy=policy,
    )
    merged = json.loads(
        (tmp_path / "overlay/etc/zog/host-bindings.json").read_text()
    )
    assert existing["bindings"][0] in merged["bindings"]


@pytest.mark.parametrize("kwargs", [
    {"station_uid": 0},
    {"station_gid": 0},
    {"controller_uid": 0},
    {"controller_gid": 0},
    {"station_uid": 11021},
])
def test_stage_rejects_root_or_same_identity(tmp_path, monkeypatch, kwargs):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    values = dict(
        output=tmp_path / "overlay",
        controller_project="/home/controller/zog-project",
        station_uid=12031, station_gid=12032,
        controller_uid=11021, controller_gid=11022,
        host_bindings_policy=empty_policy(tmp_path),
    )
    values.update(kwargs)
    with pytest.raises(StateError):
        profile.stage(**values)


def test_stage_rejects_unsafe_paths_and_oversized_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    policy = empty_policy(tmp_path)
    base = dict(
        output=tmp_path / "overlay",
        controller_project="/home/controller/zog-project",
        station_uid=12031, station_gid=12032,
        controller_uid=11021, controller_gid=11022,
        host_bindings_policy=policy,
    )
    for value in ("/", "/home/controller/../other", "/home/controller/project name"):
        with pytest.raises(StateError):
            profile.stage(**{**base, "controller_project": value})

    policy.write_bytes(b" " * 65537)
    with pytest.raises(StateError, match="64 KiB"):
        profile.stage(**base)


def test_profile_is_staging_only_and_does_not_touch_live_systemd(tmp_path, monkeypatch):
    policy = empty_policy(tmp_path)
    monkeypatch.setattr(profile.os, "geteuid", lambda: 0)
    profile.stage(
        output=tmp_path / "overlay",
        controller_project="/home/controller/zog-project",
        station_uid=12031, station_gid=12032,
        controller_uid=11021, controller_gid=11022,
        host_bindings_policy=policy,
    )
    manifest = json.loads((tmp_path / "overlay/profile.json").read_text())
    assert manifest["units"][profile.UNIT_SOCKET] == "enable"
    assert manifest["units"][profile.UNIT_SERVICE] == "socket-activated"
    assert not (tmp_path / "overlay/run").exists()
