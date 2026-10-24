"""Exact host-install API surface consumed by host-discover 0.4.11.

The selected host-discover successor was independently tested against immutable
host-install 0.14.3. These regressions ensure later 0.14.x host-install source
does not silently break that non-resident managed-beacon contract.
"""
import inspect

from zog.host_install import state_admission
from zog.host_install import state_contract
from zog.host_install import state_gate
from zog.host_install import state_inspect
from zog.host_install import state_io
from zog.host_install import state_probe


HOST_DISCOVER_SOURCE = "9e741d9a86bb2fd466ac46b252be0b78528eeff7"
HOST_DISCOVER_VERSION = "0.4.11"
HOST_INSTALL_0143_SOURCE = "889f137dc19d1f34fca42fd3dd8df862f8ebae9d"


def test_selected_successor_and_non_resident_contract_are_current():
    import json
    from pathlib import Path
    import zog.host_install as host_install

    assert tuple(map(int, host_install.__version__.split("."))) >= (0, 14, 3)
    assert HOST_DISCOVER_VERSION == "0.4.11"
    assert HOST_DISCOVER_SOURCE == (
        "9e741d9a86bb2fd466ac46b252be0b78528eeff7"
    )
    assert HOST_INSTALL_0143_SOURCE == (
        "889f137dc19d1f34fca42fd3dd8df862f8ebae9d"
    )
    root = Path(__file__).resolve().parents[1]
    bundle = json.loads(
        (root / "examples/non-resident-state-v1/bundle.json").read_text()
    )
    assert state_contract.validate(bundle) == bundle
    installation = bundle["installation"]
    assert state_contract.installation_mode(installation) == "non-resident"
    recorded = installation["installer_recorded"]
    assert recorded["host_os"] == {
        "management": "externally-managed",
        "boot": "externally-managed",
        "root_filesystem": "externally-managed",
    }
    for forbidden in (
        "foreign_boot_bundle", "host_slots", "expected_slot",
        "expected_host_generation", "expected_artifact_id", "root_partuuid",
    ):
        assert forbidden not in recorded


def test_host_discover_state_api_signatures_remain_compatible_with_0143():
    expected = {
        state_contract.require: "(value, code, message)",
        state_contract.canonical: "(value)",
        state_contract.decode: "(raw)",
        state_contract.fields: "(value, names)",
        state_contract.sha: "(value)",
        state_contract.header: "(value, kind, names)",
        state_contract.validate: "(bundle)",
        state_contract.installation_mode: "(installation)",
        state_inspect.directory: "(path)",
        state_inspect.metadata: "(fd, uid, gid, mode, is_directory=True)",
        state_inspect.read_at: "(fd, name, uid=0, gid=0, mode=292)",
        state_inspect.assess_mount: "(rows, devices, expected, root_device)",
        state_inspect.inspect_live: "()",
        state_inspect.host_generation_report: "(context)",
        state_admission.request_live: "(context)",
        state_gate.decide: "(bundle, evidence)",
        state_probe.probe_live: "()",
        state_io.raw: "(fd, name, uid=0, gid=0, mode=384, links=(1,))",
        state_io.publish: (
            "(fd, name, data, mode=384, *, uid=0, gid=0, "
            "checkpoint=<function <lambda> at SIGNATURE>)"
        ),
        state_io.ensure_directory: (
            "(fd, name, uid, gid, mode, "
            "checkpoint=<function <lambda> at SIGNATURE>)"
        ),
        state_io.lock: "(fd, name='.host-install.lock')",
    }
    for function, wanted in expected.items():
        observed = str(inspect.signature(function))
        if "checkpoint=<function <lambda> at " in observed:
            observed = observed.split("checkpoint=<function <lambda> at ", 1)[0] + (
                "checkpoint=<function <lambda> at SIGNATURE>)"
            )
        assert observed == wanted, (function.__module__, function.__name__, observed)


def test_host_discover_fixed_state_account_contract_is_unchanged():
    assert state_contract.PROFILE == "zog-host-accounts-v1"
    assert state_contract.CONFIG == "/etc/zog/host-install"
    assert state_contract.PATHS == {
        "mount_point": "/state",
        "identity_directory": "/state/host-discover/identity",
        "trust_directory": "/state/host-discover/trust",
        "control_directory": "/state/host-discover/control",
    }
    assert state_contract.ACCOUNTS["users"]["host-discover"] == {
        "uid": 970,
        "gid": 970,
        "groups": [972, 973],
    }
    assert state_contract.ACCOUNTS["groups"]["host-discover"] == 970
    assert state_contract.ACCOUNTS["groups"]["archive-consumers"] == 972
    assert state_contract.ACCOUNTS["groups"]["host-control"] == 973


def test_host_discover_imported_symbols_are_present_without_legacy_shim():
    required = {
        state_contract: (
            "StateError", "canonical", "decode", "fields", "header",
            "require", "sha", "validate", "installation_mode",
        ),
        state_inspect: (
            "directory", "metadata", "read_at", "assess_mount",
            "inspect_live", "host_generation_report",
        ),
        state_admission: ("request_live",),
        state_gate: ("decide",),
        state_probe: ("probe_live",),
        state_io: ("raw", "publish", "ensure_directory", "lock"),
    }
    for module, names in required.items():
        for name in names:
            assert hasattr(module, name), (module.__name__, name)

    # The aggregate namespace is canonical; compatibility must not reintroduce
    # the obsolete standalone import layout.
    import importlib.util
    assert importlib.util.find_spec("host_install") is None
