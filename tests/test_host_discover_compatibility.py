"""Exact source API surface consumed by selected public host-discover.

This is a regression contract, not a promise that every private host-install
symbol is stable. It covers only the interfaces imported by the reviewed
host-discover public candidate during the 2026-10-18 migration acceptance.
"""
import inspect

from zog.host_install import state_admission
from zog.host_install import state_contract
from zog.host_install import state_gate
from zog.host_install import state_inspect
from zog.host_install import state_io
from zog.host_install import state_probe


HOST_DISCOVER_SOURCE = "341255fd0ebdee5eedfd4be9a40829ec17391887"
HOST_INSTALL_044_SOURCE = "b2323c8d2cb7f00b1d0145451ca72fbbbd5fb486"


def test_host_discover_state_api_signatures_remain_compatible_with_044():
    expected = {
        state_contract.require: "(value, code, message)",
        state_contract.canonical: "(value)",
        state_contract.decode: "(raw)",
        state_contract.fields: "(value, names)",
        state_contract.sha: "(value)",
        state_contract.header: "(value, kind, names)",
        state_contract.validate: "(bundle)",
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
            "require", "sha", "validate",
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
