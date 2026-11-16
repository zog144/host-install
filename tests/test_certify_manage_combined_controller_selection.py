"""Check issuer selection against original reviewed Resident B aggregate source tree.

This is *source-only*: source Git blobs are not a real installed aggregate.
The native attestor separately checks actual interpreter, installed modules
and the aggregate's installed RECORD once the producer provides real bytes.
"""
import hashlib
import json
from pathlib import Path

import pytest

from zog.host_install import certify_manage_profile as p
from zog.host_install.state_contract import StateError

ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "companions/image-build-resident-b/project/host/resident-b-aggregate-installed-source-pins-v1.json"
BOX = ROOT / "companions/box-control-certificate"
ROOT_CONTROLLER = ROOT / "companions/root-control"


def source_selection():
    return json.loads(SELECTION.read_text())


def git_blob(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\0" + raw
    ).hexdigest()


def test_exact_combined_source_selection_not_historical_issuer_pins():
    record = source_selection()
    assert record["status"] == "SOURCE_PINNED_AGGREGATE_NOT_YET_PRODUCED"
    assert record["distribution"]["name"] == "zog"
    assert record["distribution"]["python"] == "3.12"
    assert record["distribution"]["install_prefix"] == "usr/lib/python3.12/site-packages"
    assert record["controllers"]["box-control"]["revision"] == p.BOX_CONTROL_COMMIT
    assert record["controllers"]["root-control"]["revision"] == p.ROOT_CONTROL_COMMIT
    assert p.BOX_CONTROL_COMMIT != "73d64fb8b643e27667ac719080a37913c008b5dd"
    assert p.ROOT_CONTROL_COMMIT != "8bb9a5638622b3c443e59351cfdf06583cea8e80"
    assert p.CONTROLLER_PYTHON == "/usr/bin/python3.12"
    assert p.CONTROLLER_SITE_PACKAGES == "/" + record["distribution"]["install_prefix"]
    assert p.CONTROLLER_DISTRIBUTION == record["distribution"]["name"]
    assert record["native"]["installed_accepted"] is False
    assert record["native"]["source_only"] is True
    assert record["native"]["aggregate_wheel_sha256"] is None


def test_all_fifteen_issuer_modules_match_aggregate_git_blobs_and_source_files():
    record = source_selection()
    assert len(p.BOX_CONTROL_MODULE_BLOBS) == 10
    assert len(p.ROOT_CONTROL_MODULE_BLOBS) == 5
    for component, modules in (("box-control", p.BOX_CONTROL_MODULE_BLOBS),
                               ("root-control", p.ROOT_CONTROL_MODULE_BLOBS)):
        selection = record["controllers"][component]
        prefix = selection["source_prefix"]
        checkout = BOX if component == "box-control" else ROOT_CONTROLLER
        for module, expected in modules.items():
            path = module.replace(".", "/") + ".py"
            assert path in selection["files"]
            assert selection["files"][path] == {"git_blob": expected, "mode": "100644"}
            local = checkout / prefix / path.removeprefix("zog/box_control/" if
                         component == "box-control" else "zog/root_control/")
            assert local.is_file() and not local.is_symlink()
            assert git_blob(local.read_bytes()) == expected


def test_four_changed_module_pins_are_the_selected_combined_source():
    assert p.BOX_CONTROL_MODULE_BLOBS["zog.box_control.issuer_lifecycle_broker"] == (
        "fc32e0c42fd97cdadefa197f9a0bfdc2beacc7c9")
    assert p.BOX_CONTROL_MODULE_BLOBS["zog.box_control.issuer_lifecycle_client"] == (
        "3168d674963259aadacfed05c91cec765928f094")
    assert p.ROOT_CONTROL_MODULE_BLOBS["zog.root_control.daemon"] == (
        "e5f6b8d15a8cb9cf9aeed7658a2d01271be380ab")
    assert p.ROOT_CONTROL_MODULE_BLOBS["zog.root_control.systemd"] == (
        "0f0e78c50ed5f517d30f63cb56471138319df7c2")


def test_wrong_interpreter_cannot_use_aggregate_through_default_python_alias():
    with pytest.raises(StateError, match="canonical approved Python"):
        p._absolute("../../usr/bin/python3.12", "canonical approved Python")
