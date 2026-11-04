"""Cross-owner source metadata matches exact image-build PR16 installed-byte verifier."""
import ast
import json
import os
from pathlib import Path
from zog.host_install import resident_b_evidence_handoff as handoff

def parse_constants(source):
    module=ast.parse(source)
    out={}
    for node in module.body:
        if isinstance(node,ast.Assign):
            for left in node.targets:
                if isinstance(left,ast.Name) and left.id in ("SCHEMA","SOURCE_PINS","MODULES"):
                    out[left.id]=ast.literal_eval(node.value)
    return out

def test_immutable_image_build_installed_evidence_contract_matches_host_install():
    root=Path(os.environ["ZOG_REVIEW_IMAGE_BUILD_PR16"])
    script=(root/"tools/verify_resident_b_installed_evidence.py").read_text()
    constants=parse_constants(script)
    assert constants["SCHEMA"]==handoff.OBS_SCHEMA
    assert constants["SOURCE_PINS"]==handoff.CONTROLLERS
    assert set(constants["MODULES"])=={"_ssl","_sqlite3","_hashlib"}
    assert "zog-resident-b-selected-input-generation-v1" in script
    assert "zog-resident-b-installed-evidence-v1" in script
    assert "EVIDENCE_COHERENT_UNACCEPTED" in script
    assert "accepted_generation" in script
    assert "stat.S_IMODE(sstat.st_mode)!=0o755" in script
    combined=json.loads((root/"project/host/resident-b-pr14-pr15-combined-source-review.json").read_text())
    actual=set(sum(combined["expected_installed_outputs"].values(),[]))
    py=ast.literal_eval((root/"project/package/python-resident312/stages/final/produce-manifest.py").read_text())
    actual.update(py["required"])
    assert handoff.REQUIRED_OUTPUTS.issubset(actual)
    assert set(py["required"])=={
        "usr/bin/python3.12","usr/lib/libpython3.12.so.1.0",
        "usr/lib/python3.12/lib-dynload/_ssl.cpython-312-x86_64-linux-gnu.so",
        "usr/lib/python3.12/lib-dynload/_sqlite3.cpython-312-x86_64-linux-gnu.so",
        "usr/lib/python3.12/lib-dynload/_hashlib.cpython-312-x86_64-linux-gnu.so"}
    assert "SOURCE_ONLY_NATIVE_NOT_READY"==combined["status"]
    assert combined["accepted_generation"] is None

def test_mount_contract_is_real_host_install_verifiedstate_not_signature_text():
    from zog.host_install import state_inspect
    source=Path(state_inspect.__file__).read_text()
    assert "metadata(fd, 0, 0, 0o755)" in source
    assert "host_generation_report(context)" in source
    assert "root_partition_partuuid()" in source
    assert "context.recheck()" in source
