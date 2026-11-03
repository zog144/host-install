"""Independent station-access consumer readback negatives for protected bundle.

These tests use synthetic root-owned files only. They do not authenticate an
AWS IID, adopt a signer pin, activate a credential or claim native reboot.
"""
import os

import pytest

from zog.host_install import command_center_authority as authority
from zog.host_install.state_contract import StateError, canonical
from test_command_center_authority import fixture, verify, NOW


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned metadata tests require root CI")
@pytest.mark.parametrize("damage", (
    "missing-material",
    "truncated-receipt",
    "pending-receipt-after-commit",
))
def test_accepted_receipt_requires_complete_exact_readback(tmp_path, monkeypatch, damage):
    value = fixture()
    accepted = verify(value)
    reader_gid = 1001  # synthetic dedicated issuer-reader, NOT a production role

    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        authority._publish_bundle(root, value["materials"], accepted, reader_gid)
    finally:
        os.close(root)

    # The real stage/inspect wrapper restricts the path under /opt/station-trust.
    # Only this synthetic test substitutes the root directory descriptor and
    # separately observed test database, never a production pathname or pin.
    monkeypatch.setattr(authority, "_offline_root",
                        lambda _: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY))
    monkeypatch.setattr(authority, "_observe_database", lambda _: value["observed"])
    monkeypatch.setattr(authority, "RETAINED_CERTIFICATE_SIGNER_SHA256",
                        value["certificate_sha"])
    kwargs = dict(
        offline_directory=str(tmp_path),
        reader_gid=reader_gid,
        expected_operator_pin_sha256=value["operator_sha"],
        expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
        expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
        expected_authorization_issuer=value["issuer"],
        now=NOW,
    )
    report = authority.inspect_offline(**kwargs)
    assert report["status"] == "protected-offline-authority-materials-retained"
    assert report["production_activation_authorized"] is False
    assert report["credential_delivery_authorized"] is False

    folder = tmp_path / authority.DIRECTORY_NAME
    recorded = {
        name: (folder / name).stat().st_ino
        for name in authority.FILES
    }
    if damage == "missing-material":
        (folder / "root-grant.json").unlink()
    elif damage == "truncated-receipt":
        (folder / authority.RECEIPT_NAME).write_bytes(b'{"schema":"partial')
    else:
        (folder / (".pending." + authority.RECEIPT_NAME)).write_bytes(
            canonical(accepted))
    with pytest.raises(StateError):
        authority.inspect_offline(**kwargs)
    # Inspection never repairs/replaces, even in the presence of a valid
    # originally published receipt or a forged partial sibling.
    for name, inode in recorded.items():
        if (folder / name).exists():
            assert (folder / name).stat().st_ino == inode
    assert not (tmp_path / "state").exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="synthetic root-owner offline publication requires root CI")
@pytest.mark.parametrize("replacement_at", ("before-publication", "during-publication"))
def test_station_database_identity_rotated_during_offline_authority_staging(
        tmp_path, monkeypatch, replacement_at):
    """A signed original DB inode must not authorize a different live DB.

    The source test substitutes synthetic inputs and a temporary root-owned
    offline directory; it does not provision STATE or authenticate AWS IID.
    """
    value = fixture()
    original = value["observed"]
    replaced = dict(original, inode=original["inode"] + 1)
    observations = []
    def observe(path):
        assert path == original["path"]
        observations.append(path)
        if replacement_at == "before-publication" and len(observations) >= 2:
            return replaced
        if replacement_at == "during-publication" and len(observations) >= 3:
            return replaced
        return original

    monkeypatch.setattr(authority, "_read_inputs", lambda paths, reader_gid: value["materials"])
    monkeypatch.setattr(authority, "_observe_database", observe)
    monkeypatch.setattr(authority, "_offline_root", lambda path:
                        os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY))
    monkeypatch.setattr(authority, "RETAINED_CERTIFICATE_SIGNER_SHA256",
                        value["certificate_sha"])
    options = dict(
        offline_directory=str(tmp_path),
        paths={name: "synthetic" for name in value["materials"]},
        reader_gid=1001,
        expected_operator_pin_sha256=value["operator_sha"],
        expected_instance_id=authority.COMMAND_CENTER_INSTANCE_ID,
        expected_station_source_commit=authority.STATION_ACCESS_COMMIT,
        expected_authorization_issuer=value["issuer"],
        now=NOW,
    )
    with pytest.raises(StateError, match="database identity changed"):
        authority.stage_offline(**options)

    folder = tmp_path / authority.DIRECTORY_NAME
    if replacement_at == "before-publication":
        assert not folder.exists()  # reject before writing even one authority file
    else:
        assert folder.is_dir()
        assert (folder / authority.RECEIPT_NAME).exists()
        # Crash/interruption may durably leave inert staging, but replay
        # against the replaced station database cannot claim acceptance.
        with pytest.raises(StateError):
            authority.inspect_offline(**{
                k: v for k, v in options.items() if k != "paths"
            })
    assert len(observations) >= (2 if replacement_at == "before-publication" else 3)
    assert not (tmp_path / "state").exists()
