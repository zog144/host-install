"""Actual importlib.metadata (not a fake source import) RECORD readback tests.

No Host, package install, services, AWS, issuer credentials, DNS or ACME
mutation. All package trees are disposable and intentionally untrusted.
"""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re

import pytest

from zog.host_install import certify_record_readback as record
from zog.host_install.state_contract import StateError

DIST_NAME = "zog-0.1.1.dev20261117.dist-info"
MAX = record.MAX_RECORD_BYTES


def fixture(tmp_path, *, newline="\r\n"):
    root = tmp_path / "site-packages"
    info = root / DIST_NAME
    info.mkdir(parents=True)
    (info / "METADATA").write_text(
        "Metadata-Version: 2.3\nName: zog\nVersion: 0.1.1.dev20261117\n"
    )
    (info / "WHEEL").write_text(
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )
    raw = newline.join([
        "zog/box_control/issuer_lifecycle_broker.py,sha256=abc,13",
        "zog/root_control/daemon.py,sha256=def,17",
        f"{DIST_NAME}/RECORD,,",
        "",
    ]).encode()
    (info / "RECORD").write_bytes(raw)
    return root, importlib.metadata.PathDistribution(info), raw


def members(dist):
    return [p for p in (dist.files or ())
            if len(p.parts) == 2 and p.name == "RECORD"
            and p.parts[0] == DIST_NAME]


def read(root, dist, *, members_override=None):
    return record.verify_record(
        dist, root, members(dist) if members_override is None else members_override,
        protect_path=lambda *_: None,
    )


def diagnostic(exc):
    message = str(exc.value)
    assert message.startswith("certify-installed: aggregate RECORD")
    assert "; diagnostics=" in message
    return json.loads(message.split("; diagnostics=", 1)[1])


def assert_private_report(evidence, original):
    assert evidence["schema"] == "zog-certify-installed-record-readback-v1"
    assert evidence["installed_record_path"].endswith("/" + DIST_NAME + "/RECORD")
    assert evidence["metadata_record_path"].endswith("/RECORD")
    assert evidence["listed_record_matches"] in (0, 1)
    assert "zog/root_control/daemon.py" not in json.dumps(evidence)
    assert "zog/box_control/issuer_lifecycle_broker.py" not in json.dumps(evidence)
    assert original.decode("utf-8", errors="ignore") not in json.dumps(evidence)
    assert "record_text" not in evidence and "record_bytes" not in evidence


@pytest.mark.parametrize("newline,expect_translated", [
    ("\n", False), ("\r\n", True), ("\r", True)
])
def test_real_path_distribution_accepts_exact_bytes_or_only_newlines(
        tmp_path, newline, expect_translated):
    root, dist, raw = fixture(tmp_path, newline=newline)
    view = dist.read_text("RECORD")
    assert view == raw.decode().replace("\r\n", "\n").replace("\r", "\n")
    assert (view.encode() != raw) is expect_translated
    text, result = read(root, dist)
    assert text.encode() == raw
    assert result["installed_sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["newline_translation_only"] is expect_translated
    assert result["status"] == (
        "verified_universal_newlines" if expect_translated else "verified_exact_bytes")
    assert result["installed_size_bytes"] == len(raw)
    assert result["metadata_size_bytes"] == len(view.encode())
    assert result["metadata_sha256"] == hashlib.sha256(view.encode()).hexdigest()
    assert result["installed_entry_count"] == result["metadata_entry_count"] == 3
    assert result["matching_entry_count"] == 3
    assert_private_report(result, raw)


def test_physical_record_missing_in_real_distribution_reports_paths(tmp_path):
    root, dist, raw = fixture(tmp_path)
    (root / DIST_NAME / "RECORD").unlink()
    with pytest.raises(StateError, match="missing installed record") as caught:
        read(root, dist)
    evidence = diagnostic(caught)
    assert evidence["status"] == "missing_installed_record"
    assert evidence["installed_size_bytes"] is None
    assert evidence["installed_sha256"] is None
    assert evidence["listed_record_matches"] == 0
    assert_private_report(evidence, raw)


def test_existing_empty_record_is_not_treated_as_missing(tmp_path):
    root, dist, raw = fixture(tmp_path)
    (root / DIST_NAME / "RECORD").write_bytes(b"")
    with pytest.raises(StateError, match="empty installed record") as caught:
        read(root, dist)
    evidence = diagnostic(caught)
    assert evidence["status"] == "empty_installed_record"
    assert evidence["installed_size_bytes"] == 0
    assert evidence["installed_sha256"] == hashlib.sha256(b"").hexdigest()
    assert_private_report(evidence, raw)


def test_oversized_physical_record_reports_exact_size_and_hash(tmp_path):
    root, dist, raw = fixture(tmp_path)
    oversized = b"z" * (MAX + 1)
    (root / DIST_NAME / "RECORD").write_bytes(oversized)
    with pytest.raises(StateError, match="oversized installed record") as caught:
        read(root, dist, members_override=[])
    evidence = diagnostic(caught)
    assert evidence["status"] == "oversized_installed_record"
    assert evidence["installed_size_bytes"] == MAX + 1
    assert evidence["installed_sha256"] == hashlib.sha256(oversized).hexdigest()
    assert_private_report(evidence, raw)


class AlternateView:
    """Only a test view: real distribution's exact path and listing retained."""
    def __init__(self, source, value, *, metadata_dir=None):
        self.source = source
        self._path = metadata_dir or source._path
        self.version = source.version
        self.files = source.files
        self.value = value
    def locate_file(self, name):
        return self.source.locate_file(name)
    def read_text(self, name):
        assert name == "RECORD"
        return self.value


def test_missing_metadata_view_is_distinct_from_existing_installed_record(tmp_path):
    root, dist, raw = fixture(tmp_path)
    view = AlternateView(dist, None)
    with pytest.raises(StateError, match="missing metadata record") as caught:
        read(root, view)
    evidence = diagnostic(caught)
    assert evidence["status"] == "missing_metadata_record"
    assert evidence["installed_sha256"] == hashlib.sha256(raw).hexdigest()
    assert evidence["metadata_size_bytes"] is None
    assert evidence["installed_entry_count"] == 3
    assert_private_report(evidence, raw)


def test_empty_metadata_view_is_distinct_from_missing_view(tmp_path):
    root, dist, raw = fixture(tmp_path)
    with pytest.raises(StateError, match="empty metadata record") as caught:
        read(root, AlternateView(dist, ""))
    evidence = diagnostic(caught)
    assert evidence["status"] == "empty_metadata_record"
    assert evidence["metadata_size_bytes"] == 0
    assert evidence["metadata_sha256"] == hashlib.sha256(b"").hexdigest()
    assert evidence["matching_entry_count"] == 0
    assert_private_report(evidence, raw)


def test_oversized_metadata_view_reports_size_without_file_contents(tmp_path):
    root, dist, raw = fixture(tmp_path)
    large = "Q" * (MAX + 1)
    with pytest.raises(StateError, match="oversized metadata record") as caught:
        read(root, AlternateView(dist, large))
    evidence = diagnostic(caught)
    assert evidence["status"] == "oversized_metadata_record"
    assert evidence["installed_sha256"] == hashlib.sha256(raw).hexdigest()
    assert evidence["metadata_size_bytes"] == MAX + 1
    assert evidence["metadata_sha256"] == hashlib.sha256(large.encode()).hexdigest()
    assert_private_report(evidence, raw)


def test_genuine_changed_metadata_rows_rejected_and_matching_count_reported(tmp_path):
    root, dist, raw = fixture(tmp_path)
    view = dist.read_text("RECORD")
    changed = view.replace("sha256=def", "sha256=mutated")
    with pytest.raises(StateError, match="differing record views") as caught:
        read(root, AlternateView(dist, changed))
    evidence = diagnostic(caught)
    assert evidence["status"] == "differing_record_views"
    assert evidence["installed_entry_count"] == evidence["metadata_entry_count"] == 3
    assert evidence["matching_entry_count"] == 2
    assert evidence["installed_sha256"] == hashlib.sha256(raw).hexdigest()
    assert evidence["metadata_sha256"] == hashlib.sha256(changed.encode()).hexdigest()
    assert evidence["newline_translation_only"] is False
    assert_private_report(evidence, raw)


def test_alternate_metadata_directory_cannot_substitute_second_record(tmp_path):
    root, dist, raw = fixture(tmp_path)
    other = root / "zog-other.dist-info"
    other.mkdir()
    with pytest.raises(StateError, match="metadata directory mismatch") as caught:
        read(root, AlternateView(dist, dist.read_text("RECORD"), metadata_dir=other))
    evidence = diagnostic(caught)
    assert evidence["status"] == "metadata_directory_mismatch"
    assert evidence["metadata_record_path"] == str(other / "RECORD")
    assert_private_report(evidence, raw)


def test_unlisted_record_cannot_be_adopted_when_file_looks_valid(tmp_path):
    root, dist, raw = fixture(tmp_path)
    with pytest.raises(StateError, match="record listing missing or ambiguous") as caught:
        read(root, dist, members_override=[])
    evidence = diagnostic(caught)
    assert evidence["status"] == "record_listing_missing_or_ambiguous"
    assert evidence["listed_record_matches"] == 0
    assert evidence["installed_sha256"] == hashlib.sha256(raw).hexdigest()
    assert_private_report(evidence, raw)


def test_invalid_utf8_is_rejected_before_reading_metadata(tmp_path):
    root, dist, raw = fixture(tmp_path)
    (root / DIST_NAME / "RECORD").write_bytes(b"field,\xff,bad\n")
    with pytest.raises(StateError, match="installed record not utf8") as caught:
        read(root, dist, members_override=[Path(DIST_NAME) / "RECORD"])
    evidence = diagnostic(caught)
    assert evidence["status"] == "installed_record_not_utf8"
    assert evidence["installed_size_bytes"] == len(b"field,\xff,bad\n")
    assert_private_report(evidence, raw)


def test_oversized_diagnostic_hash_is_bounded(tmp_path):
    root, dist, raw = fixture(tmp_path)
    size = record.MAX_DIAGNOSTIC_HASH_BYTES + 1
    file = root / DIST_NAME / "RECORD"
    with file.open("wb") as stream:
        stream.truncate(size)
    with pytest.raises(StateError, match="oversized installed record") as caught:
        read(root, dist, members_override=[Path(DIST_NAME) / "RECORD"])
    evidence = diagnostic(caught)
    assert evidence["installed_size_bytes"] == size
    assert evidence["installed_sha256"] is None
    assert_private_report(evidence, raw)


def test_oversized_diagnostic_rejects_growth_without_hashing_append(
        tmp_path, monkeypatch):
    """A growing file cannot turn the bounded diagnostic into an EOF read."""
    root, dist, raw = fixture(tmp_path)
    installed = root / DIST_NAME / "RECORD"
    installed.write_bytes(b"x" * (MAX + 1))
    real_fdopen = record.os.fdopen

    class GrowingReader:
        def __init__(self, source):
            self.source = source
            self.grown = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.source.close()

        def read(self, size=-1):
            assert 0 < size <= 65536
            if not self.grown:
                self.grown = True
                with installed.open("ab") as writer:
                    writer.write(b"unexpected-appended-bytes")
            return self.source.read(size)

        def fileno(self):
            return self.source.fileno()

    monkeypatch.setattr(record.os, "fdopen",
                        lambda fd, mode: GrowingReader(real_fdopen(fd, mode)))
    with pytest.raises(StateError, match="installed record changed during read") as caught:
        read(root, dist, members_override=[Path(DIST_NAME) / "RECORD"])
    evidence = diagnostic(caught)
    assert evidence["status"] == "installed_record_changed_during_read"
    assert evidence["installed_size_bytes"] == MAX + 1
    assert evidence["installed_sha256"] is None
    assert_private_report(evidence, raw)
