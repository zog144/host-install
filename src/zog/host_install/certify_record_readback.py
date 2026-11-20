"""Read-only installed aggregate RECORD reconciliation and bounded diagnostics.

importlib.metadata.Distribution.read_text() is a *text* API: Python's
Path.read_text() transparently translates CRLF/CR to LF. A wheel's installed
RECORD is typically CSV with CRLF newlines. Directly comparing the text
API's UTF-8 bytes to RECORD's original on-disk bytes is incorrect.

This helper authenticates the actual protected raw RECORD, retains its
unaltered SHA-256, and allows *only* universal-newline translation between
that raw source and the Python metadata view. The original importer must
still verify every required module's Git blob, installed RECORD hash and
byte size. It never repairs or rewrites an installed file.

Failure reports contain only a fixed status, root-relative package paths,
byte lengths, SHA-256 digests, and counts of matching CSV entries. They
contain no file bytes, module contents, environment, tokens or credentials.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import stat

from .state_contract import StateError, require

MAX_RECORD_BYTES = 4_000_000
MAX_DIAGNOSTIC_HASH_BYTES = 16_000_000


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _entries(text):
    """Return only a safe internal set of exact RECORD tuples for counting.

    Duplicate rows and malformed CSV are not admitted by the main importer;
    this is for safe diagnostics only, never a replacement for validation.
    """
    if type(text) is not str:
        return set(), 0
    try:
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (csv.Error, ValueError):
        return set(), 0
    valid = [tuple(row) for row in rows if len(row) == 3]
    return set(valid), len(rows)


def _metadata_path(dist, root):
    # _path is only *diagnostic* metadata that importlib exposes for a
    # PathDistribution; we still require the actual RECORD's checked path.
    original = getattr(dist, "_path", None)
    return (Path(original) if original is not None
            else root / ("zog-" + dist.version + ".dist-info")) / "RECORD"


def _diagnostic(root, raw_path, metadata_path, count):
    return {
        "schema": "zog-certify-installed-record-readback-v1",
        "installed_record_path": str(raw_path),
        "metadata_record_path": str(metadata_path),
        "listed_record_matches": count,
        "installed_size_bytes": None,
        "installed_sha256": None,
        "metadata_size_bytes": None,
        "metadata_sha256": None,
        "installed_entry_count": None,
        "metadata_entry_count": None,
        "matching_entry_count": None,
        "newline_translation_only": False,
        "status": "uninspected",
    }


def _failure(reason, evidence):
    # Never expose file content or unbounded exception text.
    evidence["status"] = reason
    raise StateError(
        "certify-installed",
        "aggregate RECORD " + reason.replace("_", " ") +
        "; diagnostics=" + json.dumps(
            evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ),
    )


def _hash_oversize(path, info, evidence):
    """Hash only bounded read-only evidence through an O_NOFOLLOW FD."""
    if info.st_size > MAX_DIAGNOSTIC_HASH_BYTES:
        return None
    digest = hashlib.sha256()
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        first = os.fstat(fd)
        if ((first.st_dev, first.st_ino, first.st_size) !=
                (info.st_dev, info.st_ino, info.st_size)):
            _failure("installed_record_changed_during_read", evidence)
        with os.fdopen(fd, "rb") as source:
            fd = -1
            for data in iter(lambda: source.read(65536), b""):
                digest.update(data)
            last = os.fstat(source.fileno())
            if ((last.st_dev, last.st_ino, last.st_size, last.st_mtime_ns) !=
                    (first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns)):
                _failure("installed_record_changed_during_read", evidence)
    except OSError:
        _failure("installed_record_unreadable", evidence)
    finally:
        if fd >= 0:
            os.close(fd)
    return digest.hexdigest()


def verify_record(distribution, root, record_members, *, protect_path):
    """Return (raw decoded text, safe evidence) or fail closed.

    Only an exact installed dist-info RECORD member is admissible. The
    distribution's own metadata directory and located RECORD must agree,
    preventing a shadow metadata provider from substituting a different
    RECORD file. No native Host command, installation or service is invoked.
    """
    root = Path(root)
    members = tuple(record_members)
    expected = _metadata_path(distribution, root)
    actual = (Path(distribution.locate_file(members[0]))
              if len(members) == 1 else expected)
    evidence = _diagnostic(root, actual, expected, len(members))

    require(actual.is_absolute() and expected.is_absolute(),
            "certify-installed", "aggregate RECORD paths must be absolute")
    # Validate trusted ancestry even for a missing leaf: this prevents
    # diagnostic probing through a redirected metadata directory.
    protect_path(actual.parent, root)
    if actual.parent != expected.parent:
        _failure("metadata_directory_mismatch", evidence)

    try:
        info = actual.lstat()
    except FileNotFoundError:
        _failure("missing_installed_record", evidence)
    except OSError:
        _failure("installed_record_unreadable", evidence)
    protect_path(actual, root)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        _failure("installed_record_not_regular", evidence)

    evidence["installed_size_bytes"] = info.st_size
    if info.st_size == 0:
        evidence["installed_sha256"] = _hash(b"")
        _failure("empty_installed_record", evidence)
    if info.st_size > MAX_RECORD_BYTES:
        evidence["installed_sha256"] = _hash_oversize(actual, info, evidence)
        _failure("oversized_installed_record", evidence)
    try:
        # Do not read beyond the checked size or follow a replacement link.
        fd = os.open(actual, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            now = os.fstat(fd)
            if ((now.st_dev, now.st_ino, now.st_size) !=
                    (info.st_dev, info.st_ino, info.st_size)):
                _failure("installed_record_changed_during_read", evidence)
            with os.fdopen(fd, "rb") as file:
                fd = -1
                raw = file.read(MAX_RECORD_BYTES + 1)
            if len(raw) != info.st_size:
                _failure("installed_record_changed_during_read", evidence)
            # Guard against a concurrent in-place modification of a nominally
            # identical-length RECORD; neither read-only success nor error
            # diagnostics can assert stable bytes in that situation.
            current = actual.lstat()
            if ((current.st_dev, current.st_ino, current.st_size,
                 current.st_mtime_ns, current.st_ctime_ns) !=
                    (info.st_dev, info.st_ino, info.st_size,
                     info.st_mtime_ns, info.st_ctime_ns)):
                _failure("installed_record_changed_during_read", evidence)
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError:
        _failure("installed_record_unreadable", evidence)
    evidence["installed_sha256"] = _hash(raw)
    if len(raw) > MAX_RECORD_BYTES:
        _failure("oversized_installed_record", evidence)
    try:
        raw_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _failure("installed_record_not_utf8", evidence)
    _, evidence["installed_entry_count"] = _entries(raw_text)

    if len(members) != 1:
        # The physical RECORD can exist but be omitted/duplicated from the
        # distribution's metadata listing. Never silently accept it.
        _failure("record_listing_missing_or_ambiguous", evidence)

    try:
        metadata = distribution.read_text("RECORD")
    except (OSError, UnicodeError):
        metadata = None
    if metadata is None:
        _failure("missing_metadata_record", evidence)
    if type(metadata) is not str:
        _failure("invalid_metadata_record_view", evidence)
    metadata_raw = metadata.encode("utf-8")
    evidence["metadata_size_bytes"] = len(metadata_raw)
    evidence["metadata_sha256"] = _hash(metadata_raw)
    if len(metadata_raw) == 0:
        evidence["metadata_entry_count"] = 0
        evidence["matching_entry_count"] = 0
        _failure("empty_metadata_record", evidence)
    if len(metadata_raw) > MAX_RECORD_BYTES:
        _failure("oversized_metadata_record", evidence)
    _, evidence["metadata_entry_count"] = _entries(metadata)
    left, _ = _entries(raw_text)
    right, _ = _entries(metadata)
    evidence["matching_entry_count"] = len(left & right)

    # This is the only permitted discrepancy: Python universal-newline
    # conversion, not a content change. The RAW on-disk digest is preserved
    # and the full downstream signed/pinned module checks are unchanged.
    normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    if metadata != normalized:
        _failure("differing_record_views", evidence)

    # Require that the actual selected RECORD path still identifies the
    # same inode and unchanged bytes after metadata lookup. Otherwise a
    # replacement between the two independent readbacks is uncertain.
    try:
        final_info = actual.lstat()
    except OSError:
        _failure("installed_record_changed_during_read", evidence)
    if ((final_info.st_dev, final_info.st_ino, final_info.st_size,
         final_info.st_mtime_ns, final_info.st_ctime_ns) !=
            (info.st_dev, info.st_ino, info.st_size,
             info.st_mtime_ns, info.st_ctime_ns)):
        _failure("installed_record_changed_during_read", evidence)
    evidence["newline_translation_only"] = metadata_raw != raw
    evidence["status"] = (
        "verified_universal_newlines" if metadata_raw != raw else "verified_exact_bytes"
    )
    return raw_text, evidence
