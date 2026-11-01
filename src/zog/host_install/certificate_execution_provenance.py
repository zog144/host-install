"""Native-only protected execution bridge provenance publication.

The original signed Host/installation/state authority and installed wheel
RECORD must come from an independently authenticated root-owned reader.
No source contents, digest, inode or approval may be provided over a broker
RPC. This module cannot attest a live wheel by itself.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat

from .state_contract import StateError, canonical
from .state_io import raw, publish
from .certificate_selected_broker_install import (
    BOX_CONTROL_REVIEWED_COMMIT, COMMIT_NAME, COMMIT_SCHEMA, _fixed_root_parent,
)

# Updated only when the complete, independently reviewed root-control PR #23
# source and wheel RECORD are attested. A mismatched source must NOT activate.
ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT = "UNPINNED"
FIELDS = frozenset(("root_control_revision", "wheel_record_sha256",
    "host_id", "installation_id", "state_volume_id", "box_control_revision"))
SCHEMA = "zog-host-install-selected-issuer-execution-source-v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _deny():
    raise StateError("issuer-execution-provenance",
                     "installed-root-source-unavailable") from None


def publish_verified_execution_provenance(*, independently_trusted_source_reader,
                                           independently_pinned_record_reader):
    """Root-only stage after immutable broker installation and wheel audit.

    The callback is an out-of-band root attestor, not a JSON request field.
    The protected approval, actual installed wheel and RECORD, locked
    directory and Host/STATE binding must be independently validated there.
    """
    if (os.geteuid() != 0 or not callable(independently_trusted_source_reader)
            or not callable(independently_pinned_record_reader)):
        _deny()
    if not re.fullmatch(r"[0-9a-f]{40}", ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT):
        _deny()
    from zog.root_control.issuer_execution_fence import (
        IssuerExecutionFence, FIXED_DIRECTORY, LOCK,
    )
    from zog.root_control.issuer_execution_provenance import (
        NAME, require_installed_provenance,
    )
    with _fixed_root_parent() as parent:
        commit_bytes = raw(parent, COMMIT_NAME, uid=0, gid=0, mode=0o444)
        if commit_bytes is None: _deny()
        try:
            commit = json.loads(commit_bytes)
        except (ValueError, TypeError):
            _deny()
        if (type(commit) is not dict or commit.get("schema") != COMMIT_SCHEMA
                or canonical(commit) != commit_bytes
                or commit.get("box_control_revision") != BOX_CONTROL_REVIEWED_COMMIT):
            _deny()
        evidence = independently_trusted_source_reader()
        expected_record = independently_pinned_record_reader()
        if (type(expected_record) is not str or
                _HEX64.fullmatch(expected_record) is None):
            _deny()
        if (type(evidence) is not dict or set(evidence) != FIELDS
                or evidence["root_control_revision"] !=
                   ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT
                or evidence["box_control_revision"] != BOX_CONTROL_REVIEWED_COMMIT
                or type(evidence["wheel_record_sha256"]) is not str
                or _HEX64.fullmatch(evidence["wheel_record_sha256"]) is None
                or evidence["wheel_record_sha256"] != expected_record
                or any(evidence.get(field) != commit[field] for field in
                       ("host_id", "installation_id", "state_volume_id"))):
            _deny()
        fd = os.open(FIXED_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY |
                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            directory = os.fstat(fd)
            if (directory.st_uid, directory.st_gid) != (0, 0) or (
                    stat.S_IMODE(directory.st_mode) != 0o700):
                _deny()
            fence = IssuerExecutionFence(fd)
            with fence._locked():
                record = fence._read()
                commit_sha = hashlib.sha256(commit_bytes).hexdigest()
                if (record is None or record["revoked"] or
                        record["authority_commit_sha256"] != commit_sha):
                    _deny()
                lock = os.stat(LOCK, dir_fd=fd, follow_symlinks=False)
                if (not stat.S_ISREG(lock.st_mode) or
                        (lock.st_uid, lock.st_gid) != (0, 0) or
                        stat.S_IMODE(lock.st_mode) != 0o600 or lock.st_nlink != 1):
                    _deny()
                attestation = {
                    **evidence, "schema": SCHEMA, "commit_sha256": commit_sha,
                    "directory_dev": directory.st_dev,
                    "directory_ino": directory.st_ino,
                    "lock_dev": lock.st_dev, "lock_ino": lock.st_ino,
                }
                raw_bytes = canonical(attestation)
                publish(fd, NAME, raw_bytes, mode=0o600, uid=0, gid=0)
                if raw(fd, NAME, uid=0, gid=0, mode=0o600) != raw_bytes:
                    _deny()
                require_installed_provenance(
                    fd, root_control_revision=ROOT_CONTROL_EXECUTION_REVIEWED_COMMIT,
                    box_control_revision=BOX_CONTROL_REVIEWED_COMMIT,
                    commit_sha256=commit_sha, identities=commit,
                )
                # Callback input must not change during protected publication.
                if (independently_trusted_source_reader() != evidence or
                        independently_pinned_record_reader() != expected_record):
                    _deny()
                return {"status": "source-provenance-staged",
                        "commit_sha256": commit_sha,
                        "wheel_record_sha256": evidence["wheel_record_sha256"],
                        "native_activation_authorized": False}
        finally:
            os.close(fd)
