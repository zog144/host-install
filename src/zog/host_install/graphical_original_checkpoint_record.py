"""Durable original Task C S3 checkpoint installation identity (source candidate).

Copyright (c) 2026 Alex Black. BSD-3-Clause OR GPL-3.0-only.

Create is an explicit one-time installer operation, NOT a recovery mechanism.
Continuation only reads two already durable files. Neither entry point creates
an S3 genesis, sends SSM, accepts native authority or starts a service.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from . import graphical_native_owner_install as owner

SCHEMA = "zog-task-c-original-checkpoint-installation-v1"
RESERVATION_SCHEMA = "zog-task-c-original-checkpoint-reservation-v1"
RECORD = "original-checkpoint-installation.json"
RESERVATION = "original-checkpoint-installation.reserved"
FIELDS = frozenset({
    "schema", "host_id", "installation_id", "state_volume_id",
    "checkpoint_account_id", "checkpoint_region", "checkpoint_bucket",
    "checkpoint_prefix", "checkpoint_scope_sha256", "checkpoint_genesis_sha256",
    "checkpoint_role_arn", "root_source_revision",
})

def _hold():
    owner.hold()

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")

def _selected(manifest, *, original_scope_sha256):
    row = owner.validate_install_contract(manifest)
    policy = row["checkpoint_policy"]
    if not owner._match(original_scope_sha256, owner.SHA):
        _hold()
    return {
        "schema": SCHEMA,
        "host_id": row["host_id"],
        "installation_id": row["installation_id"],
        "state_volume_id": row["state_volume_id"],
        "checkpoint_account_id": policy["account_id"],
        "checkpoint_region": policy["region"],
        "checkpoint_bucket": policy["bucket"],
        "checkpoint_prefix": policy["prefix"],
        "checkpoint_scope_sha256": original_scope_sha256,
        "checkpoint_genesis_sha256": policy["genesis_sha256"],
        "checkpoint_role_arn": policy["role_arn"],
        "root_source_revision": row["root_source_revision"],
    }

def _directory(path):
    path = Path(path)
    if path.is_symlink():
        _hold()
    try:
        info = path.lstat()
    except OSError:
        _hold()
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        _hold()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = os.fstat(fd)
        if (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
            _hold()
    except OSError:
        _hold()
    return fd

def _read(dfd, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    except FileNotFoundError:
        _hold()
    except OSError:
        _hold()
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 4096):
            _hold()
        raw = os.read(fd, 4097)
        if len(raw) != info.st_size:
            _hold()
        try:
            value = json.loads(raw, object_pairs_hook=_unique,
                               parse_constant=lambda _: _hold())
        except (ValueError, TypeError, UnicodeError, OverflowError):
            _hold()
        if type(value) is not dict or _canonical(value) != raw:
            _hold()
        return value
    finally:
        os.close(fd)

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _hold()
        result[key] = value
    return result

def _write_exclusive(dfd, name, value):
    raw = _canonical(value)
    if not 0 < len(raw) <= 4096:
        _hold()
    try:
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    except OSError:
        _hold()
    try:
        os.fchmod(fd, 0o600)
        written = 0
        while written < len(raw):
            count = os.write(fd, raw[written:])
            if count <= 0:
                _hold()
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(dfd)

def reserve_original_checkpoint(directory, manifest, *,
                                independently_selected_scope_sha256,
                                explicit_first_install=False):
    """One-time, explicitly selected install. Never called on continuation.

    Native installer MUST authenticate an original independent approval and
    prove fresh Host installation before calling this; a True flag alone is
    never operator authority. The reservation is irreversible: interrupted
    creation leaves a hold, not an opportunity to replay installation.
    """
    if explicit_first_install is not True:
        _hold()
    original = _selected(manifest,
                         original_scope_sha256=independently_selected_scope_sha256)
    dfd = _directory(directory)
    try:
        # The first durable reservation precedes any record publication.
        # Once either entry exists, no "first install" can be repeated.
        _write_exclusive(dfd, RESERVATION, {
            "schema": RESERVATION_SCHEMA,
            "identity_sha256": "sha256:" + hashlib.sha256(
                _canonical(original)).hexdigest(),
        })
        _write_exclusive(dfd, RECORD, original)
        if _read(dfd, RECORD) != original:
            _hold()
    finally:
        os.close(dfd)
    return {"status": "ORIGINAL_CHECKPOINT_RECORDED_NOT_NATIVE_ACCEPTED",
            "install_authorized": False, "ssm_authorized": False}

def continue_original_checkpoint(directory, manifest, *,
                                 independently_selected_scope_sha256):
    """Read-only continuation; absence or changed origin is irrevocable HOLD."""
    expected = _selected(manifest,
                         original_scope_sha256=independently_selected_scope_sha256)
    dfd = _directory(directory)
    try:
        record = _read(dfd, RECORD)
        reservation = _read(dfd, RESERVATION)
        if (set(record) != FIELDS or record != expected
                or reservation != {
                    "schema": RESERVATION_SCHEMA,
                    "identity_sha256": "sha256:" + hashlib.sha256(
                        _canonical(record)).hexdigest(),
                }):
            _hold()
    finally:
        os.close(dfd)
    return {"status": "ORIGINAL_CHECKPOINT_CONTINUATION_MATCH_UNACCEPTED",
            "identity_sha256": "sha256:" + hashlib.sha256(
                _canonical(expected)).hexdigest(),
            "install_authorized": False, "ssm_authorized": False}
