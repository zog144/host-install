"""Source-owned read-only inspector for the *controller-present* Fonts destination.

This is NOT the controller-free prepared initializer, an approval to restore
the old Git revision, or a historical supersession receipt. It never creates
files, locks, Projects, SSM requests or execution identities.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from . import fonts_project_initialization as init
from . import fonts_project_migration as migration

SCHEMA = "zog-host-install-fonts-controller-present-inspection-v1"
EXPECTED_MANIFEST_SHA256 = "535c0c283599c8ad3e256d4cdf8db5bb4b16bf1350dfec59de10ebde52d79cb7"
NATIVE_PROJECT_UID = 24201
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_REV = re.compile(r"[0-9a-f]{40,64}\Z")
_MAX = 1024 * 1024


class InspectionHold(RuntimeError):
    """Untrusted historical destination or evidence path; no repair attempted."""


def require(value, message):
    if not value:
        raise InspectionHold(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


def _object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate key in historical destination evidence")
        result[name] = value
    return result


def _json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_object,
                           parse_constant=lambda name: (_ for _ in ()).throw(
                               InspectionHold("nonfinite historical evidence")))
    except (ValueError, UnicodeError) as error:
        raise InspectionHold("invalid historical destination JSON evidence") from error
    require(type(value) is dict, "historical destination JSON is not an object")
    return value


def _folder(parent, name):
    """Bind lstat to O_NOFOLLOW directory inode; never open a link."""
    require(type(name) is str and name and name not in (".", "..") and
            "/" not in name, "invalid fixed destination path component")
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISDIR(before.st_mode), "foreign directory in destination ancestry")
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    found = os.fstat(fd)
    if ((before.st_dev, before.st_ino, before.st_uid, before.st_gid,
         before.st_mode) != (found.st_dev, found.st_ino, found.st_uid,
                            found.st_gid, found.st_mode)):
        os.close(fd)
        raise InspectionHold("destination directory replaced during readback")
    sticky_root = (found.st_uid == 0 and
                   stat.S_IMODE(found.st_mode) == 0o1777)
    if found.st_mode & 0o022 and not sticky_root:
        os.close(fd)
        raise InspectionHold("destination directory is group/other writable")
    return fd, found


def _absolute(path):
    """Walk from real filesystem root through fixed no-follow descriptors."""
    path = Path(path)
    require(path.is_absolute() and str(path) != "/" and
            os.path.normpath(str(path)) == str(path),
            "noncanonical absolute historical Project")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    ancestry = [os.fstat(fd)]
    try:
        for piece in path.parts[1:]:
            next_fd, info = _folder(fd, piece)
            os.close(fd)
            fd = next_fd
            ancestry.append(info)
        return fd, ancestry
    except BaseException:
        os.close(fd)
        raise


def _file(folder, name, *, owners, maximum=_MAX):
    """Read fixed basename by anchored inode and verify post-read stability."""
    require(type(name) is str and name not in ("", ".", "..") and
            "/" not in name, "invalid historical evidence filename")
    try:
        original = os.stat(name, dir_fd=folder, follow_symlinks=False)
    except FileNotFoundError:
        return None, None
    require(stat.S_ISREG(original.st_mode) and original.st_nlink == 1
            and original.st_uid in owners and not original.st_mode & 0o022
            and 0 < original.st_size <= maximum,
            "unsafe historical Project evidence: " + name)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=folder)
    try:
        before = os.fstat(fd)
        keys = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                "st_nlink", "st_size")
        require(tuple(getattr(before, k) for k in keys) ==
                tuple(getattr(original, k) for k in keys),
                "historical evidence inode replaced: " + name)
        raw = os.read(fd, maximum + 1)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=folder, follow_symlinks=False)
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns) and
                tuple(getattr(named, k) for k in keys) ==
                tuple(getattr(before, k) for k in keys),
                "historical evidence changed during read: " + name)
        return raw, before
    finally:
        os.close(fd)


def _identity(observed):
    return {"device": observed.st_dev, "inode": observed.st_ino,
            "owner_uid": observed.st_uid, "owner_gid": observed.st_gid,
            "mode": stat.S_IMODE(observed.st_mode)}


def _git(directory, *, expected_repo, owners):
    """Read HEAD/tree/origin via an opened source directory, never write."""
    gitfd, metadata = _folder(directory, ".git")
    try:
        require(metadata.st_uid in owners,
                "foreign selected Git metadata ownership")
    finally:
        os.close(gitfd)
    source = os.fstat(directory)
    require(source.st_uid in owners, "foreign source Git checkout owner")
    env = os.environ.copy()
    env.update({"PATH": "/usr/bin:/bin", "GIT_OPTIONAL_LOCKS": "0",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
    result = {}
    for key, argv in (
        ("revision", ("rev-parse", "--verify", "HEAD")),
        ("tree", ("rev-parse", "--verify", "HEAD^{tree}")),
        ("origin", ("remote", "get-url", "origin")),
        ("top", ("rev-parse", "--show-toplevel")),
    ):
        done = subprocess.run(
            ["/usr/bin/git", "-C", "/proc/self/fd/" + str(directory), *argv],
            pass_fds=(directory,), capture_output=True, text=True,
            timeout=20, check=False, env=env)
        require(done.returncode == 0, "selected source Git evidence unavailable")
        result[key] = done.stdout.strip()
    require(_REV.fullmatch(result["revision"]) is not None and
            _REV.fullmatch(result["tree"]) is not None,
            "source Git object identity is invalid")
    require(result["origin"] in ("https://github.com/" + expected_repo,
                                 "https://github.com/" + expected_repo + ".git"),
            "source Git origin differs from original manifest")
    actual_root = os.readlink("/proc/self/fd/" + str(directory))
    require(result["top"] == actual_root,
            "source Git top-level redirects outside opened source directory")
    another, after_git = _folder(directory, ".git")
    os.close(another)
    require((after_git.st_dev, after_git.st_ino, after_git.st_uid,
             after_git.st_mode) ==
            (metadata.st_dev, metadata.st_ino, metadata.st_uid,
             metadata.st_mode) and
            (os.fstat(directory).st_dev, os.fstat(directory).st_ino) ==
            (source.st_dev, source.st_ino),
            "selected source/Git directory changed during observation")
    return {**result, "tree_sha256": hashlib.sha256(
        (result["tree"] + "\n").encode("ascii")).hexdigest(),
            "source_identity": _identity(source),
            "full_checkout_contents_authenticated": False}



def _manifest(data):
    expected = {key: {"repository": repo, "revision": revision}
                for key, (repo, revision) in init.SOURCES.items()}
    require(data.get("schema") == init.SCHEMA
            and data.get("project_root") == migration.NEW
            and data.get("source_checkouts") == expected
            and data.get("historical_project_materialized") is False
            and data.get("copy_performed") is False
            and data.get("account_selection") is False
            and data.get("controller_installed") is False
            and type(data.get("source_tree_sha256")) is dict
            and set(data["source_tree_sha256"]) == set(init.SOURCES)
            and all(type(x) is str and _HEX.fullmatch(x)
                    for x in data["source_tree_sha256"].values()),
            "original initialized manifest does not bind expected historical sources")


def inspect(*, root=Path("/")):
    """Return diagnostic facts without approving the controller or source.

    Native inspection runs as the existing root service without switching
    identity, and *observes* the already-owned UID 24201 Project. The
    supplied root is a disposable test fixture only, not a CLI option.
    """
    root = Path(root).absolute()
    native = root == Path("/")
    if native:
        require(os.geteuid() == 0, "native controller-present inspection needs root")
    owner = NATIVE_PROJECT_UID if native else os.geteuid()
    owners = {0, owner}
    target = root / migration.NEW.lstrip("/")
    fd, ancestry = _absolute(target)
    try:
        project = ancestry[-1]
        require(project.st_uid == owner and
                stat.S_IMODE(project.st_mode) == 0o700,
                "historical Project owner or private mode differs")
        require(all(x.st_uid in owners for x in ancestry),
                "foreign historical Project ancestor owner")
        initial_entries = sorted(os.listdir(fd))
        expected = {init.MANIFEST, "source", "companions", "state",
                    "controller-inherited-v1.json", *init.LAYOUT_DIRECTORIES}
        require({init.MANIFEST, "source", "companions", "state",
                 "controller-inherited-v1.json"} <= set(initial_entries)
                and set(initial_entries) <= expected,
                "unrecognized historical destination contents")
        require("controller.json" not in initial_entries,
                "unexpected second controller in original destination")

        manifest_raw, manifest_meta = _file(
            fd, init.MANIFEST, owners=owners)
        require(manifest_raw is not None,
                "historical initialization manifest is absent")
        manifest = _json(manifest_raw)
        require(manifest_raw == _canonical(manifest) + b"\n",
                "historical initialization manifest noncanonical")
        _manifest(manifest)
        canonical_sha = hashlib.sha256(_canonical(manifest)).hexdigest()
        require(canonical_sha == EXPECTED_MANIFEST_SHA256,
                "historical initialization manifest SHA differs")
        controller_raw, controller_meta = _file(
            fd, "controller-inherited-v1.json", owners=owners)
        require(controller_raw is not None,
                "historical destination controller is missing")
        _json(controller_raw)  # Structure only, not proof of authorization.

        state_fd, state_meta = _folder(fd, "state")
        source_fd, source_meta = _folder(fd, "source")
        companion_fd, companion_meta = _folder(fd, "companions")
        try:
            require(state_meta.st_uid == owner and
                    stat.S_IMODE(state_meta.st_mode) == 0o700,
                    "historical STATE owner or private mode differs")
            require(source_meta.st_uid in owners and
                    companion_meta.st_uid in owners,
                    "foreign historical source/companion owner")
            source_repo, expected_revision = init.SOURCES["source"]
            active_source = _git(source_fd, expected_repo=source_repo,
                                 owners=owners)
            companions = {}
            for key in ("companions/box-control", "companions/build-record"):
                repo, historical_revision = init.SOURCES[key]
                which = key.split("/")[-1]
                child, meta = _folder(companion_fd, which)
                try:
                    require(meta.st_uid in owners,
                            "foreign retained companion owner")
                    observed = _git(child, expected_repo=repo, owners=owners)
                finally:
                    os.close(child)
                companions[key] = {
                    **observed,
                    "historical_revision": historical_revision,
                    "manifest_tree_sha256": manifest["source_tree_sha256"][key],
                    "revision_matches_manifest": observed["revision"] == historical_revision,
                    "tree_matches_manifest": observed["tree_sha256"] ==
                        manifest["source_tree_sha256"][key],
                }
            layout = {}
            for name in init.LAYOUT_DIRECTORIES:
                if name not in initial_entries:
                    layout[name] = "absent"
                    continue
                child, entry = _folder(fd, name)
                try:
                    require(entry.st_uid in owners,
                            "foreign historical runtime directory owner")
                    layout[name] = "present"  # Never inspect or mutate runtime state.
                finally:
                    os.close(child)
            retained_state = _identity(state_meta)
        finally:
            os.close(state_fd)
            os.close(source_fd)
            os.close(companion_fd)

        # Check the same opened manifest and controller, plus state identity,
        # after Git and other readbacks. Do not claim a consistent snapshot
        # if the Project was replaced under our open descriptor.
        again_manifest, current_manifest = _file(
            fd, init.MANIFEST, owners=owners)
        again_controller, current_controller = _file(
            fd, "controller-inherited-v1.json", owners=owners)
        reread_state, state_after = _folder(fd, "state")
        os.close(reread_state)
        now_fd, now_ancestry = _absolute(target)
        try:
            require(_identity(now_ancestry[-1]) == _identity(project),
                    "historical Project identity changed during inspection")
        finally:
            os.close(now_fd)
        require(again_manifest == manifest_raw and
                current_manifest.st_ino == manifest_meta.st_ino and
                again_controller == controller_raw and
                current_controller.st_ino == controller_meta.st_ino and
                _identity(state_after) == retained_state and
                sorted(os.listdir(fd)) == initial_entries,
                "historical manifest/controller/STATE changed during readback")
        return {
            "schema": SCHEMA, "status": "controller-present-unresolved",
            "project_root": migration.NEW,
            "project": _identity(project),
            "effective_uid": os.geteuid(),
            "manifest_sha256": canonical_sha,
            "manifest_raw_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "manifest_inode": manifest_meta.st_ino,
            "historical_source_revision": expected_revision,
            "manifest_source_tree_sha256": manifest["source_tree_sha256"]["source"],
            "observed_source": active_source,
            "source_revision_matches_manifest":
                active_source["revision"] == expected_revision,
            "source_tree_matches_manifest":
                active_source["tree_sha256"] ==
                    manifest["source_tree_sha256"]["source"],
            "companions": companions,
            "controller_present": True,
            "controller_filename": "controller-inherited-v1.json",
            "controller_sha256": hashlib.sha256(controller_raw).hexdigest(),
            "controller": _identity(controller_meta),
            "state": retained_state, "runtime_layout": layout,
            "initialized_controller_authority": False,
            "historical_writer_authenticated": False,
            "manifest_replaced": False, "state_modified": False,
            "mutation": False, "ssm_send_authorized": False,
            "execution_authorized": False, "compilation_authorized": False,
        }
    finally:
        os.close(fd)


def main(argv=None):
    """Fixed native CLI; no root/UID/user/controller/source overrides."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", action="store_true", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(inspect(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
