"""Source-only migration admission: bind a selected bundle, original evidence and runtime.

This module deliberately cannot create production /state or authorize a service,
account, or identity mutation. Native acceptance must supply independently
authenticated live observations and a separately reviewed protected executor.
"""
import copy
import hashlib
import uuid
import os
from pathlib import Path
import re
import stat

from .state_contract import StateError, canonical, decode, digest, require, validate
from .state_account_migration import (
    JOURNAL_SCHEMA, SCHEMA, review_source_migration,
)
from .state_account_migration_consumer import CONSUMER_SELECTION

CANDIDATE_ROOT = (
    "/opt/host-discover/candidates/"
    "retained-legacy-3fd8bd0-3d94f34-20261109/venv"
)
ADMISSION_SCHEMA = "zog-registry-state-migration-admission-selection-v1"
RUNTIME_SCHEMA = "zog-registry-state-migration-runtime-selection-v1"
# Source selection, NOT a verified or installed filesystem assertion.
CANDIDATE_EXECUTABLE = CANDIDATE_ROOT + "/bin/host-discover"
CANDIDATE_PYTHON = CANDIDATE_ROOT + "/bin/python3.12"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def assemble_migration_bundle(template, *, installation_id, state_volume_id,
                              installation_record_id, authorization_id,
                              root_fs_uuid, root_partuuid,
                              host_uuid, fingerprint, registry_origin):
    """Create a canonical non-resident migration bundle from explicit selections.

    UUIDs and installed Host facts must be independently authorized/reobserved
    by the native issuer. This pure builder does not create an installation or
    grant its own authorization_id; it never initializes another Host key.
    """
    require(type(template) is dict, "migration-bundle", "template required")
    validate(template)
    require(template["bootstrap"]["mode"] == "fresh"
            and template["installation"]["operation"] == "fresh"
            and template["installation"]["installation_mode"] == "non-resident",
            "migration-bundle", "only uninstalled non-resident template accepted")
    supplied = (installation_id, state_volume_id, installation_record_id,
                authorization_id, root_fs_uuid, root_partuuid, host_uuid)
    def valid_uuid(value):
        try:
            return type(value) is str and str(uuid.UUID(value)) == value \
                and uuid.UUID(value).int != 0
        except (ValueError, AttributeError, TypeError):
            return False
    require(all(valid_uuid(x) for x in supplied)
            and len(set(supplied)) == len(supplied)
            and type(fingerprint) is str and HEX64.fullmatch(fingerprint)
            and type(registry_origin) is str
            and registry_origin.startswith("https://")
            and registry_origin.rstrip("/") == registry_origin,
            "migration-bundle", "distinct identifiers and original Host binding required")
    b = copy.deepcopy(template)
    bootstrap, installation, marker = b["bootstrap"], b["installation"], b["marker"]
    installation["installation_id"] = installation_id
    installation["record_id"] = installation_record_id
    installation["operation"] = "migration"
    bootstrap["installation_id"] = installation_id
    bootstrap["mode"] = "migration"
    bootstrap["initialization"]["authorization_id"] = authorization_id
    bootstrap["initialization"]["expected_host_uuid"] = host_uuid
    bootstrap["initialization"]["expected_fingerprint"] = fingerprint
    controls = [r for r in bootstrap["registries"] if r["role"] == "control"]
    require(len(controls) == 1, "migration-bundle", "one existing control origin required")
    controls[0]["origin"] = registry_origin
    controls[0]["ca"] = None
    marker.update(schema=2, kind="zog-state-directory", backing_root="/",
                  installation_id=installation_id, state_volume_id=state_volume_id,
                  filesystem_uuid=root_fs_uuid, partition_partuuid=root_partuuid)
    state = bootstrap["state"]
    state.update(storage_backend="root-directory", filesystem_type="directory",
                 state_volume_id=state_volume_id, filesystem_uuid=root_fs_uuid,
                 partition_partuuid=root_partuuid)
    state["marker_sha256"] = digest(marker)
    installation["installer_recorded"]["marker_sha256"] = digest(marker)
    bootstrap["installation_record"]["sha256"] = digest(installation)
    validate(b)
    return b


def select_runtime(executable, interpreter, executable_sha256,
                   interpreter_sha256, *, fs_root="/", disposable=False):
    """Read-only installed-byte selection, including resolved interpreter target.

    A selection is only observation. It is never a production admission token.
    The caller must independently attest installed distribution RECORD and
    effective service sandbox, not infer them from these two SHA-256 values.
    """
    require(executable == CANDIDATE_EXECUTABLE and
            interpreter == CANDIDATE_PYTHON and
            all(type(x) is str and HEX64.fullmatch(x) for x in
                (executable_sha256, interpreter_sha256)),
            "migration-runtime", "exact candidate paths and hashes required")
    root = Path(fs_root)
    require((root == Path("/") or disposable) and root.is_absolute()
            and not root.is_symlink(), "migration-runtime",
            "only selected filesystem view allowed")
    def verify(path, expected):
        item = root / path.lstrip("/")
        # Refuse symlinked ancestors; venv/bin/python3.12 may itself be a
        # symlink, so resolve it only within the selected venv.
        cur = root
        for part in Path(path).parts[1:-1]:
            previous = cur.lstat()
            require(stat.S_ISDIR(previous.st_mode)
                    and previous.st_uid == 0
                    and not previous.st_mode & 0o022,
                    "migration-runtime", "unprotected candidate ancestor")
            cur = cur / part
            require(not cur.is_symlink(), "migration-runtime",
                    "intermediate candidate path is a symlink")
        parent_info = cur.lstat()
        require(stat.S_ISDIR(parent_info.st_mode)
                and parent_info.st_uid == 0
                and not parent_info.st_mode & 0o022,
                "migration-runtime", "unprotected candidate bin directory")
        require(item.exists(), "migration-runtime", "candidate file absent")
        resolved = item.resolve(strict=True)
        venv_root = (root / CANDIDATE_ROOT.lstrip("/")).resolve()
        # The venv's python3.12 is often a symlink to the protected host
        # interpreter; only that exact root-owned system path is admissible.
        system_python = root / "usr/bin/python3.12"
        require(resolved.is_file() and (
                    resolved.is_relative_to(venv_root)
                    or (path == CANDIDATE_PYTHON and
                        resolved == system_python)),
                "migration-runtime",
                "candidate executable or Python target outside selection")
        if resolved == system_python:
            for parent in (root / "usr", root / "usr/bin"):
                ps = parent.lstat()
                require(stat.S_ISDIR(ps.st_mode) and ps.st_uid == 0
                        and not ps.st_mode & 0o022,
                        "migration-runtime", "unprotected system Python ancestry")
        s = resolved.stat()
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0
                and s.st_gid == 0 and s.st_nlink == 1
                and (s.st_mode & 0o022) == 0,
                "migration-runtime", "candidate bytes not protected")
        h = hashlib.sha256()
        with resolved.open("rb") as fd:
            for chunk in iter(lambda: fd.read(65536), b""):
                h.update(chunk)
        require(h.hexdigest() == expected, "migration-runtime",
                "installed candidate digest mismatch")
        return [s.st_dev, s.st_ino]
    executable_inode = verify(executable, executable_sha256)
    interpreter_inode = verify(interpreter, interpreter_sha256)
    # The selected console-script must actually invoke that same interpreter.
    # A matching script SHA-256 alone does not prevent a foreign shebang from
    # launching an unreviewed environment.
    script = root / executable.lstrip("/")
    with script.open("rb") as fp:
        shebang = fp.readline(256)
    require(shebang.startswith(b"#!") and shebang.endswith(b"\n")
            and len(shebang) < 256,
            "migration-runtime", "reviewed console-script shebang required")
    try:
        selected_python = shebang[2:].strip().decode("ascii")
    except UnicodeError as exc:
        raise StateError("migration-runtime", "invalid shebang encoding") from exc
    allowed_python = {CANDIDATE_PYTHON, CANDIDATE_ROOT + "/bin/python",
                      CANDIDATE_ROOT + "/bin/python3"}
    require(selected_python in allowed_python
            and (root / selected_python.lstrip("/")).resolve(strict=True) ==
                (root / interpreter.lstrip("/")).resolve(strict=True),
            "migration-runtime", "candidate script bypasses selected Python")
    return {
        "schema": RUNTIME_SCHEMA,
        "consumer_selection_sha256": digest(CONSUMER_SELECTION),
        "executable": executable,
        "interpreter": interpreter,
        "executable_sha256": executable_sha256,
        "interpreter_sha256": interpreter_sha256,
        "executable_inode": executable_inode,
        "interpreter_inode": interpreter_inode,
    }


def review_admission(bundle, source_inputs, runtime, *,
                     original_identity_inodes, original_credential_inodes,
                     authorization_reference):
    """Construct one reviewable, content-addressed admission selection.

    This function accepts source inputs only; it cannot authenticate that
    observations came from the Host or that authorization was issued.
    """
    validate(bundle)
    require(type(source_inputs) is dict and
            set(source_inputs) == {
                "migration_id", "root_observation", "account_snapshot",
                "file_inventory", "configuration_bytes", "binding",
                "public_identity_witness", "unit_bytes", "service_snapshot",
                "consumer_contract",
            } and source_inputs["consumer_contract"] == CONSUMER_SELECTION,
            "migration-admission", "complete selected review inputs required")
    plan = review_source_migration(bundle, **source_inputs)
    from .state_account_migration_launcher import render_launcher_dropin
    # The bare review_source_migration retains an intentionally unrendered
    # placeholder. An admitted plan MUST hash only the selected Python 3.12
    # drop-in that will actually be published by the native adapter.
    require(type(runtime) is dict
            and runtime.get("interpreter") == CANDIDATE_PYTHON,
            "migration-admission", "reviewed launcher interpreter required")
    plan["unit_dropin_sha256"] = hashlib.sha256(
        render_launcher_dropin(runtime["interpreter"])).hexdigest()
    inventory = source_inputs["file_inventory"]
    identity = {k: [v["dev"], v["inode"]]
                for k,v in inventory.items() if k in (
                    "identity.pem", "binding.json", "key.lock",
                    "registry-ca.pem", "mirror-role.json", "mirror-role.lock",
                    "primary-origin.json") and v is not None}
    require(type(original_identity_inodes) is dict and
            all(original_identity_inodes.get(k) == v for k,v in identity.items())
            and set(original_identity_inodes) in (
                set(identity), set(identity) | {"directory"}),
            "migration-admission", "original identity inode witness mismatch")
    require(type(original_credential_inodes) is dict
            and set(original_credential_inodes) ==
                set(inventory["credential_files"])
            and all(type(p) is list and len(p) == 2
                    and all(type(n) is int and n > 0 for n in p)
                    for p in original_credential_inodes.values()),
            "migration-admission", "original credential inode witness required")
    require(type(runtime) is dict and
            runtime.get("schema") == RUNTIME_SCHEMA
            and runtime.get("consumer_selection_sha256") ==
                plan["consumer_selection_sha256"]
            and runtime.get("executable") == CANDIDATE_EXECUTABLE
            and runtime.get("interpreter") == CANDIDATE_PYTHON
            and all(type(runtime.get(k)) is str
                    and HEX64.fullmatch(runtime[k]) for k in
                    ("executable_sha256", "interpreter_sha256"))
            and all(type(runtime.get(k)) is list and
                    len(runtime[k]) == 2 and
                    all(type(n) is int and n > 0 for n in runtime[k])
                    for k in ("executable_inode", "interpreter_inode")),
            "migration-admission", "exact installed runtime evidence required")
    require(type(authorization_reference) is str and
            re.fullmatch(r"[a-zA-Z0-9_.:/-]{8,256}", authorization_reference),
            "migration-admission", "nonempty distinct authorization reference required")
    selection = {
        "schema": ADMISSION_SCHEMA,
        "plan": plan,
        "bundle_sha256": digest(bundle),
        "identity_inodes": original_identity_inodes,
        "credential_inodes": original_credential_inodes,
        "runtime": runtime,
        "authorization_reference": authorization_reference,
    }
    return selection


def initial_journal(selection):
    """Exact initial row, not executable authorization."""
    require(type(selection) is dict and
            selection.get("schema") == ADMISSION_SCHEMA
            and type(selection.get("plan")) is dict
            and selection["plan"].get("schema") == SCHEMA,
            "migration-admission", "reviewed selection required")
    plan = selection["plan"]
    return {
        "schema": JOURNAL_SCHEMA,
        "migration_id": plan["migration_id"],
        "plan_sha256": digest(plan),
        "status": "applying",
        "completed": [],
        "active": None,
    }


def publish_disposable_admission(folder, selection, *, disposable=False):
    """Crash-resilient, no-replace test publication; NEVER production root.

    No live Host pathname can be supplied to this helper. Root-owned
    production issuer, exclusive lock, reobservation and monotonic journal
    remain separate reviewed prerequisites.
    """
    p = Path(folder).absolute()
    # Explicit opt-in and a temporary test subtree are necessary. Never
    # interpret a 'root-owned empty folder' as authorization for production.
    require(disposable and os.geteuid() == 0 and p.is_dir()
            and not p.is_symlink()
            and (p.is_relative_to("/tmp/") or p.is_relative_to("/var/tmp/"))
            and p.stat().st_uid == 0
            and stat.S_IMODE(p.stat().st_mode) == 0o700
            and not any(p.iterdir()),
            "migration-admission", "empty protected disposable directory required")
    payloads = {
        "plan.json": canonical(selection["plan"]),
        "admission.json": canonical(selection),
        "transaction.json": canonical(initial_journal(selection)),
    }
    fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name, raw in payloads.items():
            item = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                remaining = memoryview(raw)
                while remaining:
                    written = os.write(item, remaining)
                    require(written > 0, "migration-admission",
                            "incomplete durable record write")
                    remaining = remaining[written:]
                os.fsync(item)
            finally:
                os.close(item)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"status": "disposable-source-only",
            "admission_sha256": digest(selection),
            "native_accepted": False}
