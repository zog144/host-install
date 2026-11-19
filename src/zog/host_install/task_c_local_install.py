"""Ordinary root-backed Task C software staging (no S3 or signed installer).

Installs local repository packages into one application venv and stages *disabled*
systemd units. This module never enables/starts a socket, service or SSM command.
Local root owns the installation. Exactly one trusted-Host gateway service
is selected; there is no broker, no second owner and no S3 authority.

Historical signed v3/v4 migration modules are deliberately not imported.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.resources
import json
import os
from pathlib import Path
import stat
import subprocess

from .task_c_journal_directory import (
    DIRECTORY as JOURNAL_DIR, ensure_operations, TaskCJournalDirectoryError,
)

SCHEMA = "zog-task-c-local-installation-v1"
MODULES = (
    "zog.host_deploy.gateway.generic_pipeline",
    "zog.host_deploy.gateway.trusted_host_submission",
    "zog.host_deploy.gateway.graphics_operation_send_intent",
    "zog.root_control.task_c_trusted_host",
)
ROOT_CONTROL_REVISION = "b655b0a2b2ba7abb5fddbdaadae01ef6e34bcb56"
ROOT_CONTROL_JOURNAL_GIT_BLOB = "de63bac2261d639eb9f1177ef92651bbd3fcb750"
ROOT_CONTROL_JOURNAL_REL = "src/zog/root_control/task_c_trusted_host.py"
VENVDIR = "/opt/zog/task-c/venv"
DATA_DIRS = (
    "/var/lib/host-deploy-gateway",
)
UNITS = (
    "zog-task-c-gateway.service",
)
UNIT_DIR = "/etc/systemd/system"


class TaskCInstallError(RuntimeError):
    pass


def _require(value, message):
    if not value:
        raise TaskCInstallError(message)


def _source(path, package):
    path = Path(path).absolute()
    _require(path.is_dir() and not path.is_symlink(),
             "source repository must be a real directory")
    _require((path / "pyproject.toml").is_file() and
             (path / "src" / "zog" / package).is_dir(),
             "incorrect component repository: " + package)
    return path


def _reviewed_root_control(source):
    """Verify original selected Git revision and exact journal source bytes."""
    source = Path(source)
    path = source / ROOT_CONTROL_JOURNAL_REL
    _require(path.is_file() and not path.is_symlink(),
             "selected root-control Task C journal source absent or linked")
    raw = path.read_bytes()
    git_blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()
    _require(git_blob == ROOT_CONTROL_JOURNAL_GIT_BLOB,
             "selected root-control journal source differs from reviewed bytes")
    try:
        selected = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "--verify", "HEAD"],
            text=True, capture_output=True, timeout=10, check=False,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TaskCInstallError("cannot inspect selected root-control Git HEAD") from exc
    _require(selected.returncode == 0
             and selected.stdout.strip() == ROOT_CONTROL_REVISION,
             "selected root-control source revision differs from reviewed candidate")
    return {"revision": selected.stdout.strip(), "journal_git_blob": git_blob}


def source_plan(*, host_deploy, host_install, root_control, python):
    """Explicit, locally selected repositories; not a remote trust grant."""
    roots = (
        _source(host_deploy, "host_deploy"),
        _source(host_install, "host_install"),
        _source(root_control, "root_control"),
    )
    _require(len(set(roots)) == len(roots), "component sources overlap")
    journal_source = _reviewed_root_control(roots[2])
    python = Path(python)
    _require(python.is_absolute() and python.is_file()
             and not python.is_symlink(),
             "selected installed Python executable must be an absolute file")
    return {
        "schema": SCHEMA,
        "host_deploy_source": str(roots[0]),
        "host_install_source": str(roots[1]),
        "root_control_source": str(roots[2]),
        "root_control_revision": journal_source["revision"],
        "root_control_journal_git_blob": journal_source["journal_git_blob"],
        "root_control_journal": JOURNAL_DIR,
        "journal_owner": "root:root",
        "journal_mode": "0700",
        "python": str(python),
        "venv": VENVDIR,
        "data_directories": list(DATA_DIRS),
        "units": list(UNITS),
        "runtime_modules": list(MODULES),
        "s3_required": False,
        "signed_storage_approval_required": False,
        "separate_storage_volume_required": False,
        "service_activation": False,
        "ssm_execution": False,
    }


def _under(root, path):
    _require(path.startswith("/"), "fixed absolute destination required")
    return root / path.lstrip("/")


def _directory(root, path, mode):
    dest = _under(root, path)
    top = root
    _require(top.is_dir() and not top.is_symlink(),
             "installation root missing or symlink")
    for name in Path(path).parts[1:]:
        top = top / name
        _require(not top.is_symlink(), "symlinked installation ancestor")
        if not top.exists():
            top.mkdir(mode=mode if top == dest else 0o755)
        _require(top.is_dir() and not top.is_symlink(),
                 "installation path is not a directory")
    dest.chmod(mode)
    return dest


def _publish_unit(root, name, body):
    """Atomic normal root-owned systemd file, no signed unit ceremony."""
    _require(name in UNITS and type(body) is bytes and body,
             "unrecognized systemd unit")
    dest = _under(root, UNIT_DIR) / name
    if dest.exists() or dest.is_symlink():
        st = dest.lstat()
        _require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
                 and not dest.is_symlink(),
                 "existing unit is not an ordinary regular file")
        if dest.read_bytes() == body:
            return
    pending = dest.with_name("." + name + ".pending")
    _require(not pending.exists() and not pending.is_symlink(),
             "foreign interrupted pending unit")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o644)
    try:
        os.write(fd, body)
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(pending, dest)
    folder = os.open(dest.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(folder)
    finally:
        os.close(folder)


def _units():
    base = importlib.resources.files("zog.host_install").joinpath(
        "systemd", "task-c-local")
    return {name: base.joinpath(name).read_bytes() for name in UNITS}


def _run(runner, args):
    result = runner(list(map(str, args)), check=False)
    _require(result.returncode == 0,
             "ordinary Python/systemd installation command failed")


def _require_gateway_inactive(runner):
    """Do not overwrite the selected runtime while it is running."""
    result = runner(
        ["/usr/bin/systemctl", "is-active", "--quiet", UNITS[0]],
        check=False,
    )
    _require(result.returncode in (3, 4),
             "Task C Gateway is active or its inactive state cannot be established")


def stage(plan, *, root=Path("/"), runner=subprocess.run):
    """Root-only package + disabled unit staging; no command can send SSM.

    A non-/ disposable root is an internal regression fixture, not a CLI
    option. Unit publication happens only after normal pip check and exact
    local runtime-module imports; any missing consumer prevents service setup.
    """
    _require(type(plan) is dict and plan.get("schema") == SCHEMA,
             "reviewed local installation plan required")
    _require(os.geteuid() == 0, "normal privileged Host install requires root")
    root = Path(root).absolute()
    _require(root.is_dir() and not root.is_symlink(), "invalid installation root")
    # Validate sources again rather than trusting a stale plan.
    approved = source_plan(
        host_deploy=plan["host_deploy_source"],
        host_install=plan["host_install_source"],
        root_control=plan["root_control_source"],
        python=plan["python"])
    _require(approved == plan, "installation plan changed")
    if root == Path("/"):
        _require_gateway_inactive(runner)
    # Before Python package installation or unit publication, fail closed
    # against foreign journal custody. No mkdir/chmod/chown by the Gateway.
    try:
        journal_directory = ensure_operations(root)
    except TaskCJournalDirectoryError as exc:
        raise TaskCInstallError(str(exc)) from exc
    _directory(root, "/opt/zog/task-c", 0o755)
    venv_parent = _under(root, VENVDIR)
    if not venv_parent.exists():
        _run(runner, (plan["python"], "-m", "venv", str(venv_parent)))
    _require(venv_parent.is_dir() and not venv_parent.is_symlink(),
             "selected application venv absent")
    executable = venv_parent / "bin" / "python"
    _require(executable.is_file(), "venv Python not installed")
    # Install the selected reviewed root-control module IN THE SAME Task C
    # gateway venv as host-deploy, with ordinary package dependencies and
    # pip check. A separate root-control environment would leave the owner
    # journal unavailable to host-deploy's real CLI.
    _run(runner, (executable, "-m", "pip", "install", "--no-cache-dir",
                  plan["host_install_source"], plan["host_deploy_source"],
                  plan["root_control_source"]))
    _run(runner, (executable, "-m", "pip", "check"))
    # Require all actual gateway imports and the real root-control send-once
    # journal from the selected Python environment. Import is not enough:
    # compare the installed journal source bytes with the reviewed Git blob.
    import_check = (
        "import hashlib, importlib, pathlib; "
        + "; ".join("importlib.import_module(" + repr(m) + ")"
                    for m in MODULES)
        + "; from zog.root_control import task_c_trusted_host as j"
        + "; p=pathlib.Path(j.__file__)"
        + "; data=p.read_bytes()"
        + "; h=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\\0'+data).hexdigest()"
        + "; assert h==" + repr(ROOT_CONTROL_JOURNAL_GIT_BLOB)
        + "; assert j.DEFAULT_DIRECTORY==" + repr(JOURNAL_DIR)
        + "; assert getattr(j,'LocalTaskCJournal',None) is not None"
    )
    _run(runner, (executable, "-I", "-c", import_check))
    for path in DATA_DIRS:
        _directory(root, path, 0o700)
    _directory(root, UNIT_DIR, 0o755)
    for name, body in _units().items():
        _publish_unit(root, name, body)
    if root == Path("/"):
        _run(runner, ("/usr/bin/systemctl", "daemon-reload"))
        _require_gateway_inactive(runner)
    # No systemctl enable/start/restart, no socket activation, AWS, S3 or SSM.
    return {"schema": SCHEMA, "status": "software-and-disabled-units-staged",
            "units": list(UNITS), "journal": journal_directory,
            "root_control_revision": ROOT_CONTROL_REVISION,
            "native_runtime_started": False, "gateway_active": False,
            "ssm_authorized": False}



def inspect_local_host_state():
    """Read existing canonical Host/STATE identity, never issue a new identity.

    This is a separate *optional* read-only step after /state preparation.
    It is not a prerequisite to installing disabled Python software on a
    retained Host whose existing /state migration is still underway.
    """
    from .state_inspect import inspect_live
    with inspect_live() as context:
        context.recheck()
        bootstrap = context.bundle["bootstrap"]
        state = bootstrap["state"]
        result = {
            "schema": "zog-task-c-local-host-state-observation-v1",
            "status": "existing-local-installation-observed",
            "installation_id": bootstrap["installation_id"],
            "state_id": state["state_volume_id"],
            "state_backend": state.get("storage_backend", "mounted-volume"),
            "root_filesystem_uuid": state["filesystem_uuid"],
            "expected_host_uuid": bootstrap["initialization"].get(
                "expected_host_uuid"),
            "ssm_authorized": False,
        }
        context.recheck()
        return result

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Stage local Task C Python software and disabled systemd units")
    parser.add_argument("--host-deploy-source")
    parser.add_argument("--host-install-source")
    parser.add_argument("--root-control-source")
    parser.add_argument("--python")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--plan", action="store_true")
    action.add_argument("--stage", action="store_true")
    action.add_argument("--inspect-state", action="store_true",
                        help="read-only existing canonical installation/STATE")
    args = parser.parse_args(argv)
    if args.inspect_state:
        result = inspect_local_host_state()
    else:
        if any(not value for value in (
                args.host_deploy_source, args.host_install_source,
                args.root_control_source, args.python)):
            parser.error("--plan/--stage require host-deploy, host-install, root-control and --python")
        selected = source_plan(
            host_deploy=args.host_deploy_source,
            host_install=args.host_install_source,
            root_control=args.root_control_source,
            python=args.python)
        result = stage(selected) if args.stage else selected
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
