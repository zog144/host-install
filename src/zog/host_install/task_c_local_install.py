"""Ordinary root-backed Task C software staging (no S3 or signed installer).

Installs local repository packages into one application venv and stages *disabled*
systemd units. This module never enables/starts a socket, service or SSM command.
Local root owns the installation. Exactly one trusted-Host gateway service
is selected; there is no broker, no second owner and no S3 authority.

Historical signed v3/v4 migration modules are deliberately not imported.
"""
from __future__ import annotations

import argparse
import importlib.resources
import json
import os
from pathlib import Path
import stat
import subprocess

SCHEMA = "zog-task-c-local-installation-v1"
MODULES = (
    "zog.host_deploy.gateway.generic_pipeline",
    "zog.host_deploy.gateway.trusted_host_submission",
    "zog.host_deploy.gateway.graphics_operation_send_intent",
    "zog.root_control.task_c_trusted_host",
)
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


def source_plan(*, root_control, host_deploy, host_install, python):
    """Explicit, locally selected repositories; not a remote trust grant."""
    roots = (
        _source(root_control, "root_control"),
        _source(host_deploy, "host_deploy"),
        _source(host_install, "host_install"),
    )
    _require(len(set(roots)) == len(roots), "component sources overlap")
    python = Path(python)
    _require(python.is_absolute() and python.is_file()
             and not python.is_symlink(),
             "selected installed Python executable must be an absolute file")
    return {
        "schema": SCHEMA,
        "root_control_source": str(roots[0]),
        "host_deploy_source": str(roots[1]),
        "host_install_source": str(roots[2]),
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
        root_control=plan["root_control_source"],
        host_deploy=plan["host_deploy_source"],
        host_install=plan["host_install_source"],
        python=plan["python"])
    _require(approved == plan, "installation plan changed")
    _directory(root, "/opt/zog/task-c", 0o755)
    venv_parent = _under(root, VENVDIR)
    if not venv_parent.exists():
        _run(runner, (plan["python"], "-m", "venv", str(venv_parent)))
    _require(venv_parent.is_dir() and not venv_parent.is_symlink(),
             "selected application venv absent")
    executable = venv_parent / "bin" / "python"
    _require(executable.is_file(), "venv Python not installed")
    _run(runner, (executable, "-m", "pip", "install", "--no-cache-dir",
                  plan["host_install_source"], plan["root_control_source"],
                  plan["host_deploy_source"]))
    _run(runner, (executable, "-m", "pip", "check"))
    # Require the actual trusted-Host gateway sender and durable local
    # journal modules, not proposed owner/trust modules which do not exist.
    _run(runner, (executable, "-I", "-c",
                  "import importlib; "
                  + "; ".join("importlib.import_module(" + repr(m) + ")"
                              for m in MODULES)))
    for path in DATA_DIRS:
        _directory(root, path, 0o700)
    _directory(root, UNIT_DIR, 0o755)
    for name, body in _units().items():
        _publish_unit(root, name, body)
    if root == Path("/"):
        _run(runner, ("/usr/bin/systemctl", "daemon-reload"))
    # No systemctl enable/start/restart, no socket activation, AWS, S3 or SSM.
    return {"schema": SCHEMA, "status": "software-and-disabled-units-staged",
            "units": list(UNITS), "native_runtime_started": False,
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
    parser.add_argument("--root-control-source")
    parser.add_argument("--host-deploy-source")
    parser.add_argument("--host-install-source")
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
                args.root_control_source, args.host_deploy_source,
                args.host_install_source, args.python)):
            parser.error("--plan/--stage require all three sources and --python")
        selected = source_plan(
            root_control=args.root_control_source,
            host_deploy=args.host_deploy_source,
            host_install=args.host_install_source,
            python=args.python)
        result = stage(selected) if args.stage else selected
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
