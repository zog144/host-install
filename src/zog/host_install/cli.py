import argparse
import json
import sys
import subprocess
from pathlib import Path

from . import InstallError
from .state_contract import StateError, decode, validate
from .state_inspect import inspect_report
from .state_probe import probe_live
from .state_provision import stage_overlay, prepare_live
from .state_initialize import authorize_live, initialize_live
from .state_admission import serve_stdin, serve_listener
from .certificate_gate import decide as certificate_decide
from .welcome_readiness import serve_stdin as welcome_readiness_serve
from .certificate_lifecycle import (
    load_record as certificate_lifecycle_load,
    reconcile as certificate_lifecycle_reconcile,
    store_record as certificate_lifecycle_store,
)
from . import (beacon_profile, application_progress_profile,
               host_welcome_progress_profile, image_progress_profile,
               certify_manage_profile)
from .artifact import stage
from .filesystem import build_root_fixture
from .image import inspect, install
from .layout import plan
from .manifest import MIB, parse
from .preflight import assess, collect


def main(argv=None):
    parser = argparse.ArgumentParser(prog="host-install")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "preflight", "assemble-fixture"):
        cmd = sub.add_parser(name)
        cmd.add_argument("manifest", type=Path)
        cmd.add_argument("--disk-mib", required=True, type=int)
        if name == "preflight":
            cmd.add_argument("--target", required=True)
            cmd.add_argument("--identity", required=True)
        if name == "assemble-fixture":
            cmd.add_argument("--artifacts", type=Path, required=True)
            cmd.add_argument("--operation", type=Path, required=True)
    cmd = sub.add_parser("inspect")
    cmd.add_argument("operation", type=Path)
    cmd = sub.add_parser("stage-artifact")
    cmd.add_argument("directory", type=Path)
    cmd.add_argument("--expected-id", required=True)
    cmd.add_argument("--operation", type=Path, required=True)
    cmd = sub.add_parser("build-root-fixture")
    cmd.add_argument("staging", type=Path)
    cmd.add_argument("--operation", type=Path, required=True)
    cmd.add_argument("--mib", type=int, required=True)
    cmd.add_argument("--filesystem-uuid", required=True)
    cmd = sub.add_parser("state-validate", help="validate an offline synthetic record bundle")
    cmd.add_argument("bundle", type=Path)
    sub.add_parser("state-inspect", help="read-only inspection of canonical live STATE")
    sub.add_parser("state-probe", help="explicit STATE write probe as UID/GID 970")
    cmd = sub.add_parser("state-stage", help="publish a new offline configuration overlay")
    cmd.add_argument("bundle", type=Path)
    cmd.add_argument("--output", type=Path, required=True)
    cmd.add_argument("--previous-bundle", type=Path)
    cmd.add_argument("--ca-directory", type=Path)
    cmd = sub.add_parser("state-prepare", help="provision directories only on verified live STATE")
    cmd.add_argument("--initialize-volume", help="explicit fresh volume UUID; never generates a key")
    cmd = sub.add_parser("state-authorize", help="explicit root-owned identity initialization authorization")
    cmd.add_argument("--initialization-id", required=True)
    sub.add_parser("state-initialize", help="consume an existing installer authorization using UID 970")
    sub.add_parser("state-admission-serve", help="serve one privileged observation on a systemd accepted socket")
    cmd = sub.add_parser("beacon-prepare", help="explicit supervisor provisioning; never run at boot")
    cmd.add_argument("--state-volume-id", required=True)
    cmd = sub.add_parser("beacon-stage", help="stage reviewed managed-beacon systemd profile offline")
    cmd.add_argument("--discover-source", type=Path, required=True)
    cmd.add_argument("--producer-source", type=Path, help="optional checkout used only to verify packaged host-install templates")
    cmd.add_argument("--output", type=Path, required=True)
    cmd.add_argument("--executable-directory", default="/usr/bin")
    sub.add_parser("state-admission-listen", help="serve the systemd listener until ordered shutdown")
    sub.add_parser("welcome-readiness-serve", help="serve one sanitized bootstrap readiness snapshot on a systemd accepted socket")
    cmd = sub.add_parser("application-progress-stage", help="stage the protected station application-progress observer profile")
    cmd.add_argument("--output", type=Path, required=True)
    cmd.add_argument("--controller-project", required=True)
    cmd.add_argument("--station-consumer-uid", type=int, required=True)
    cmd.add_argument("--station-consumer-gid", type=int, required=True)
    cmd.add_argument("--controller-owner-uid", type=int, required=True)
    cmd.add_argument("--controller-owner-gid", type=int, required=True)
    cmd.add_argument("--host-bindings-policy", type=Path, required=True)
    cmd.add_argument("--python-executable", default="/usr/bin/python3")
    cmd.add_argument("--producer-source", type=Path)
    cmd = sub.add_parser("host-welcome-progress-stage", help="stage the dedicated host-welcome observer using independently resolved live UIDs")
    cmd.add_argument("--output", type=Path, required=True)
    cmd.add_argument("--controller-project", required=True)
    cmd.add_argument("--box-control-source", type=Path, required=True)
    cmd.add_argument("--python-executable", default="/usr/bin/python3")
    cmd.add_argument("--producer-source", type=Path)
    cmd = sub.add_parser("host-welcome-progress-attest-installed", help="attest actual aggregate box-control observer bytes against reviewed source and wheel RECORD")
    cmd.add_argument("--python-executable", default="/usr/bin/python3")
    cmd = sub.add_parser("host-welcome-image-progress-stage", help="stage the dedicated image-build progress observer using independently resolved live UIDs")
    cmd.add_argument("--output", type=Path, required=True)
    cmd.add_argument("--image-build-state-root", required=True)
    cmd.add_argument("--image-build-source", type=Path, required=True)
    cmd.add_argument("--python-executable", default="/usr/bin/python3")
    cmd.add_argument("--producer-source", type=Path)
    cmd = sub.add_parser("host-welcome-image-progress-attest-installed", help="attest aggregate image-build observer bytes against reviewed source and wheel RECORD")
    cmd.add_argument("--python-executable", default="/usr/bin/python3")
    cmd = sub.add_parser("certify-manage-native-stage", help="stage the native certify-manage controller/application profile without activating it")
    cmd.add_argument("--output", type=Path, required=True)
    cmd.add_argument("--controller-project", required=True)
    cmd.add_argument("--root-control-socket", required=True)
    cmd.add_argument("--lifecycle-consumer-account", required=True)
    cmd.add_argument("--generation", required=True)
    cmd.add_argument("--software-result", type=Path, required=True)
    cmd.add_argument("--host-bindings-policy", type=Path, required=True)
    cmd.add_argument("--image-build-source", type=Path, required=True)
    cmd.add_argument("--certify-manage-source", type=Path, required=True)
    cmd = sub.add_parser("certify-manage-prepared-attest", help="attest actual prepared issuer grant and certificate-data storage")
    cmd.add_argument("--controller-project", required=True)
    cmd.add_argument("--root-control-socket", required=True)
    cmd.add_argument("--software-view", required=True)
    cmd = sub.add_parser("certify-manage-controller-attest-installed", help="attest installed box-control/root-control issuer controller bytes")
    cmd.add_argument("--python-executable", default="/usr/bin/python3")
    cmd = sub.add_parser("certificate-status", help="evaluate detached secret-free certificate enablement evidence")
    cmd.add_argument("evidence", type=Path)
    cmd = sub.add_parser(
        "certificate-lifecycle-simulate",
        help="advance a secret-free certificate lifecycle record from simulated application evidence",
    )
    cmd.add_argument("observation", type=Path)
    cmd.add_argument("--record", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "certify-manage-controller-attest-installed":
            result = certify_manage_profile.attest_installed_controller(
                python_executable=args.python_executable,
            )
        elif args.command == "certify-manage-prepared-attest":
            result = certify_manage_profile.attest_prepared(
                controller_project=args.controller_project,
                root_control_socket=args.root_control_socket,
                expected_software_view=args.software_view,
            )
        elif args.command == "certify-manage-native-stage":
            result = certify_manage_profile.stage_live(
                output=args.output,
                controller_project=args.controller_project,
                root_control_socket=args.root_control_socket,
                lifecycle_consumer_account=args.lifecycle_consumer_account,
                generation=args.generation,
                software_result=args.software_result,
                host_bindings_policy=args.host_bindings_policy,
                image_build_source=args.image_build_source,
                certify_manage_source=args.certify_manage_source,
            )
        elif args.command == "host-welcome-image-progress-attest-installed":
            result = image_progress_profile.verify_installed(
                python_executable=args.python_executable,
            )
        elif args.command == "host-welcome-image-progress-stage":
            result = image_progress_profile.stage_live(
                output=args.output,
                image_build_state_root=args.image_build_state_root,
                image_build_source=args.image_build_source,
                python_executable=args.python_executable,
                producer_source=args.producer_source,
            )
        elif args.command == "host-welcome-progress-attest-installed":
            result = host_welcome_progress_profile.verify_installed(
                python_executable=args.python_executable,
            )
        elif args.command == "host-welcome-progress-stage":
            result = host_welcome_progress_profile.stage_live(
                output=args.output,
                controller_project=args.controller_project,
                box_control_source=args.box_control_source,
                python_executable=args.python_executable,
                producer_source=args.producer_source,
            )
        elif args.command == "application-progress-stage":
            result = application_progress_profile.stage(
                output=args.output,
                controller_project=args.controller_project,
                station_uid=args.station_consumer_uid,
                station_gid=args.station_consumer_gid,
                controller_uid=args.controller_owner_uid,
                controller_gid=args.controller_owner_gid,
                host_bindings_policy=args.host_bindings_policy,
                python_executable=args.python_executable,
                producer_source=args.producer_source,
            )
        elif args.command == "welcome-readiness-serve":
            welcome_readiness_serve()
            return 0
        elif args.command == "certificate-status":
            with args.evidence.open("rb") as stream:
                result = certificate_decide(decode(stream.read(65537)))
        elif args.command == "certificate-lifecycle-simulate":
            with args.observation.open("rb") as stream:
                observation = decode(stream.read(65537))
            previous = certificate_lifecycle_load(args.record)
            result = certificate_lifecycle_reconcile(previous, observation)
            certificate_lifecycle_store(args.record, result["record"], previous)
        elif args.command == "state-admission-listen":
            serve_listener()
            return 0
        elif args.command == "beacon-prepare":
            result = beacon_profile.prepare_live(args.state_volume_id)
        elif args.command == "beacon-stage":
            result = beacon_profile.stage(args.discover_source, args.producer_source, args.output, args.executable_directory)
        elif args.command == "state-admission-serve":
            serve_stdin()
            return 0  # stdout is the protocol socket; never append a CLI envelope.
        elif args.command == "state-stage":
            with args.bundle.open("rb") as stream:
                bundle = validate(decode(stream.read(65537)))
            previous = None
            if args.previous_bundle:
                with args.previous_bundle.open("rb") as stream:
                    previous = validate(decode(stream.read(65537)))
            ca = {}
            if args.ca_directory:
                for reg in bundle["bootstrap"]["registries"]:
                    if reg["ca"] is not None:
                        with (args.ca_directory / (reg["registry_id"] + ".pem")).open("rb") as stream:
                            ca[reg["registry_id"]] = stream.read(65537)
            result = stage_overlay(bundle, args.output, previous, ca)
        elif args.command == "state-prepare":
            result = prepare_live(args.initialize_volume)
        elif args.command == "state-authorize":
            result = authorize_live(args.initialization_id)
        elif args.command == "state-initialize":
            result = initialize_live()
        elif args.command == "state-validate":
            with args.bundle.open("rb") as stream:
                validate(decode(stream.read(65537)))
            result = {"status": "offline-records-valid", "control_authorized": False}
        elif args.command == "state-inspect":
            result = inspect_report()
        elif args.command == "state-probe":
            result = probe_live()
        elif args.command == "inspect":
            result = inspect(args.operation)
        elif args.command == "stage-artifact":
            result = stage(args.directory, args.expected_id, args.operation)
        elif args.command == "build-root-fixture":
            result = build_root_fixture(args.staging, args.operation, args.mib, args.filesystem_uuid)
        else:
            m = parse(args.manifest.read_bytes())
            p = plan(m, args.disk_mib * MIB)
            if args.command == "plan":
                result = p
            elif args.command == "preflight":
                result = assess(collect(), args.target, args.identity, p["disk_bytes"])
            else:
                result = install(m, args.artifacts, args.operation, p["disk_bytes"])
        print(json.dumps({"ok": True, "result": result}, indent=2))
        return 0
    except StateError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "error": str(exc)}), file=sys.stderr)
        return 2
    except (InstallError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
