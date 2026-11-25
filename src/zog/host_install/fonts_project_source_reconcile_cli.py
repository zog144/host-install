"""Source-owned prepared Project reconciliation; no alternate root or user."""
import argparse
import json
from pathlib import Path

from . import fonts_project_source_reconciliation as reconcile
from . import fonts_project_source_restore as recovery


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--reconcile-plan", action="store_true")
    operation.add_argument("--restore-reviewed-source", action="store_true")
    operation.add_argument("--verify-recovery", action="store_true")
    parser.add_argument("--source-checkout", type=Path)
    parser.add_argument("--expected-plan-sha256")
    args = parser.parse_args(argv)
    if args.verify_recovery:
        if args.expected_plan_sha256 is None:
            parser.error("--verify-recovery requires --expected-plan-sha256")
        if args.source_checkout is not None:
            parser.error("--verify-recovery does not accept an external checkout")
        answer = recovery.verify_recovery(
            root=Path("/"), expected_plan_sha256=args.expected_plan_sha256)
    elif args.restore_reviewed_source:
        if args.expected_plan_sha256 is None or args.source_checkout is None:
            parser.error("--restore-reviewed-source requires --source-checkout "
                         "and --expected-plan-sha256")
        answer = recovery.restore(
            root=Path("/"), reviewed_checkout=args.source_checkout,
            expected_plan_sha256=args.expected_plan_sha256)
    else:
        if args.expected_plan_sha256 is not None or args.source_checkout is None:
            parser.error("--reconcile-plan requires --source-checkout "
                         "and forbids --expected-plan-sha256")
        answer = reconcile.plan(Path("/"), args.source_checkout)
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
