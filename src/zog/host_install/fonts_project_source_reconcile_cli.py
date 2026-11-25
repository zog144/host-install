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
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--expected-plan-sha256")
    args = parser.parse_args(argv)
    if args.restore_reviewed_source:
        if args.expected_plan_sha256 is None:
            parser.error("--restore-reviewed-source requires --expected-plan-sha256")
        answer = recovery.restore(
            root=Path("/"), reviewed_checkout=args.source_checkout,
            expected_plan_sha256=args.expected_plan_sha256)
    else:
        if args.expected_plan_sha256 is not None:
            parser.error("--expected-plan-sha256 is only valid for restore")
        answer = reconcile.plan(Path("/"), args.source_checkout)
    print(json.dumps(answer, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
