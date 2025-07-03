"""ckptscan command line.

Exit codes, because the only interesting caller is CI:

  0  nothing found at or above the failure threshold
  1  findings at or above the threshold
  2  usage or input error
"""
from __future__ import annotations

import argparse
import sys

from ckptscan.findings import Severity
from ckptscan.scanner import scan_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="ckptscan",
        description="Find code that executes when a checkpoint loads. "
                    "Static: this never unpickles anything.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--fail-on", default=Severity.MEDIUM,
                    choices=Severity.ORDER,
                    help="lowest severity that exits 1")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    findings = []
    for path in args.paths:
        try:
            findings.extend(scan_path(path))
        except OSError as exc:
            print(f"ckptscan: {exc}", file=sys.stderr)
            return 2

    if not args.quiet:
        for f in findings:
            print(f)
    failing = [f for f in findings
               if Severity.at_least(f.severity, args.fail_on)]
    print(f"{len(findings)} finding(s), {len(failing)} at or above "
          f"{args.fail_on}", file=sys.stderr)
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
