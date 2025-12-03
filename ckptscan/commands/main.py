"""ckptscan command line.

Exit codes, because the only interesting caller is CI:

  0  nothing found at or above the failure threshold
  1  findings at or above the threshold
  2  usage or input error

`ckptscan <path>` with no subcommand means `ckptscan scan <path>`,
because that is what it meant before subcommands existed and breaking
it would be rude.
"""
from __future__ import annotations

import argparse
import sys

from ckptscan.commands import loaders as loaders_cmd
from ckptscan.commands import scan as scan_cmd
from ckptscan.findings import Severity

MODULES = (scan_cmd, loaders_cmd)
SUBCOMMANDS = {"scan", "loaders"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ckptscan",
        description="Find code that executes when a model checkpoint "
                    "loads. Static: this never unpickles anything.")
    ap.add_argument("--fail-on", default=Severity.MEDIUM,
                    choices=Severity.ORDER,
                    help="lowest severity that exits 1")
    ap.add_argument("-q", "--quiet", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for mod in MODULES:
        mod.add_parser(sub)
    return ap


def _normalise(argv: list) -> list:
    """Insert the implied `scan` subcommand."""
    for i, token in enumerate(argv):
        if token.startswith("-"):
            continue
        if token in SUBCOMMANDS:
            return argv
        return argv[:i] + ["scan"] + argv[i:]
    return argv


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(_normalise(argv))
    rc = args.fn(args)
    if rc:
        return rc
    findings = getattr(args, "_findings", [])
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
