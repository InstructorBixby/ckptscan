"""`ckptscan scan`: the checkpoint scanner."""
from __future__ import annotations

import sys

from ckptscan.scanner import scan_path


def run(args) -> int:
    findings = []
    for path in args.paths:
        try:
            findings.extend(scan_path(path))
        except OSError as exc:
            print(f"ckptscan: {exc}", file=sys.stderr)
            return 2
    args._findings = findings
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("scan", help="scan checkpoint files")
    p.add_argument("paths", nargs="+")
    p.set_defaults(fn=run)
