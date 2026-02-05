"""`ckptscan scan`: the checkpoint scanner."""
from __future__ import annotations

import sys
from pathlib import Path

from ckptscan.scanner import CANDIDATES, scan_path


def _count(paths) -> int:
    total = 0
    for path in paths:
        p = Path(path)
        if p.is_file():
            total += 1
        else:
            total += sum(1 for c in p.rglob("*")
                         if c.is_file()
                         and c.suffix.lower() in CANDIDATES)
    return total


def run(args) -> int:
    findings = []
    for path in args.paths:
        try:
            findings.extend(scan_path(path))
        except OSError as exc:
            print(f"ckptscan: {exc}", file=sys.stderr)
            return 2
    args._findings = findings
    args._scanned = _count(args.paths)
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("scan", help="scan checkpoint files")
    p.add_argument("paths", nargs="+")
    p.set_defaults(fn=run)
