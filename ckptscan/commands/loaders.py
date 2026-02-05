"""`ckptscan loaders`: scan source for load calls that opt out.

The severity of a bare `torch.load(p)` depends entirely on which torch
the project can install, so this reads the pin and adjusts. An unknown
pin does not lower anything -- a wrong guess has to fail towards
reporting.
"""
from __future__ import annotations

import sys
from pathlib import Path

from ckptscan import loaders, pins
from ckptscan.findings import Severity


def _reweight(findings: list, floor, root: str) -> list:
    """Raise the default-reliance finding when the pin is old."""
    if not pins.predates_flip(floor):
        return findings
    shown = ".".join(str(n) for n in floor)
    for f in findings:
        if (f.rule == "CKPT-013"
                and f.detail.get("weights_only") == "default"):
            f.severity = Severity.HIGH
            f.message = (f"torch.load relying on the default, but "
                         f"{root} pins torch {shown}, which predates "
                         f"the restricted-unpickler default. This "
                         f"executes whatever it loads.")
            f.detail["torch_floor"] = shown
    return findings


def run(args) -> int:
    findings = []
    scanned = 0
    for path in args.paths:
        try:
            found = loaders.analyse_path(path)
        except OSError as exc:
            print(f"ckptscan: {exc}", file=sys.stderr)
            return 2
        p = Path(path)
        scanned += 1 if p.is_file() else sum(
            1 for c in p.rglob("*.py")
            if not any(part in loaders.SKIP_PARTS for part in c.parts))
        root = args.project or path
        floor = None if args.no_pin else pins.torch_floor(root)
        findings.extend(_reweight(found, floor, str(Path(root))))
    args._findings = findings
    args._scanned = scanned
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser(
        "loaders",
        help="scan Python source for loads that turn protection off")
    p.add_argument("paths", nargs="+")
    p.add_argument("--project", default=None,
                   help="where to look for the torch pin "
                        "(default: the scanned path)")
    p.add_argument("--no-pin", action="store_true",
                   help="do not read the torch pin")
    p.set_defaults(fn=run)
