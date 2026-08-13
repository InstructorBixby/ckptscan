"""`ckptscan scan`: the checkpoint scanner.

Sharded models are the common shape now -- four to twenty files in a
directory, each independent -- so the walk is parallel. The work is
mostly I/O and small bursts of opcode parsing, and a thread pool is
enough; a process pool would pay for pickling the findings back, which
is a joke this project does not need to make twice.
"""
from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from ckptscan.scanner import Posture, candidates, scan_file


def default_jobs() -> int:
    return min(8, (os.cpu_count() or 2))


def run(args) -> int:
    try:
        targets = []
        for path in args.paths:
            targets.extend(candidates(path))
    except OSError as exc:
        print(f"ckptscan: {exc}", file=sys.stderr)
        return 2

    posture = Posture.from_config(args.config_obj,
                                  strict=args.strict)
    if args.strict and posture.extra:
        print("ckptscan: --strict, so [allow] in the config is "
              "ignored", file=sys.stderr)
    work = partial(scan_file, posture=posture)

    jobs = args.jobs if args.jobs is not None else default_jobs()
    findings = []
    try:
        if jobs <= 1 or len(targets) <= 1:
            for target in targets:
                findings.extend(work(target))
        else:
            with ThreadPoolExecutor(max_workers=jobs) as pool:
                for result in pool.map(work, targets):
                    findings.extend(result)
    except OSError as exc:
        print(f"ckptscan: {exc}", file=sys.stderr)
        return 2

    args._findings = findings
    args._scanned = len(targets)
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("scan", help="scan checkpoint files")
    p.add_argument("paths", nargs="+")
    p.add_argument("--jobs", type=int, default=None, metavar="N",
                   help=f"parallel file scans "
                        f"(default: {default_jobs()}, 1 to disable)")
    p.add_argument("--strict", action="store_true",
                   help="raise unrecognised calls to high, ignore "
                        "[allow] from the config, and report what the "
                        "shipped allowlist waved through. For a "
                        "one-off review, not for a gate.")
    p.set_defaults(fn=run)
