"""ckptscan command line.

Exit codes, because the only interesting caller is CI:

  0  nothing found at or above the failure threshold
  1  findings at or above the threshold
  2  usage, configuration or input error

`ckptscan <path>` with no subcommand means `ckptscan scan <path>`,
because that is what it meant before subcommands existed and breaking
it would be rude.
"""
from __future__ import annotations

import argparse
import sys

from ckptscan import config as config_mod
from ckptscan.commands import loaders as loaders_cmd
from ckptscan.commands import rules as rules_cmd
from ckptscan.commands import scan as scan_cmd
from ckptscan.commands import verify as verify_cmd
from ckptscan.findings import Severity
from ckptscan.report import human, json_report, sarif

MODULES = (scan_cmd, loaders_cmd, verify_cmd, rules_cmd)
SUBCOMMANDS = {"scan", "loaders", "verify", "rules"}

RENDERERS = {"human": human.render, "json": json_report.render,
             "sarif": sarif.render}

VALUE_FLAGS = {"--fail-on", "--format", "--output", "--config"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ckptscan",
        description="Find code that executes when a model checkpoint "
                    "loads. Static: this never unpickles anything.")
    ap.add_argument("--fail-on", default=None,
                    choices=Severity.ORDER,
                    help="lowest severity that exits 1 "
                         "(default: medium, or fail_on in the config)")
    ap.add_argument("--format", default="human",
                    choices=sorted(RENDERERS))
    ap.add_argument("--output", metavar="FILE", default=None,
                    help="write the report here instead of stdout")
    ap.add_argument("--config", default=None,
                    help="ckptscan.toml (default: nearest one found)")
    ap.add_argument("--no-config", action="store_true")
    ap.add_argument("--explain", action="store_true",
                    help="print the remediation for each finding")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for mod in MODULES:
        mod.add_parser(sub)
    return ap


def _normalise(argv: list) -> list:
    """Insert the implied `scan` subcommand."""
    skip_next = False
    for i, token in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            skip_next = token in VALUE_FLAGS
            continue
        if token in SUBCOMMANDS:
            return argv
        return argv[:i] + ["scan"] + argv[i:]
    return argv


def _config(args):
    if args.no_config:
        return config_mod.Config()
    if args.config:
        return config_mod.load(args.config)
    return config_mod.discover(".") or config_mod.Config()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(_normalise(argv))

    try:
        cfg = _config(args)
    except config_mod.ConfigError as exc:
        print(f"ckptscan: {exc}", file=sys.stderr)
        return 2
    args.config_obj = cfg

    rc = args.fn(args)
    if rc:
        return rc
    findings = getattr(args, "_findings", [])
    scanned = getattr(args, "_scanned", 0)
    if getattr(args, "_report_only", False):
        return 0

    findings, dropped = cfg.apply(findings)
    findings.sort(key=lambda f: (Severity.rank(f.severity), f.path,
                                 f.rule))
    fail_on = args.fail_on or cfg.fail_on
    failing = [f for f in findings
               if Severity.at_least(f.severity, fail_on)]

    if args.format == "human":
        text = human.render(
            findings,
            colour=(not args.no_color and human.use_colour()),
            explain=args.explain, dropped=dropped)
    else:
        text = RENDERERS[args.format](
            findings, scanned=scanned, fail_on=fail_on,
            dropped=dropped)

    if args.output:
        with open(args.output, "w", encoding="utf-8",
                  newline="\n") as fh:
            fh.write(text)
    elif not args.quiet:
        sys.stdout.write(text)

    if args.format == "human" and not args.quiet:
        print(human.summary(findings, failing=failing,
                            fail_on=fail_on, scanned=scanned,
                            dropped=dropped), file=sys.stderr)
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
