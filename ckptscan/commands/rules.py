"""`ckptscan rules`: print the rule table.

Exists so that `docs/rules.md` can be generated from the registry
rather than written twice and drifting. CI regenerates it and fails if
the file in the repository differs.
"""
from __future__ import annotations

import json
import sys

from ckptscan.registry import RULES


def as_markdown() -> str:
    rules = sorted(RULES.values(), key=lambda r: r.number)
    out = ["# Rules", "",
           "Generated from `ckptscan/registry.py` by",
           "`ckptscan rules --format markdown`. Do not edit by hand.",
           "",
           "| id | severity | title |", "|---|---|---|"]
    for r in rules:
        out.append(f"| [`{r.id}`](#{r.id.lower()}) | {r.default} | "
                   f"{r.title} |")
    out.append("")
    for r in rules:
        out += [f"## {r.id}", "",
                f"**{r.title}** -- default severity `{r.default}`.", "",
                f"**What.** {r.what}", "",
                f"**Why it matters.** {r.why}", "",
                f"**Fix.** {r.fix}", ""]
    return "\n".join(out)


def run(args) -> int:
    if args.rules_format == "markdown":
        sys.stdout.write(as_markdown())
    elif args.rules_format == "json":
        print(json.dumps(
            [{"id": r.id, "title": r.title, "severity": r.default,
              "what": r.what, "why": r.why, "fix": r.fix}
             for r in sorted(RULES.values(), key=lambda r: r.number)],
            indent=1))
    else:
        for r in sorted(RULES.values(), key=lambda r: r.number):
            print(f"{r.id}  {r.default:8} {r.title}")
    args._report_only = True
    return 0


def add_parser(sub) -> None:
    p = sub.add_parser("rules", help="print the rule table")
    p.add_argument("--format", dest="rules_format", default="text",
                   choices=("text", "markdown", "json"))
    p.set_defaults(fn=run)
