"""Output for a person at a terminal."""
from __future__ import annotations

import os
import sys

from ckptscan.findings import Severity
from ckptscan.registry import RULES

COLOURS = {
    Severity.CRITICAL: "\x1b[1;31m",
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[90m",
}
RESET = "\x1b[0m"


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("CKPTSCAN_COLOR") == "always":
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def render(findings: list, *, colour: bool = False,
           explain: bool = False, dropped=()) -> str:
    lines = []
    for f in findings:
        prefix = COLOURS.get(f.severity, "") if colour else ""
        suffix = RESET if colour and prefix else ""
        where = f" [{f.location}]" if f.location else ""
        lines.append(f"{prefix}{f.severity.upper():8}{suffix} "
                     f"{f.rule} {f.path}{where}: {f.message}")
        if f.taxonomy:
            lines.append(f"         maps to "
                         f"{', '.join(f.taxonomy)} in llm-redteam-notes")
        if explain:
            rule = RULES.get(f.rule)
            if rule:
                lines.append(f"         fix: {rule.fix}")
    for finding, suppression in dropped:
        lines.append(f"{'SUPPRESSED':8} {finding.rule} {finding.path}: "
                     f"{suppression.justification}")
    return "\n".join(lines) + ("\n" if lines else "")


def summary(findings: list, *, failing: list, fail_on: str,
            scanned: int, dropped=()) -> str:
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = [f"{counts[s]} {s}" for s in Severity.ORDER
             if s in counts]
    body = ", ".join(parts) or "nothing"
    out = (f"{scanned} file(s) scanned: {body}. "
           f"{len(failing)} at or above {fail_on}.")
    if dropped:
        out += f" {len(dropped)} suppressed."
    if not findings:
        out += (" No load-time code execution reachable in what could "
                "be parsed -- which is not the same as safe; see the "
                "README.")
    return out
