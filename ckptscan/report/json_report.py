"""Machine-readable output.

Versioned, because something downstream will parse it and a schema
that changes shape without saying so is worse than no schema.
"""
from __future__ import annotations

import json

import ckptscan
from ckptscan.findings import Severity

SCHEMA_VERSION = 1


def document(findings: list, *, scanned: int, fail_on: str,
             dropped=()) -> dict:
    counts = {s: 0 for s in Severity.ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "ckptscan",
        "version": ckptscan.__version__,
        "static_analysis_only": True,
        "files_scanned": scanned,
        "fail_on": fail_on,
        "counts": counts,
        "findings": [f.to_json() for f in findings],
        "suppressed": [
            {"rule": f.rule, "path": f.path, "location": f.location,
             "justification": s.justification}
            for f, s in dropped],
    }


def render(findings: list, **kw) -> str:
    return json.dumps(document(findings, **kw), indent=1,
                      sort_keys=True) + "\n"
