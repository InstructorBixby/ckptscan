"""SARIF 2.1.0, so this can post findings into a code-scanning view.

The mapping decisions worth knowing about:

- A SARIF `result` needs a location, and SARIF locations are
  file-plus-region. A finding here is often located inside a file -- a
  zip member, a pickle byte offset, a layer name -- and SARIF has no
  vocabulary for that. So the artifact is the file, and the internal
  location goes in `logicalLocations` and in the message, rather than
  being faked as a line number. A fabricated line number in a binary
  is worse than none.
- `level` has four values and this tool has five severities. critical
  and high both map to `error`; the real severity is carried in
  `properties.severity` and in `rank` so nothing is lost.
- Every rule in the registry is emitted in `rules`, whether or not it
  fired, because that is what makes the help text available in a
  viewer.
"""
from __future__ import annotations

import json
from pathlib import Path

import ckptscan
from ckptscan.findings import Severity
from ckptscan.registry import RULES

SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
          "master/Schemata/sarif-schema-2.1.0.json")
VERSION = "2.1.0"

LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
RANKS = {
    Severity.CRITICAL: 100.0,
    Severity.HIGH: 80.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 20.0,
    Severity.INFO: 1.0,
}


def _uri(path: str) -> str:
    p = Path(path)
    try:
        return p.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return p.as_posix()


def _rule_object(rule) -> dict:
    return {
        "id": rule.id,
        "name": rule.id.replace("-", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": f"{rule.what} {rule.why}"},
        "help": {"text": f"{rule.why}\n\nRemediation: {rule.fix}",
                 "markdown": (f"**{rule.title}**\n\n{rule.what}\n\n"
                              f"{rule.why}\n\n**Fix.** {rule.fix}")},
        "defaultConfiguration": {
            "level": LEVELS.get(rule.default, "warning")},
        "properties": {"severity": rule.default,
                       "tags": ["security", "supply-chain",
                                "machine-learning"]},
    }


def _result(finding) -> dict:
    out = {
        "ruleId": finding.rule,
        "level": LEVELS.get(finding.severity, "warning"),
        "rank": RANKS.get(finding.severity, 50.0),
        "message": {"text": finding.message},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": _uri(finding.path)},
            },
        }],
        "properties": {"severity": finding.severity},
    }
    if finding.location:
        out["locations"][0]["logicalLocations"] = [
            {"name": finding.location, "kind": "member"}]
        out["message"]["text"] = (f"{finding.location}: "
                                  f"{finding.message}")
    if finding.taxonomy:
        out["properties"]["taxonomy"] = list(finding.taxonomy)
    if finding.detail:
        out["properties"]["detail"] = {
            k: str(v) for k, v in finding.detail.items()}
    return out


def document(findings: list, **_kw) -> dict:
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "ckptscan",
                "version": ckptscan.__version__,
                "informationUri":
                    "https://git.c01n31.net/c01n31pan1c/ckptscan",
                "rules": [_rule_object(r) for r in
                          sorted(RULES.values(),
                                 key=lambda r: r.number)],
            }},
            "results": [_result(f) for f in findings],
        }],
    }


def render(findings: list, **kw) -> str:
    return json.dumps(document(findings, **kw), indent=1) + "\n"
