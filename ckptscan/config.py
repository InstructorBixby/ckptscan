"""`ckptscan.toml`: severity overrides and suppressions.

Two things a real deployment needs and one thing it must not get.

Needs: a way to raise or lower a rule for its own risk appetite, and a
way to allowlist a callable its own project pickles.

Must not get: a way to turn a rule off without saying why. Every
scanner that has ever shipped has a config file full of disabled rules
and nobody can remember which were disabled because they were wrong and
which because somebody wanted a green build on a Friday. So
`justification` is mandatory, it has a minimum length, and the audit
output lists every suppression with its reason. The file is in version
control; the justification is the only thing that makes the diff
reviewable six months later.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from ckptscan.findings import Severity
from ckptscan.registry import RULES

MIN_JUSTIFICATION = 25


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Suppression:
    rule: str
    justification: str
    paths: tuple = ()

    def applies_to(self, finding) -> bool:
        if finding.rule != self.rule:
            return False
        if not self.paths:
            return True
        return any(_match(p, finding.path) for p in self.paths)


def _match(pattern: str, path: str) -> bool:
    from fnmatch import fnmatch
    return fnmatch(path, pattern) or fnmatch(path, f"*/{pattern}")


@dataclass
class Config:
    fail_on: str = Severity.MEDIUM
    severities: dict = field(default_factory=dict)
    suppressions: tuple = ()
    allow: dict = field(default_factory=dict)

    def severity_for(self, finding) -> str:
        return self.severities.get(finding.rule, finding.severity)

    def apply(self, findings: list) -> tuple:
        """(kept findings, [(finding, suppression)])."""
        kept, dropped = [], []
        for f in findings:
            hit = next((s for s in self.suppressions
                        if s.applies_to(f)), None)
            if hit is not None:
                dropped.append((f, hit))
                continue
            f.severity = self.severity_for(f)
            kept.append(f)
        return kept, dropped


def _suppressions(raw) -> tuple:
    out = []
    for i, entry in enumerate(raw or []):
        if not isinstance(entry, dict):
            raise ConfigError(f"[[suppress]] #{i + 1} is not a table")
        rule = entry.get("rule")
        if not rule:
            raise ConfigError(f"[[suppress]] #{i + 1} has no rule")
        if rule not in RULES:
            raise ConfigError(
                f"[[suppress]] {rule}: no such rule. Known ids are "
                f"{', '.join(sorted(RULES))}")
        why = (entry.get("justification") or "").strip()
        if not why:
            raise ConfigError(
                f"[[suppress]] {rule}: justification is required. A "
                f"disabled rule with no reason is indistinguishable "
                f"from a disabled rule that was wrong to disable.")
        if len(why) < MIN_JUSTIFICATION:
            raise ConfigError(
                f"[[suppress]] {rule}: justification is "
                f"{len(why)} characters; at least "
                f"{MIN_JUSTIFICATION} are expected. Write the sentence "
                f"you would want to read in six months.")
        paths = entry.get("paths") or ()
        if isinstance(paths, str):
            paths = (paths,)
        out.append(Suppression(rule=rule, justification=why,
                               paths=tuple(paths)))
    return tuple(out)


def _severities(raw) -> dict:
    out = {}
    for rule, value in (raw or {}).items():
        if rule not in RULES:
            raise ConfigError(f"[severity] {rule}: no such rule")
        if value not in Severity.ORDER:
            raise ConfigError(
                f"[severity] {rule} = {value!r}: not a severity "
                f"({', '.join(Severity.ORDER)})")
        out[rule] = value
    return out


def _allow(raw) -> dict:
    out = {}
    for dotted, why in (raw or {}).items():
        why = (why or "").strip() if isinstance(why, str) else ""
        if len(why) < MIN_JUSTIFICATION:
            raise ConfigError(
                f"[allow] {dotted}: needs a reason of at least "
                f"{MIN_JUSTIFICATION} characters. An allowlist entry "
                f"is a promise that calling this with "
                f"attacker-chosen arguments is harmless.")
        if "." not in dotted:
            raise ConfigError(
                f"[allow] {dotted}: expected module.attribute")
        module, _, attr = dotted.rpartition(".")
        out[(module, attr)] = why
    return out


def loads(text: str) -> Config:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"not valid TOML: {exc}") from exc
    unknown = set(doc) - {"fail_on", "severity", "suppress", "allow"}
    if unknown:
        raise ConfigError(f"unknown section(s) {sorted(unknown)}")
    fail_on = doc.get("fail_on", Severity.MEDIUM)
    if fail_on not in Severity.ORDER:
        raise ConfigError(f"fail_on = {fail_on!r} is not a severity")
    return Config(
        fail_on=fail_on,
        severities=_severities(doc.get("severity")),
        suppressions=_suppressions(doc.get("suppress")),
        allow=_allow(doc.get("allow")))


def load(path: str | Path) -> Config:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"no config at {p}")
    return loads(p.read_text(encoding="utf-8"))


def discover(start: str | Path = ".") -> Config | None:
    """`ckptscan.toml` here or in any parent directory."""
    here = Path(start).resolve()
    if here.is_file():
        here = here.parent
    for directory in (here, *here.parents):
        candidate = directory / "ckptscan.toml"
        if candidate.exists():
            return load(candidate)
    return None
