"""What the scanner emits.

One flat record type. The temptation is a tree -- file, member, stream,
finding -- and it is the wrong shape for the two things that happen to
a finding: it gets printed in a list, and it gets filtered by rule id
and severity. The location is a string field because a location here is
genuinely heterogeneous: a byte offset in a file, a member inside a zip,
a layer name inside a saved model.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = (CRITICAL, HIGH, MEDIUM, LOW, INFO)

    @classmethod
    def rank(cls, s: str) -> int:
        return cls.ORDER.index(s) if s in cls.ORDER else len(cls.ORDER)

    @classmethod
    def at_least(cls, s: str, floor: str) -> bool:
        return cls.rank(s) <= cls.rank(floor)


@dataclass
class Finding:
    rule: str                 # CKPT-001
    severity: str
    path: str                 # the file on disk
    message: str
    location: str = ""        # member, offset, layer -- format specific
    detail: dict = field(default_factory=dict)
    taxonomy: tuple = ()      # llm-redteam-notes ids, where one applies

    def to_json(self) -> dict:
        out = asdict(self)
        out["taxonomy"] = list(self.taxonomy)
        return out

    def __str__(self) -> str:
        where = f" [{self.location}]" if self.location else ""
        return (f"{self.severity.upper():8} {self.rule} {self.path}"
                f"{where}: {self.message}")


def worst(findings: list) -> str:
    """Highest severity present, or "" for none."""
    if not findings:
        return ""
    return min((f.severity for f in findings), key=Severity.rank)
