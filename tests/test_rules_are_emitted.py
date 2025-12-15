"""Every rule in the registry must be reachable, and vice versa.

A rule with no emitter is documentation of something that cannot
happen. An emitted id with no registry entry is a finding nobody can
look up. Both have happened here.
"""
import re
from pathlib import Path

from ckptscan.registry import RULES

SRC = Path(__file__).resolve().parents[1] / "ckptscan"
ID_RE = re.compile(r'rule="(CKPT-\d+)"')


def emitted():
    found = set()
    for path in SRC.rglob("*.py"):
        if path.name == "registry.py":
            continue
        found |= set(ID_RE.findall(path.read_text(encoding="utf-8")))
    return found


def test_every_emitted_id_is_documented():
    assert not emitted() - set(RULES)


def test_every_documented_id_is_emitted():
    assert not set(RULES) - emitted()
