"""ckptscan: find code that executes when a model checkpoint is loaded.

The names re-exported here are the supported API. Anything reached by
importing a submodule directly may move in a minor release -- see
docs/stability.md.
"""
from __future__ import annotations

from ckptscan.config import Config, ConfigError
from ckptscan.findings import Finding, Severity
from ckptscan.loaders import analyse_path as scan_loaders
from ckptscan.reach import Reach, reach_of
from ckptscan.registry import RULES, Rule
from ckptscan.scanner import scan_file, scan_path

__version__ = "1.0.0"

__all__ = [
    "RULES",
    "Config",
    "ConfigError",
    "Finding",
    "Reach",
    "Rule",
    "Severity",
    "__version__",
    "reach_of",
    "scan_file",
    "scan_loaders",
    "scan_path",
]
