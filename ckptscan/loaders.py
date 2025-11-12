"""Find the call sites, not just the files.

After the `weights_only` default flipped, the interesting question
stopped being "is this file executable" -- most files are, and most
loaders now refuse them -- and became "does this code turn the
protection off". That is a question about source, so this is an AST
walk.

AST, not grep, for one reason that matters: `weights_only` can arrive
as a keyword, through a dict splat, or not at all, and the difference
between `torch.load(p)` and `torch.load(p, weights_only=False)` is the
difference between relying on a default and overriding it. A regex
cannot tell those apart and the severity does.

Rules:
  CKPT-013  torch.load with the protection explicitly off
  CKPT-015  numpy.load(allow_pickle=True)
  CKPT-016  keras load_model(safe_mode=False)
  CKPT-011  a bare pickle/joblib/dill load
"""
from __future__ import annotations

import ast
from pathlib import Path

from ckptscan.findings import Finding, Severity


def _name_of(node: ast.AST) -> str:
    """Dotted name for a Name or Attribute chain, else ""."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _kw(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
        if kw.arg is None:
            return "splat"
    return None


def _is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _loc(path: str, node: ast.AST) -> str:
    return f"{path}:{getattr(node, 'lineno', 0)}"


def analyse_source(source: str, *, path: str) -> list:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Finding(
            rule="CKPT-004", severity=Severity.INFO, path=path,
            message=f"not parseable as Python: {exc}")]

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name_of(node.func)
        tail = name.rsplit(".", 1)[-1]
        where = _loc(path, node)

        if name.endswith("torch.load") or name == "load" and False:
            pass

        if tail == "load" and (name.startswith("torch")
                               or name.endswith("torch.load")):
            wo = _kw(node, "weights_only")
            if _is_false(wo):
                out.append(Finding(
                    rule="CKPT-013", severity=Severity.HIGH, path=path,
                    location=where,
                    message=("torch.load(weights_only=False) turns off "
                             "the restricted unpickler. Whatever this "
                             "loads executes."),
                    detail={"call": name, "weights_only": "False"}))
            elif wo == "splat":
                out.append(Finding(
                    rule="CKPT-013", severity=Severity.MEDIUM,
                    path=path, location=where,
                    message=("torch.load with keyword arguments from a "
                             "dict; whether weights_only is set cannot "
                             "be determined here"),
                    detail={"call": name, "weights_only": "**kwargs"}))
            elif wo is None:
                out.append(Finding(
                    rule="CKPT-013", severity=Severity.LOW, path=path,
                    location=where,
                    message=("torch.load relying on the default. Safe "
                             "on 2.6 and later, executes anything on "
                             "earlier versions -- check the pin."),
                    detail={"call": name, "weights_only": "default"}))

        elif tail == "load" and name.startswith(("np.", "numpy.")):
            if _is_true(_kw(node, "allow_pickle")):
                out.append(Finding(
                    rule="CKPT-015", severity=Severity.HIGH, path=path,
                    location=where,
                    message=("numpy.load(allow_pickle=True) executes "
                             "the pickle inside an object array. An "
                             "array of numbers never needs this."),
                    detail={"call": name}))

        elif tail in ("load_model", "model_from_json",
                      "model_from_config"):
            if _is_false(_kw(node, "safe_mode")):
                out.append(Finding(
                    rule="CKPT-016", severity=Severity.HIGH, path=path,
                    location=where,
                    message=(f"{tail}(safe_mode=False) deserialises "
                             f"Lambda layers, which means running the "
                             f"code object stored in the model "
                             f"config."),
                    detail={"call": name}))

        elif name in ("pickle.load", "pickle.loads", "dill.load",
                      "dill.loads", "cPickle.load", "joblib.load",
                      "pandas.read_pickle", "pd.read_pickle"):
            out.append(Finding(
                rule="CKPT-011", severity=Severity.MEDIUM, path=path,
                location=where,
                message=(f"{name} executes whatever it is given. There "
                         f"is no restricted mode for this call; the "
                         f"input has to be trusted."),
                detail={"call": name}))
    return out


def analyse_path(path: str | Path) -> list:
    p = Path(path)
    if p.is_file():
        return analyse_source(
            p.read_text(encoding="utf-8", errors="replace"), path=str(p))
    out = []
    for child in sorted(p.rglob("*.py")):
        if any(part in {".venv", "venv", "site-packages", ".git",
                        "__pycache__", "build", "dist"}
               for part in child.parts):
            continue
        out.extend(analyse_source(
            child.read_text(encoding="utf-8", errors="replace"),
            path=str(child)))
    return out
