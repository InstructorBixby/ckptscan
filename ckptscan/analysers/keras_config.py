"""Find executable layers in a Keras model config.

The config is JSON, so this is a tree walk rather than an opcode walk.
What it is looking for:

- `{"class_name": "Lambda", ...}` anywhere in the layer tree, at any
  nesting depth, because a Lambda can live inside a Sequential inside a
  Functional inside a custom wrapper.
- a `function` or `output_shape` spec whose value is a
  `{"class_name": "__lambda__"}` or a two-element [code, defaults]
  pair, which is the marshalled form.
- `custom_objects` or `registered_name` entries, which name something
  the loader has to resolve out of the importable world.

Shared by the `.keras` and `.h5` analysers: the container differs, the
config does not.
"""
from __future__ import annotations

from ckptscan.findings import Finding, Severity

LAMBDA_CLASSES = {"Lambda", "TFOpLambda", "SlicingOpLambda"}
#: Keys whose value, if present, names code rather than configuration.
CODE_KEYS = {"function", "output_shape_module", "module",
             "registered_name", "function_type"}
MAX_NODES = 200_000


def _walk(node, path="$"):
    """Yield (path, dict) for every object in the tree."""
    stack = [(path, node)]
    seen = 0
    while stack:
        where, item = stack.pop()
        seen += 1
        if seen > MAX_NODES:
            return
        if isinstance(item, dict):
            yield where, item
            for key, value in item.items():
                stack.append((f"{where}.{key}", value))
        elif isinstance(item, list):
            for i, value in enumerate(item):
                stack.append((f"{where}[{i}]", value))


def analyse_config(config, *, path: str, location: str = "",
                   precise: bool = True) -> list:
    out = []
    caveat = "" if precise else (
        " (found by scanning the raw file rather than by reading the "
        "model config; install ckptscan[keras] for a precise answer)")
    for where, node in _walk(config):
        cls = node.get("class_name")
        name = node.get("config", {}).get("name") \
            if isinstance(node.get("config"), dict) else None
        label = name or where

        if cls in LAMBDA_CLASSES:
            out.append(Finding(
                rule="CKPT-006", severity=Severity.CRITICAL, path=path,
                location=f"{location}{label}" if location else label,
                message=(f"{cls} layer: the config carries a "
                         f"marshalled code object that is "
                         f"reconstructed and becomes callable when the "
                         f"model is loaded{caveat}"),
                detail={"class_name": cls, "layer": label,
                        "json_path": where},
                taxonomy=("OUT-003",)))
            continue

        registered = node.get("registered_name")
        if registered and registered not in (None, "None"):
            out.append(Finding(
                rule="CKPT-018", severity=Severity.HIGH, path=path,
                location=f"{location}{label}" if location else label,
                message=(f"registered_name {registered!r}: the loader "
                         f"has to resolve this out of the importable "
                         f"world, which means it runs whatever "
                         f"provides it{caveat}"),
                detail={"registered_name": registered,
                        "json_path": where}))

        module = node.get("module")
        if module and isinstance(module, str) and \
                not module.startswith(("keras", "tensorflow", "tf.",
                                       "builtins")):
            out.append(Finding(
                rule="CKPT-018", severity=Severity.MEDIUM, path=path,
                location=f"{location}{label}" if location else label,
                message=(f"layer declares module {module!r}, which is "
                         f"not part of the framework; loading imports "
                         f"it{caveat}"),
                detail={"module": module, "json_path": where}))
    return out
