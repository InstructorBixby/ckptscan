"""Build the deliberately-unsafe sample corpus.

Promoted out of the test fixtures because it is useful outside the test
suite: it is how somebody evaluating this tool checks it detects what it
claims to, and how somebody writing a different scanner gets a test
set. `ckptscan-mkcorpus` is the console script.

Two rules this module exists to enforce.

**Nothing malicious is ever committed.** The repository contains the
generator, not the payloads. A repository with working malicious
checkpoints in it is one people are right to be wary of cloning, and it
gets flagged by somebody's endpoint protection within a week.

**Every payload is inert.** The dangerous callable in every sample
resolves to a marker write into a directory the caller names, and
nothing else. No network, no persistence, no execution of anything
downloaded, no deletion, no environment capture. A detector cannot tell
the difference -- it sees `os.system` and a `REDUCE` either way -- so
there is nothing to gain from a real payload and a great deal to lose.

The marker exists so a human can prove to themselves that the payloads
*would* run if loaded: load one in a container, look for the file. That
is the only legitimate reason to ever load one of these, and the corpus
README says so.
"""
from __future__ import annotations

import collections
import io
import json
import os
import pickle
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

MARKER = "ckptscan-corpus-ran"
TORCH_MAGIC = 0x1950A86A20F9469CFC6C


@dataclass
class Sample:
    name: str
    description: str
    expect: tuple = ()          # rule ids that must be reported
    expect_clean: bool = False  # must report nothing at all
    severity: str = ""
    builder: object = field(default=None, repr=False)


# --- inert payloads -------------------------------------------------

class MarkerSystem:
    """REDUCE -> os.system, writing a marker. The textbook shape."""

    def __reduce__(self):
        return (os.system, (f"touch /tmp/{MARKER}",))


class MarkerEval:
    """REDUCE -> builtins.eval."""

    def __reduce__(self):
        return (eval,
                ("open('/tmp/" + MARKER + "', 'a').close()",))


class MarkerSubprocess:
    def __reduce__(self):
        return (os.popen, (f"echo >> /tmp/{MARKER}",))


class UnknownCallable:
    """Reaches something no allowlist can know about."""

    def __reduce__(self):
        return (collections.namedtuple, ("Point", "x y"))


class StagedImport:
    """Imports a dangerous module without calling it in this stream."""

    def __reduce__(self):
        return (collections.OrderedDict, ([("shell", os.system)],))


def state_dict():
    return collections.OrderedDict([
        ("features.0.weight", [[0.1, 0.2], [0.3, 0.4]]),
        ("features.0.bias", [0.0, 0.0]),
        ("classifier.weight", [[0.5]]),
    ])


# --- container writers ----------------------------------------------

def _pickle(obj, protocol=4):
    return pickle.dumps(obj, protocol=protocol)


def _legacy(obj):
    buf = io.BytesIO()
    pickle.dump(TORCH_MAGIC, buf, protocol=2)
    pickle.dump({"protocol_version": 1001}, buf, protocol=2)
    pickle.dump(obj, buf, protocol=2)
    return buf.getvalue()


def _zip_ckpt(obj, extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", _pickle(obj))
        z.writestr("archive/version", "3\n")
        z.writestr("archive/data/0", b"\x00" * 64)
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    return buf.getvalue()


def _npy(descr, shape, body):
    header = ("{'descr': %r, 'fortran_order': False, 'shape': %r, }"
              % (descr, shape)).encode("latin-1")
    header += b" " * (-(10 + len(header) + 1) % 64) + b"\n"
    return (b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header))
            + header + body)


def _safetensors(header, payload=b""):
    blob = json.dumps(header, separators=(",", ":")).encode()
    return struct.pack("<Q", len(blob)) + blob + payload


def _keras(config):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("metadata.json",
                   json.dumps({"keras_version": "3.5.0"}))
        z.writestr("config.json", json.dumps(config, indent=1))
    return buf.getvalue()


def _lambda_config():
    return {"module": "keras", "class_name": "Sequential",
            "registered_name": None,
            "config": {"name": "sequential", "layers": [
                {"module": "keras.layers", "class_name": "Dense",
                 "registered_name": None,
                 "config": {"name": "d1", "units": 4}},
                {"module": "keras.layers", "class_name": "Lambda",
                 "registered_name": None,
                 "config": {"name": "lam", "function": {
                     "class_name": "__lambda__",
                     "config": {"code": "aW5lcnQtcGxhY2Vob2xkZXI=",
                                "defaults": None, "closure": None}}}},
            ]}}


SAMPLES = [
    Sample("clean/state_dict.pkl",
           "An ordinary OrderedDict of tensors. Must stay clean: this "
           "is the false positive that made the naive version "
           "useless.",
           expect_clean=True,
           builder=lambda: _pickle(state_dict())),
    Sample("clean/checkpoint.pt",
           "A zip-format checkpoint with nothing unusual in it.",
           expect_clean=True,
           builder=lambda: _zip_ckpt(
               {"state_dict": state_dict(), "epoch": 3})),
    Sample("clean/legacy.pth",
           "A legacy-format checkpoint with nothing unusual in it.",
           expect_clean=True,
           builder=lambda: _legacy(state_dict())),
    Sample("clean/weights.npy",
           "A float array.",
           expect_clean=True,
           builder=lambda: _npy("<f4", (4,),
                                struct.pack("<4f", 1, 2, 3, 4))),
    Sample("clean/model.safetensors",
           "A well-formed safetensors file. The recommendation.",
           expect_clean=True,
           builder=lambda: _safetensors(
               {"w": {"dtype": "F32", "shape": [2],
                      "data_offsets": [0, 8]}}, b"\x00" * 8)),

    Sample("unsafe/system_p2.pkl",
           "os.system through REDUCE, protocol 2 (GLOBAL).",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: _pickle(MarkerSystem(), 2)),
    Sample("unsafe/system_p4.pkl",
           "os.system through REDUCE, protocol 4 (STACK_GLOBAL). The "
           "shape a GLOBAL-only scanner misses entirely.",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: _pickle(MarkerSystem(), 4)),
    Sample("unsafe/system_p5.pkl",
           "Protocol 5, with framing.",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: _pickle(MarkerSystem(), 5)),
    Sample("unsafe/eval.pkl",
           "builtins.eval through REDUCE.",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: _pickle(MarkerEval())),
    Sample("unsafe/popen.pkl",
           "os.popen, to check the dangerous list is not just "
           "os.system.",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: _pickle(MarkerSubprocess())),
    Sample("unsafe/staged_import.pkl",
           "A dangerous module imported and stored, with no call in "
           "this stream.",
           expect=("CKPT-003",), severity="high",
           builder=lambda: _pickle(StagedImport())),
    Sample("unsafe/unknown_callable.pkl",
           "A call to something no allowlist can know. The judgement "
           "call, deliberately MEDIUM.",
           expect=("CKPT-002",), severity="medium",
           builder=lambda: _pickle(UnknownCallable())),
    Sample("unsafe/in_zip.pt",
           "The payload inside archive/data.pkl of a zip checkpoint.",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: _zip_ckpt({"sd": state_dict(),
                                      "hook": MarkerSystem()})),
    Sample("unsafe/nested_zip.pt",
           "The payload one archive deeper, which is what you build "
           "when you know a scanner looks one level down.",
           expect=("CKPT-001", "CKPT-010"), severity="critical",
           builder=lambda: _zip_ckpt(
               state_dict(),
               extra={"extra/inner.zip":
                      _zip_ckpt({"hook": MarkerSystem()})})),
    Sample("unsafe/legacy_stream2.pth",
           "The payload in the second pickle stream of a legacy file. "
           "A single-stream parse reads the magic number and reports "
           "clean.",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: _legacy({"sd": state_dict(),
                                    "hook": MarkerSystem()})),
    Sample("unsafe/traversal.pt",
           "A zip member whose name escapes the archive root.",
           expect=("CKPT-012",), severity="high",
           builder=lambda: _zip_ckpt(
               state_dict(), extra={"../escaped.txt": b"outside"})),
    Sample("unsafe/object_array.npy",
           "An object-dtype array, whose body is a pickle.",
           expect=("CKPT-005", "CKPT-001"), severity="high",
           builder=lambda: _npy("|O", (1,), _pickle(MarkerSystem()))),
    Sample("unsafe/model.joblib",
           "A zlib-compressed pickle, which a format sniff alone "
           "cannot see into.",
           expect=("CKPT-001",), severity="critical",
           builder=lambda: zlib.compress(_pickle(MarkerSystem()))),
    Sample("unsafe/lambda.keras",
           "A Keras Lambda layer: a marshalled code object in a JSON "
           "config, which no amount of pickle hardening touches.",
           expect=("CKPT-006",), severity="critical",
           builder=lambda: _keras(_lambda_config())),
    Sample("unsafe/mislabelled.safetensors",
           "A pickle wearing the name of a format that cannot "
           "execute.",
           expect=("CKPT-008", "CKPT-001"), severity="high",
           builder=lambda: _pickle(MarkerSystem())),
]


def build(out: str | Path) -> list[Path]:
    root = Path(out)
    made = []
    for sample in SAMPLES:
        target = root / sample.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(sample.builder())
        made.append(target)
    (root / "MANIFEST.json").write_text(
        json.dumps(
            [{"name": s.name, "description": s.description,
              "expect": list(s.expect), "expect_clean": s.expect_clean,
              "severity": s.severity} for s in SAMPLES],
            indent=1) + "\n",
        encoding="utf-8", newline="\n")
    (root / "README.md").write_text(README, encoding="utf-8",
                                    newline="\n")
    return made


README = """\
# Generated sample corpus

Built by `ckptscan-mkcorpus`. Not committed anywhere.

Every file under `unsafe/` is a deliberately-unsafe checkpoint. The
payload in each is **inert**: it writes a marker file called
`ckptscan-corpus-ran` into a temporary directory and does nothing
else. No network, no persistence, no deletion, nothing downloaded.

A detector cannot tell the difference between this and a real payload
-- it sees `os.system` and a call opcode either way -- so there is
nothing to gain from a real one.

## do not load these

Not because they will hurt you; because you do not need to. The whole
point of the tool is that you can find out what a checkpoint would do
without running it.

The one defensible reason to load one is to satisfy yourself that they
really would execute. If you do that, do it in a container with no
network, and look for the marker file afterwards.

## MANIFEST.json

Each sample's expected findings. The test suite asserts that every
`unsafe/` sample still produces its rules and that every `clean/`
sample still produces nothing, which catches a detector regression and
a false-positive regression in the same run.
"""
