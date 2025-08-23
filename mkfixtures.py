"""Build the deliberately-unsafe checkpoints the tests scan.

Generated, never committed. Two reasons:

1. A repository with working malicious payloads in it is a repository
   people are right to be wary of cloning, and every scanner that
   ships one gets flagged by somebody's endpoint protection.
2. A generated fixture is readable. The payload is four lines of Python
   in this file rather than an opaque blob somebody has to trust.

Every payload here is **inert**: it writes a marker file into a
directory the caller names, and does nothing else. No network, no
persistence, no execution of anything downloaded. The point is to
exercise the detector, and a marker file does that exactly as well as
anything harmful would.

No numpy, torch, h5py or sklearn is imported. Every format is written
by hand from its specification, so the fixtures build anywhere the
tests run.
"""
import argparse
import collections
import io
import json
import os
import pathlib
import pickle
import struct
import zipfile
import zlib


MARKER = "ckptscan-fixture-ran"
TORCH_MAGIC = 0x1950A86A20F9469CFC6C


class SystemPayload:
    """REDUCE -> os.system. The textbook shape."""

    def __reduce__(self):
        return (os.system, (f"touch /tmp/{MARKER}",))


class EvalPayload:
    """REDUCE -> builtins.eval."""

    def __reduce__(self):
        return (eval, ("open('/tmp/" + MARKER + "', 'w').close()",))


class UnknownCallablePayload:
    """A REDUCE to something no allowlist can know about."""

    def __reduce__(self):
        return (collections.namedtuple, ("Point", "x y"))


def state_dict():
    """What an ordinary checkpoint looks like."""
    return collections.OrderedDict([
        ("features.0.weight", [[0.1, 0.2], [0.3, 0.4]]),
        ("features.0.bias", [0.0, 0.0]),
        ("classifier.weight", [[0.5]]),
    ])


def write(path, obj, protocol):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(obj, fh, protocol=protocol)
    return path


def write_legacy(path, obj):
    """The pre-zip torch format: magic number, then the object graph."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(TORCH_MAGIC, fh, protocol=2)
        pickle.dump({"protocol_version": 1001}, fh, protocol=2)
        pickle.dump(obj, fh, protocol=2)
    return path


def write_zip_checkpoint(path, obj, *, extra=None, member="data.pkl"):
    """The modern torch format: a zip with archive/data.pkl inside."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"archive/{member}", pickle.dumps(obj, protocol=4))
        z.writestr("archive/version", "3\n")
        z.writestr("archive/data/0", os.urandom(64))
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    return path


def nested_zip_bytes(obj):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(obj, protocol=4))
    return buf.getvalue()


def npy_bytes(descr, shape, body):
    """An npy v1 file, written from the format spec."""
    header = ("{'descr': %r, 'fortran_order': False, 'shape': %r, }"
              % (descr, shape)).encode("latin-1")
    pad = -(10 + len(header) + 1) % 64
    header = header + b" " * pad + b"\n"
    return (b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header))
            + header + body)


def write_npy_object(path, obj):
    """An object-dtype array: the body is a pickle."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(npy_bytes("|O", (1,),
                               pickle.dumps(obj, protocol=4)))
    return path


def write_npy_floats(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(npy_bytes("<f4", (4,),
                               struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)))
    return path


def write_npz(path, arrays):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for name, body in arrays.items():
            z.writestr(f"{name}.npy", body)
    return path


def write_joblib(path, obj, *, compress=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = pickle.dumps(obj, protocol=4)
    path.write_bytes(zlib.compress(raw) if compress else raw)
    return path


def safetensors_bytes(header: dict, body: bytes = b""):
    blob = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return struct.pack("<Q", len(blob)) + blob + body


def build(out: pathlib.Path):
    made = []
    # bare pickles
    made.append(write(out / "system_p2.pkl", SystemPayload(), 2))
    made.append(write(out / "system_p4.pkl", SystemPayload(), 4))
    made.append(write(out / "eval_p4.pkl", EvalPayload(), 4))
    made.append(write(out / "benign_p4.pkl",
                      UnknownCallablePayload(), 4))
    made.append(write(out / "plain_dict.pkl", state_dict(), 4))

    # torch formats
    made.append(write_legacy(out / "legacy_clean.pth", state_dict()))
    made.append(write_legacy(out / "legacy_unsafe.pth",
                             {"sd": state_dict(),
                              "x": SystemPayload()}))
    made.append(write_zip_checkpoint(out / "zip_clean.pt",
                                     state_dict()))
    made.append(write_zip_checkpoint(
        out / "zip_unsafe.pt",
        {"state_dict": state_dict(), "hook": SystemPayload()}))
    made.append(write_zip_checkpoint(
        out / "zip_nested.pt", state_dict(),
        extra={"extra/inner.zip":
               nested_zip_bytes({"hook": SystemPayload()})}))
    made.append(write_zip_checkpoint(
        out / "zip_traversal.pt", state_dict(),
        extra={"../escaped.txt": b"outside"}))

    # numpy
    made.append(write_npy_floats(out / "floats.npy"))
    made.append(write_npy_object(out / "object_unsafe.npy",
                                 SystemPayload()))
    made.append(write_npz(out / "arrays.npz", {
        "clean": npy_bytes("<f4", (2,), struct.pack("<2f", 1.0, 2.0)),
        "payload": npy_bytes("|O", (1,),
                             pickle.dumps(SystemPayload(),
                                          protocol=4)),
    }))

    # joblib
    made.append(write_joblib(out / "model_clean.joblib",
                             state_dict()))
    made.append(write_joblib(out / "model_unsafe.joblib",
                             {"est": SystemPayload()}))
    made.append(write_joblib(out / "model_plain.joblib",
                             state_dict(), compress=False))
    return made


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples/generated")
    args = ap.parse_args()
    for p in build(pathlib.Path(args.out)):
        print(p)


if __name__ == "__main__":
    main()
