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
"""
import argparse
import collections
import io
import os
import pathlib
import pickle
import zipfile


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
    return made


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples/generated")
    args = ap.parse_args()
    for p in build(pathlib.Path(args.out)):
        print(p)


if __name__ == "__main__":
    main()
