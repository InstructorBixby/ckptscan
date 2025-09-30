"""ONNX-shaped fixtures, written as protobuf by hand.

No `onnx` package needed to build them, which keeps the test suite
dependency-free. A ModelProto with an ir_version, an opset_import and a
graph with one node is enough to exercise every field the analyser
reads, and hand-writing it means the fixture is explicit about exactly
which bytes are being tested.

Nothing here is a working model. It is a correctly-framed protobuf.
"""
import pathlib
import struct


def _varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _tag(field, wire):
    return _varint((field << 3) | wire)


def _vint(field, value):
    return _tag(field, 0) + _varint(value)


def _bytes(field, value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _tag(field, 2) + _varint(len(value)) + value


def opset(domain, version=1):
    return _bytes(1, domain) + _vint(2, version)


def node(op_type, domain=""):
    body = _bytes(4, op_type)
    if domain:
        body += _bytes(7, domain)
    return body


def graph(nodes, name="g"):
    body = b"".join(_bytes(1, n) for n in nodes) + _bytes(2, name)
    return body


def metadata(key, value):
    return _bytes(1, key) + _bytes(2, value)


def model(*, opsets=(("", 17),), nodes=(("Relu", ""),), meta=()):
    body = _vint(1, 9)                       # ir_version
    body += _bytes(2, "ckptscan-fixture")    # producer_name
    for domain, version in opsets:
        body += _bytes(8, opset(domain, version))
    body += _bytes(7, graph([node(op, dom) for op, dom in nodes]))
    for key, value in meta:
        body += _bytes(14, metadata(key, value))
    return body


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def build(out: pathlib.Path):
    made = []
    made.append(write(out / "onnx_clean.onnx", model()))
    made.append(write(out / "onnx_custom_domain.onnx",
                      model(opsets=(("", 17), ("com.evilcorp.ops", 1)),
                            nodes=(("Relu", ""),
                                   ("SecretOp", "com.evilcorp.ops")))))
    made.append(write(out / "onnx_custom_lib.onnx",
                      model(meta=(("custom_op_library",
                                   "./libcustomops.so"),))))
    made.append(write(out / "onnx_ms_domain.onnx",
                      model(opsets=(("", 17), ("com.microsoft", 1)))))
    assert struct.pack("<B", 8)[0] == 8
    return made


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="samples/generated")
    args = ap.parse_args()
    for p in build(pathlib.Path(args.out)):
        print(p)
