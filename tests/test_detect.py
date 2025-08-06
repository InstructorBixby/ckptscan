import io
import json
import pickle
import struct
import zipfile

from ckptscan import detect


def test_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl", b"x")
    assert detect.sniff(buf.getvalue()) == detect.ZIP


def test_npz_is_a_zip_but_named():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.npy", b"x")
    assert detect.sniff(buf.getvalue(), name="w.npz") == detect.NPZ


def test_protocol_4_pickle():
    assert detect.sniff(pickle.dumps({"a": 1}, protocol=4)) \
        == detect.PICKLE


def test_protocol_0_pickle():
    assert detect.sniff(pickle.dumps({"a": 1}, protocol=0)) \
        == detect.PICKLE


def test_legacy_torch():
    data = b"\x80\x02\x8a\x0a" + \
        detect.TORCH_MAGIC.to_bytes(10, "little") + b"rest"
    assert detect.sniff(data) == detect.TORCH_LEGACY


def test_npy():
    assert detect.sniff(b"\x93NUMPY\x01\x00") == detect.NPY


def test_hdf5():
    assert detect.sniff(b"\x89HDF\r\n\x1a\n" + b"\x00" * 8) \
        == detect.HDF5


def test_gguf():
    assert detect.sniff(b"GGUF\x03\x00\x00\x00") == detect.GGUF


def test_safetensors():
    header = json.dumps({"__metadata__": {}}).encode()
    data = struct.pack("<Q", len(header)) + header + b"\x00" * 16
    assert detect.sniff(data) == detect.SAFETENSORS


def test_an_absurd_safetensors_header_length_is_not_safetensors():
    data = struct.pack("<Q", 2**60) + b"{}"
    assert detect.sniff(data) != detect.SAFETENSORS


def test_declared_from_the_extension():
    assert detect.declared("m.safetensors") == detect.SAFETENSORS
    assert detect.declared("m.pt") == detect.ZIP
    assert detect.declared("m.whatever") == detect.UNKNOWN


def test_agreement():
    assert detect.agrees(detect.ZIP, detect.PICKLE)
    assert detect.agrees(detect.NPZ, detect.ZIP)
    assert detect.agrees(detect.UNKNOWN, detect.PICKLE)
    assert not detect.agrees(detect.SAFETENSORS, detect.PICKLE)
