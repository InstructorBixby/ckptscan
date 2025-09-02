import json
import struct

from ckptscan.analysers import safetensors_file


def build(header: dict, payload: bytes = b"") -> bytes:
    blob = json.dumps(header, separators=(",", ":")).encode()
    return struct.pack("<Q", len(blob)) + blob + payload


def rules(data):
    return sorted(f.rule for f in
                  safetensors_file.analyse(data, path="m.safetensors"))


def test_a_well_formed_file_is_clean():
    data = build({"w": {"dtype": "F32", "shape": [2],
                        "data_offsets": [0, 8]}},
                 b"\x00" * 8)
    assert rules(data) == []


def test_metadata_is_not_a_tensor():
    data = build({"__metadata__": {"format": "pt"},
                  "w": {"dtype": "F32", "shape": [1],
                        "data_offsets": [0, 4]}}, b"\x00" * 4)
    assert rules(data) == []


def test_an_offset_past_the_payload():
    data = build({"w": {"data_offsets": [0, 9999]}}, b"\x00" * 8)
    findings = safetensors_file.analyse(data, path="m.safetensors")
    assert [f.rule for f in findings] == ["CKPT-017"]
    assert "outside" in findings[0].message


def test_a_reversed_span():
    data = build({"w": {"data_offsets": [8, 2]}}, b"\x00" * 8)
    assert rules(data) == ["CKPT-017"]


def test_overlapping_tensors():
    data = build({"a": {"data_offsets": [0, 8]},
                  "b": {"data_offsets": [4, 12]}}, b"\x00" * 12)
    findings = safetensors_file.analyse(data, path="m.safetensors")
    assert any("overlap" in f.message for f in findings)


def test_a_tensor_with_no_offsets():
    data = build({"w": {"dtype": "F32"}}, b"")
    assert rules(data) == ["CKPT-017"]


def test_a_header_longer_than_the_file():
    data = struct.pack("<Q", 4096) + b"{}"
    assert rules(data) == ["CKPT-017"]


def test_a_header_that_is_not_json():
    blob = b"not json at all"
    data = struct.pack("<Q", len(blob)) + blob
    assert rules(data) == ["CKPT-017"]


def test_a_header_that_is_a_list():
    blob = b"[1,2,3]"
    data = struct.pack("<Q", len(blob)) + blob
    assert rules(data) == ["CKPT-017"]


def test_a_truncated_file():
    assert rules(b"\x00\x01") == ["CKPT-004"]


def test_nothing_here_is_ever_critical():
    # The format cannot execute. Reporting a header quirk as critical
    # would undermine the one recommendation worth making.
    data = build({"w": {"data_offsets": [0, 9999]}}, b"\x00" * 8)
    for f in safetensors_file.analyse(data, path="m.safetensors"):
        assert f.severity in ("low", "medium")
