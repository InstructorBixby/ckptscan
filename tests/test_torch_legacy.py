import pickle

from ckptscan.analysers import torch_legacy
from ckptscan.scanner import scan_file


def test_split_finds_every_stream(fixtures):
    data = (fixtures / "legacy_clean.pth").read_bytes()
    assert len(torch_legacy.split(data)) >= 3


def test_a_clean_legacy_file_is_clean(fixtures):
    assert scan_file(fixtures / "legacy_clean.pth") == []


def test_a_payload_in_a_later_stream_is_found(fixtures):
    """The whole reason this analyser exists.

    genops stops at the first STOP, which in this format is the end of
    the magic number. Analysing the file as one stream finds nothing.
    """
    findings = scan_file(fixtures / "legacy_unsafe.pth")
    assert [f.rule for f in findings] == ["CKPT-001"]
    assert "stream" in findings[0].location


def test_a_single_stream_still_works():
    data = pickle.dumps({"a": 1}, protocol=2)
    assert len(torch_legacy.split(data)) == 1


def test_trailing_garbage_does_not_loop_forever():
    data = pickle.dumps({"a": 1}, protocol=2) + b"\x00" * 1000
    assert len(torch_legacy.split(data)) == 1
