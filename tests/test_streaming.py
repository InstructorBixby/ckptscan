"""Memory behaviour, which is a correctness property here.

The first report from somebody else's machine was an out-of-memory kill
on a sharded 70B model. Not the analysis -- `read_bytes()`. These tests
pin the fix by counting how much gets read, because measuring RSS in a
test is unreliable and counting bytes is not.
"""
import io
import pickle
import zipfile

from ckptscan import opcodes
from ckptscan.analysers import archives
from ckptscan.scanner import scan_file


class CountingReader(io.RawIOBase):
    """A file-like object that records how much was read of it."""

    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)
        self.read_bytes = 0

    def read(self, n=-1):
        chunk = self._buf.read(n)
        self.read_bytes += len(chunk)
        return chunk

    def readline(self, *a):
        line = self._buf.readline(*a)
        self.read_bytes += len(line)
        return line

    def readable(self):
        return True


def shard_bytes(payload_obj, tail_mib=8):
    """A pickle followed by a lot of tensor-shaped filler."""
    return pickle.dumps(payload_obj, protocol=4) + \
        b"\x00" * (tail_mib * 1024 * 1024)


def test_a_stream_is_not_read_past_the_pickle():
    data = shard_bytes({"weight": [1.0, 2.0]})
    reader = CountingReader(data)
    opcodes.parse(reader)
    # The pickle is a few dozen bytes. genops reads in small chunks,
    # so allow generously -- the point is that it is not 8 MiB.
    assert reader.read_bytes < 64 * 1024
    assert len(data) > 8 * 1024 * 1024


def test_a_payload_is_still_found_in_a_shard_shaped_file(tmp_path):
    import os

    class Payload:
        def __reduce__(self):
            return (os.system, ("true",))

    p = tmp_path / "model-00001-of-00004.bin"
    p.write_bytes(shard_bytes({"hook": Payload()}))
    findings = scan_file(p)
    assert [f.rule for f in findings] == ["CKPT-001"]


def test_an_archive_member_is_streamed(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("archive/data.pkl",
                   pickle.dumps({"w": [1.0]}, protocol=4))
        z.writestr("archive/data/0", b"\x00" * (4 * 1024 * 1024))
    p = tmp_path / "big.pt"
    p.write_bytes(buf.getvalue())
    assert scan_file(p) == []


def test_the_rewound_wrapper_replays_the_head():
    rest = io.BytesIO(b"cdef")
    r = archives._Rewound(b"ab", rest)
    assert r.read(1) == b"a"
    assert r.read(3) == b"bcd"
    assert r.read() == b"ef"


def test_the_rewound_wrapper_handles_read_all_from_the_start():
    r = archives._Rewound(b"ab", io.BytesIO(b"cd"))
    assert r.read() == b"abcd"


def test_the_rewound_wrapper_readline():
    r = archives._Rewound(b"ab\ncd", io.BytesIO(b"ef\ngh"))
    assert r.readline() == b"ab\n"
    assert r.readline() == b"cdef\n"


def test_a_file_too_big_for_a_whole_file_format_is_reported(tmp_path,
                                                            monkeypatch):
    import ckptscan.scanner as scanner
    monkeypatch.setattr(scanner, "MAX_WHOLE_FILE", 16)
    p = tmp_path / "huge.safetensors"
    p.write_bytes(b"\x08\x00\x00\x00\x00\x00\x00\x00{}" +
                  b"\x00" * 64)
    findings = scanner.scan_file(p)
    assert [f.rule for f in findings] == ["CKPT-014"]


def test_the_opcode_budget_still_applies_to_a_stream():
    data = pickle.dumps(list(range(5000)), protocol=4)
    stream = opcodes.parse(CountingReader(data), max_opcodes=50)
    assert stream.truncated
