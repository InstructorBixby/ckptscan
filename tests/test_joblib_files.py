from ckptscan.analysers import joblib_files
from ckptscan.scanner import scan_file


def rules(path):
    return sorted({f.rule for f in scan_file(path)})


def test_a_clean_compressed_model_is_clean(fixtures):
    assert rules(fixtures / "model_clean.joblib") == []


def test_a_payload_survives_decompression(fixtures):
    findings = scan_file(fixtures / "model_unsafe.joblib")
    assert [f.rule for f in findings] == ["CKPT-001"]
    assert "zlib" in findings[0].location


def test_an_uncompressed_joblib_works_too(fixtures):
    assert rules(fixtures / "model_plain.joblib") == []


def test_compression_detection():
    assert joblib_files.compression_of(b"\x1f\x8b\x08") == "gzip"
    assert joblib_files.compression_of(b"BZh9") == "bz2"
    assert joblib_files.compression_of(b"\x78\x9c") == "zlib"
    assert joblib_files.compression_of(b"\x80\x04") == ""


def test_a_broken_container_is_a_low_finding(tmp_path):
    p = tmp_path / "broken.joblib"
    p.write_bytes(b"\x1f\x8b\x08" + b"\x00" * 32)
    assert [f.rule for f in scan_file(p)] == ["CKPT-004"]
