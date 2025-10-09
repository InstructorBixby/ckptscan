from ckptscan.analysers import onnx_file
from ckptscan.scanner import scan_file


def rules(path):
    return sorted({f.rule for f in scan_file(path)})


def test_a_standard_model_is_clean(fixtures):
    assert rules(fixtures / "onnx_clean.onnx") == []


def test_a_vendor_domain_is_still_clean(fixtures):
    # com.microsoft is implemented by a standard runtime. Reporting it
    # would make every real exported model noisy.
    assert rules(fixtures / "onnx_ms_domain.onnx") == []


def test_a_custom_domain_is_medium(fixtures):
    findings = scan_file(fixtures / "onnx_custom_domain.onnx")
    assert [f.rule for f in findings] == ["CKPT-007"]
    assert "com.evilcorp.ops" in findings[0].message
    assert findings[0].severity == "medium"


def test_a_custom_op_library_in_metadata_is_high(fixtures):
    findings = scan_file(fixtures / "onnx_custom_lib.onnx")
    lib = [f for f in findings if f.rule == "CKPT-018"]
    assert lib and lib[0].severity == "high"
    assert "libcustomops.so" in lib[0].message


def test_the_varint_reader():
    assert onnx_file._varint(b"\x01", 0) == (1, 1)
    assert onnx_file._varint(b"\xac\x02", 0) == (300, 2)


def test_an_unterminated_varint_raises():
    import pytest
    with pytest.raises(ValueError):
        onnx_file._varint(b"\x80\x80\x80", 0)


def test_a_truncated_field_does_not_crash():
    # Claims a 200-byte string in a 4-byte message.
    data = b"\x08\x09" + b"\x42\xc8\x01"
    assert onnx_file.analyse(data, path="m.onnx") == []


def test_garbage_does_not_crash():
    assert onnx_file.analyse(b"\x08" + b"\xff" * 64,
                             path="m.onnx") == []
