from ckptscan.analysers import numpy_arrays
from ckptscan.scanner import scan_file


def rules(path):
    return sorted({f.rule for f in scan_file(path)})


def test_a_float_array_is_clean(fixtures):
    assert rules(fixtures / "floats.npy") == []


def test_an_object_array_is_high(fixtures):
    findings = scan_file(fixtures / "object_unsafe.npy")
    by_rule = {f.rule: f for f in findings}
    assert "CKPT-005" in by_rule
    assert by_rule["CKPT-005"].severity == "high"
    assert "allow_pickle" in by_rule["CKPT-005"].message


def test_the_payload_inside_the_object_array_is_analysed(fixtures):
    assert "CKPT-001" in rules(fixtures / "object_unsafe.npy")


def test_an_npz_member_is_analysed(fixtures):
    found = rules(fixtures / "arrays.npz")
    assert "CKPT-005" in found
    assert "CKPT-001" in found


def test_the_header_is_literal_eval_not_eval():
    # The header is attacker-controlled. eval on it would be the exact
    # bug this tool exists to find, in the tool.
    src = numpy_arrays.read_header.__module__
    import inspect

    import ckptscan.analysers.numpy_arrays as mod
    text = inspect.getsource(mod)
    assert "literal_eval" in text
    assert "eval(" not in text.replace("literal_eval(", "")
    assert src


def test_a_structured_dtype_containing_an_object_is_caught():
    from ckptscan.analysers.numpy_arrays import _is_object_dtype
    assert _is_object_dtype([("a", "<f4"), ("b", "|O")])
    assert not _is_object_dtype([("a", "<f4"), ("b", "<i8")])


def test_a_bad_header_is_a_low_finding(tmp_path):
    p = tmp_path / "broken.npy"
    p.write_bytes(b"\x93NUMPY\x01\x00\x05\x00not a dict")
    assert [f.rule for f in scan_file(p)] == ["CKPT-004"]
