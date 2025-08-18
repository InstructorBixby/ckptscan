import pickle

from ckptscan.scanner import scan_file


def test_a_pickle_called_safetensors_is_high(tmp_path):
    p = tmp_path / "model.safetensors"
    p.write_bytes(pickle.dumps({"a": 1}, protocol=4))
    findings = scan_file(p)
    mismatch = [f for f in findings if f.rule == "CKPT-008"]
    assert mismatch and mismatch[0].severity == "high"


def test_a_pickle_called_bin_is_not_a_mismatch(tmp_path):
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(pickle.dumps({"a": 1}, protocol=4))
    assert [f.rule for f in scan_file(p)] == []


def test_a_zip_called_bin_is_not_a_mismatch(tmp_path, fixtures):
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes((fixtures / "zip_clean.pt").read_bytes())
    assert [f.rule for f in scan_file(p)] == []


def test_an_unrecognised_file_says_so(tmp_path):
    p = tmp_path / "weights.pt"
    p.write_bytes(b"\x7fELF" + b"\x00" * 64)
    assert [f.rule for f in scan_file(p)] == ["CKPT-007"]
