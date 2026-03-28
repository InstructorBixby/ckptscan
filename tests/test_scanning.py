"""The tests that were spread across one file per format, pointed at
the generated corpus rather than at their own fixtures.

Keeping two sets of sample files meant two things to update whenever a
container writer changed, and they had already diverged once.
"""
import pickle

from ckptscan.analysers import torch_legacy
from ckptscan.commands.main import main
from ckptscan.scanner import scan_file


def rules(path):
    return sorted({f.rule for f in scan_file(path)})


# --- archives -------------------------------------------------------

def test_a_payload_inside_a_zip_checkpoint_names_the_member(samples):
    findings = scan_file(samples / "unsafe" / "in_zip.pt")
    assert [f.rule for f in findings] == ["CKPT-001"]
    assert findings[0].location == "archive/data.pkl"


def test_a_nested_archive_names_the_full_path(samples):
    findings = scan_file(samples / "unsafe" / "nested_zip.pt")
    inner = [f for f in findings if f.rule == "CKPT-001"]
    assert inner and inner[0].location.startswith("extra/inner.zip!")


# --- legacy torch ---------------------------------------------------

def test_split_finds_every_stream(samples):
    data = (samples / "clean" / "legacy.pth").read_bytes()
    assert len(torch_legacy.split(data)) >= 3


def test_a_payload_in_a_later_stream_is_found(samples):
    findings = scan_file(samples / "unsafe" / "legacy_stream2.pth")
    assert [f.rule for f in findings] == ["CKPT-001"]
    assert "stream" in findings[0].location


def test_a_single_stream_still_works():
    assert len(torch_legacy.split(
        pickle.dumps({"a": 1}, protocol=2))) == 1


def test_trailing_garbage_does_not_loop_forever():
    data = pickle.dumps({"a": 1}, protocol=2) + b"\x00" * 1000
    assert len(torch_legacy.split(data)) == 1


# --- numpy and joblib ----------------------------------------------

def test_the_payload_inside_an_object_array_is_analysed(samples):
    found = rules(samples / "unsafe" / "object_array.npy")
    assert "CKPT-005" in found
    assert "CKPT-001" in found


def test_a_compressed_pickle_is_decompressed(samples):
    findings = scan_file(samples / "unsafe" / "model.joblib")
    assert [f.rule for f in findings] == ["CKPT-001"]
    assert "zlib" in findings[0].location


# --- mismatch ------------------------------------------------------

def test_a_pickle_called_safetensors_is_high(samples):
    findings = scan_file(samples / "unsafe" /
                         "mislabelled.safetensors")
    mismatch = [f for f in findings if f.rule == "CKPT-008"]
    assert mismatch and mismatch[0].severity == "high"


def test_a_pickle_called_bin_is_not_a_mismatch(tmp_path):
    p = tmp_path / "pytorch_model.bin"
    p.write_bytes(pickle.dumps({"a": 1}, protocol=4))
    assert [f.rule for f in scan_file(p)] == []


def test_an_unrecognised_file_says_so(tmp_path):
    p = tmp_path / "weights.pt"
    p.write_bytes(b"\x7fELF" + b"\x00" * 64)
    assert [f.rule for f in scan_file(p)] == ["CKPT-007"]


# --- keras ---------------------------------------------------------

def test_a_lambda_layer_is_critical_and_named(samples):
    findings = scan_file(samples / "unsafe" / "lambda.keras")
    lam = [f for f in findings if f.rule == "CKPT-006"]
    assert lam and lam[0].severity == "critical"
    assert "lam" in lam[0].location
    assert "OUT-003" in lam[0].taxonomy


# --- the cli -------------------------------------------------------

def test_the_whole_corpus_fails_the_gate(samples, capsys):
    assert main([str(samples)]) == 1
    out = capsys.readouterr().out
    assert out.count("CKPT-001") >= 7


def test_the_clean_half_passes(samples):
    assert main([str(samples / "clean")]) == 0
