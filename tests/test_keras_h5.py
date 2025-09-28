from ckptscan.analysers import keras_h5
from ckptscan.scanner import scan_file


def test_the_fallback_finds_a_lambda(fixtures):
    findings = scan_file(fixtures / "keras_lambda.h5")
    lam = [f for f in findings if f.rule == "CKPT-006"]
    assert lam
    assert lam[0].severity == "critical"


def test_the_fallback_says_it_is_a_fallback(fixtures):
    findings = scan_file(fixtures / "keras_lambda.h5")
    lam = [f for f in findings if f.rule == "CKPT-006"][0]
    assert "scanning the raw file" in lam.message
    assert "ckptscan[keras]" in lam.message


def test_a_clean_h5_is_clean(fixtures):
    assert [f.rule for f in scan_file(fixtures / "keras_clean.h5")] == []


def test_the_brace_matcher_ignores_braces_in_strings():
    blob = (b"model_config\x00"
            b'{"class_name": "Lambda", "config": {"name": "a}b"}}'
            b"\x00trailing")
    config = keras_h5._fallback(blob)
    assert config["class_name"] == "Lambda"
    assert config["config"]["name"] == "a}b"


def test_the_brace_matcher_handles_an_escaped_quote():
    blob = (b"model_config\x00"
            b'{"class_name": "Dense", "config": {"name": "a\\"b"}}')
    config = keras_h5._fallback(blob)
    assert config["config"]["name"] == 'a"b'


def test_no_config_at_all_is_not_a_finding():
    data = b"\x89HDF\r\n\x1a\n" + b"\x00" * 128
    assert keras_h5.analyse(data, path="w.h5") == []
