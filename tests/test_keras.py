from ckptscan.analysers import keras_zip
from ckptscan.scanner import scan_file


def rules(path):
    return sorted({f.rule for f in scan_file(path)})


def test_a_clean_keras_model_is_clean(fixtures):
    assert rules(fixtures / "keras_clean.keras") == []


def test_a_lambda_layer_is_critical(fixtures):
    findings = scan_file(fixtures / "keras_lambda.keras")
    lam = [f for f in findings if f.rule == "CKPT-006"]
    assert lam and lam[0].severity == "critical"
    assert "lambda_1" in lam[0].location


def test_a_lambda_in_a_submodel_is_found(fixtures):
    """Where they actually hide."""
    findings = scan_file(fixtures / "keras_nested_lambda.keras")
    assert any(f.rule == "CKPT-006" for f in findings)


def test_a_custom_registered_layer_is_high(fixtures):
    findings = scan_file(fixtures / "keras_custom.keras")
    by_rule = {f.rule for f in findings}
    assert "CKPT-018" in by_rule
    assert "CKPT-006" not in by_rule


def test_a_lambda_maps_to_a_taxonomy_id(fixtures):
    findings = scan_file(fixtures / "keras_lambda.keras")
    lam = [f for f in findings if f.rule == "CKPT-006"][0]
    assert "OUT-003" in lam.taxonomy


def test_a_keras_archive_is_recognised(fixtures):
    data = (fixtures / "keras_clean.keras").read_bytes()
    assert keras_zip.is_keras_archive(data)


def test_a_torch_checkpoint_is_not_a_keras_archive(fixtures):
    data = (fixtures / "zip_clean.pt").read_bytes()
    assert not keras_zip.is_keras_archive(data)


def test_a_keras_archive_with_no_config_is_not_an_error(tmp_path):
    import zipfile
    p = tmp_path / "empty.keras"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("metadata.json", "{}")
    assert scan_file(p) == []


def test_a_broken_config_is_a_low_finding(tmp_path):
    import zipfile
    p = tmp_path / "broken.keras"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("config.json", "{not json")
    assert [f.rule for f in scan_file(p)] == ["CKPT-004"]
