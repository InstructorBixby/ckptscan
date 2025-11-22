from ckptscan import loaders


def scan(src):
    return loaders.analyse_source(src, path="app.py")


def rules(src):
    return sorted(f.rule for f in scan(src))


def test_weights_only_false_is_high():
    findings = scan("import torch\n"
                    "m = torch.load(p, weights_only=False)\n")
    assert [f.rule for f in findings] == ["CKPT-013"]
    assert findings[0].severity == "high"
    assert findings[0].location == "app.py:2"


def test_weights_only_true_is_nothing():
    assert rules("import torch\n"
                 "m = torch.load(p, weights_only=True)\n") == []


def test_the_default_is_low_and_mentions_the_pin():
    findings = scan("import torch\nm = torch.load(p)\n")
    assert findings[0].severity == "low"
    assert "check the pin" in findings[0].message


def test_a_splat_is_medium_not_a_guess():
    findings = scan("import torch\nm = torch.load(p, **opts)\n")
    assert findings[0].severity == "medium"
    assert "cannot be determined" in findings[0].message


def test_a_variable_is_medium_not_high():
    # Deliberately not constant-propagated; saying "I do not know"
    # beats guessing a severity.
    findings = scan("import torch\nWO = False\n"
                    "m = torch.load(p, weights_only=WO)\n")
    assert findings[0].severity == "medium"


def test_numpy_allow_pickle():
    assert rules("import numpy as np\n"
                 "a = np.load(p, allow_pickle=True)\n") == ["CKPT-015"]


def test_numpy_without_allow_pickle_is_clean():
    assert rules("import numpy as np\na = np.load(p)\n") == []


def test_keras_safe_mode_false():
    findings = scan("from keras.models import load_model\n"
                    "m = load_model(p, safe_mode=False)\n")
    assert [f.rule for f in findings] == ["CKPT-016"]
    assert findings[0].severity == "high"


def test_keras_default_is_clean():
    assert rules("m = load_model(p)\n") == []


def test_bare_pickle_load():
    assert rules("import pickle\nx = pickle.load(fh)\n") == ["CKPT-011"]


def test_joblib_load():
    assert rules("import joblib\nm = joblib.load(p)\n") == ["CKPT-011"]


def test_pandas_read_pickle():
    assert rules("import pandas as pd\n"
                 "df = pd.read_pickle(p)\n") == ["CKPT-011"]


def test_an_unrelated_load_is_not_a_finding():
    assert rules("import json\nx = json.load(fh)\n") == []
    assert rules("import yaml\nx = yaml.safe_load(fh)\n") == []


def test_a_method_called_load_on_an_object_is_not_torch():
    assert rules("cache.load(p)\n") == []


def test_unparseable_source_is_info():
    findings = scan("def oops(:\n")
    assert [f.rule for f in findings] == ["CKPT-004"]
    assert findings[0].severity == "info"


def test_a_directory_walk_skips_vendored_code(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "import torch\ntorch.load(p, weights_only=False)\n")
    vendor = tmp_path / ".venv" / "lib" / "site-packages"
    vendor.mkdir(parents=True)
    (vendor / "other.py").write_text(
        "import torch\ntorch.load(p, weights_only=False)\n")
    findings = loaders.analyse_path(tmp_path)
    assert len(findings) == 1
