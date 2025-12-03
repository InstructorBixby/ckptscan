from ckptscan.commands.main import main


def project(tmp_path, source, pin=None):
    (tmp_path / "app.py").write_text(source)
    if pin:
        (tmp_path / "requirements.txt").write_text(pin)
    return tmp_path


def test_opt_out_is_reported(tmp_path, capsys):
    p = project(tmp_path, "import torch\n"
                          "torch.load(f, weights_only=False)\n")
    assert main(["loaders", str(p)]) == 1
    assert "CKPT-013" in capsys.readouterr().out


def test_the_default_is_low_with_a_current_pin(tmp_path, capsys):
    p = project(tmp_path, "import torch\ntorch.load(f)\n",
                pin="torch==2.7.0\n")
    assert main(["loaders", str(p), "--fail-on", "medium"]) == 0
    assert "LOW" in capsys.readouterr().out


def test_the_default_is_high_with_an_old_pin(tmp_path, capsys):
    p = project(tmp_path, "import torch\ntorch.load(f)\n",
                pin="torch==2.1.0\n")
    assert main(["loaders", str(p)]) == 1
    out = capsys.readouterr().out
    assert "HIGH" in out
    assert "predates" in out


def test_no_pin_flag_keeps_the_original_severity(tmp_path, capsys):
    p = project(tmp_path, "import torch\ntorch.load(f)\n",
                pin="torch==2.1.0\n")
    assert main(["loaders", str(p), "--no-pin",
                 "--fail-on", "medium"]) == 0


def test_an_unknown_pin_does_not_lower_anything(tmp_path, capsys):
    p = project(tmp_path, "import torch\n"
                          "torch.load(f, weights_only=False)\n")
    assert main(["loaders", str(p)]) == 1


def test_a_clean_project(tmp_path):
    p = project(tmp_path, "import torch\n"
                          "torch.load(f, weights_only=True)\n")
    assert main(["loaders", str(p)]) == 0


def test_the_project_flag_points_somewhere_else(tmp_path, capsys):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import torch\ntorch.load(f)\n")
    (tmp_path / "requirements.txt").write_text("torch==2.1.0\n")
    assert main(["loaders", str(src), "--project", str(tmp_path)]) == 1
    assert "predates" in capsys.readouterr().out
