from ckptscan import pins


def test_no_pin_is_unknown(tmp_path):
    assert pins.torch_floor(tmp_path) is None
    assert pins.predates_flip(None) is None


def test_requirements_exact_pin(tmp_path):
    (tmp_path / "requirements.txt").write_text("torch==2.1.0\n")
    assert pins.torch_floor(tmp_path) == (2, 1, 0)
    assert pins.predates_flip((2, 1, 0)) is True


def test_a_current_pin_does_not_predate_the_flip(tmp_path):
    (tmp_path / "requirements.txt").write_text("torch==2.7.1\n")
    assert pins.predates_flip(pins.torch_floor(tmp_path)) is False


def test_a_floor_is_the_interesting_bound(tmp_path):
    (tmp_path / "requirements.txt").write_text("torch>=2.2\n")
    assert pins.torch_floor(tmp_path) == (2, 2)


def test_pyproject_dependencies(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["torch==2.0.1", '
        '"numpy"]\n')
    assert pins.torch_floor(tmp_path) == (2, 0, 1)


def test_pyproject_extras_count_too(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = []\n'
        '[project.optional-dependencies]\ngpu = ["torch==1.13.1"]\n')
    assert pins.torch_floor(tmp_path) == (1, 13, 1)


def test_the_oldest_pin_across_files_wins(tmp_path):
    (tmp_path / "requirements.txt").write_text("torch>=2.7\n")
    (tmp_path / "requirements-old.txt").write_text("torch==1.13.0\n")
    assert pins.torch_floor(tmp_path) == (1, 13, 0)


def test_a_broken_pyproject_does_not_raise(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project\nbroken")
    assert pins.torch_floor(tmp_path) is None


def test_a_torchvision_line_is_not_a_torch_pin(tmp_path):
    (tmp_path / "requirements.txt").write_text("torchvision==0.15.0\n")
    assert pins.torch_floor(tmp_path) is None
