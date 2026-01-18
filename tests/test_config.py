import pytest

from ckptscan import config
from ckptscan.findings import Finding, Severity


def f(rule="CKPT-002", path="m.pt", severity=Severity.MEDIUM):
    return Finding(rule=rule, severity=severity, path=path,
                   message="x")


def test_an_empty_config_changes_nothing():
    cfg = config.loads("")
    kept, dropped = cfg.apply([f()])
    assert len(kept) == 1 and dropped == []


def test_severity_override():
    cfg = config.loads('[severity]\n"CKPT-002" = "low"\n')
    kept, _ = cfg.apply([f()])
    assert kept[0].severity == "low"


def test_an_unknown_rule_in_severity_is_an_error():
    with pytest.raises(config.ConfigError):
        config.loads('[severity]\n"CKPT-404" = "low"\n')


def test_a_nonsense_severity_is_an_error():
    with pytest.raises(config.ConfigError) as e:
        config.loads('[severity]\n"CKPT-002" = "scary"\n')
    assert "not a severity" in str(e.value)


def test_a_suppression_needs_a_justification():
    with pytest.raises(config.ConfigError) as e:
        config.loads('[[suppress]]\nrule = "CKPT-002"\n')
    assert "justification is required" in str(e.value)


def test_a_token_justification_is_refused():
    with pytest.raises(config.ConfigError) as e:
        config.loads('[[suppress]]\nrule = "CKPT-002"\n'
                     'justification = "noisy"\n')
    assert "six months" in str(e.value)


def test_a_real_justification_works():
    cfg = config.loads(
        '[[suppress]]\nrule = "CKPT-002"\n'
        'justification = "our own serialiser classes, reviewed in '
        'ticket PLT-412 and covered by a unit test"\n')
    kept, dropped = cfg.apply([f()])
    assert kept == []
    assert dropped[0][1].justification.startswith("our own")


def test_a_suppression_can_be_scoped_to_paths():
    cfg = config.loads(
        '[[suppress]]\nrule = "CKPT-002"\n'
        'paths = ["vendor/*.pt"]\n'
        'justification = "vendor ships its own classes, contract '
        'reviewed, see ticket PLT-511"\n')
    kept, dropped = cfg.apply([f(path="vendor/a.pt"), f(path="ours.pt")])
    assert [k.path for k in kept] == ["ours.pt"]
    assert len(dropped) == 1


def test_an_unknown_rule_in_a_suppression_lists_the_known_ones():
    with pytest.raises(config.ConfigError) as e:
        config.loads('[[suppress]]\nrule = "CKPT-404"\n'
                     'justification = "a perfectly good reason that '
                     'is long enough"\n')
    assert "CKPT-001" in str(e.value)


def test_an_allow_entry_needs_a_reason():
    with pytest.raises(config.ConfigError) as e:
        config.loads('[allow]\n"mypkg.Thing" = "fine"\n')
    assert "promise" in str(e.value)


def test_an_allow_entry_with_a_reason():
    cfg = config.loads(
        '[allow]\n"mypkg.layers.Thing" = "our own layer class, '
        'constructor takes only numbers, reviewed"\n')
    assert ("mypkg.layers", "Thing") in cfg.allow


def test_an_unknown_section_is_an_error():
    with pytest.raises(config.ConfigError):
        config.loads('[nonsense]\nx = 1\n')


def test_broken_toml():
    with pytest.raises(config.ConfigError):
        config.loads("[unclosed\n")


def test_discover_walks_upwards(tmp_path, monkeypatch):
    (tmp_path / "ckptscan.toml").write_text('fail_on = "high"\n')
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)
    cfg = config.discover(".")
    assert cfg is not None and cfg.fail_on == "high"


def test_discover_returns_none_when_there_is_nothing(tmp_path):
    assert config.discover(tmp_path) is None
