import collections
import pickle

from ckptscan import policy
from ckptscan.analysers import pickles
from ckptscan.commands.main import main


class Custom:
    def __reduce__(self):
        return (collections.namedtuple, ("P", "x"))


def test_unknown_is_medium_by_default():
    data = pickle.dumps(Custom(), protocol=4)
    findings = pickles.analyse(data, path="m.pkl")
    assert findings[0].severity == "medium"


def test_unknown_is_high_in_strict_mode():
    data = pickle.dumps(Custom(), protocol=4)
    findings = pickles.analyse(data, path="m.pkl", strict=True)
    assert [f.rule for f in findings] == ["CKPT-002"]
    assert findings[0].severity == "high"


def test_a_local_allowlist_silences_it():
    data = pickle.dumps(Custom(), protocol=4)
    extra = {("collections", "namedtuple"): "ours, reviewed"}
    assert pickles.analyse(data, path="m.pkl", extra=extra) == []


def test_strict_ignores_the_local_allowlist():
    data = pickle.dumps(Custom(), protocol=4)
    extra = {("collections", "namedtuple"): "ours, reviewed"}
    findings = pickles.analyse(data, path="m.pkl", extra=extra,
                               strict=True)
    assert [f.rule for f in findings] == ["CKPT-002"]


def test_a_local_allowlist_cannot_silence_a_dangerous_call():
    import os

    class Payload:
        def __reduce__(self):
            return (os.system, ("true",))

    extra = {("os", "system"): "we promise it is fine"}
    findings = pickles.analyse(pickle.dumps(Payload(), protocol=4),
                               path="m.pkl", extra=extra)
    assert [f.rule for f in findings] == ["CKPT-001"]


def test_strict_reports_what_the_allowlist_waved_through():
    obj = collections.OrderedDict(a=[1.0])
    findings = pickles.analyse(pickle.dumps(obj, protocol=4),
                               path="m.pkl", strict=True)
    assert [f.rule for f in findings] == ["CKPT-020"]
    assert findings[0].severity == "info"
    assert "allowlisted (core)" in findings[0].message


def test_strict_names_where_an_entry_came_from():
    assert policy.source_of("numpy._core.multiarray",
                            "_reconstruct") == "fp-12"
    assert policy.source_of("collections", "OrderedDict") == "core"


def test_strict_on_a_clean_corpus_sample_still_exits_zero(samples):
    # CKPT-020 is info, so it is below any sane --fail-on.
    assert main([str(samples / "clean"), "--strict"]) == 0


def test_strict_warns_that_it_ignored_the_config(samples, tmp_path,
                                                 monkeypatch, capsys):
    (tmp_path / "ckptscan.toml").write_text(
        '[allow]\n"mypkg.Thing" = "our own class, reviewed in '
        'ticket 9, constructor takes numbers"\n')
    monkeypatch.chdir(tmp_path)
    main([str(samples / "clean"), "--strict"])
    assert "[allow] in the config is ignored" in \
        capsys.readouterr().err
