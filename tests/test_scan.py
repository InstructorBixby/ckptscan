import builtins
import os

import scan


def test_protocol_2_system_payload(fixtures):
    findings, globals_seen = scan.scan(fixtures / "system_p2.pkl")
    assert ("os", "system") in [(m, a) for m, a, _ in globals_seen]
    assert any("os.system" in msg for _, msg in findings)


def test_protocol_4_system_payload(fixtures):
    # The whole reason STACK_GLOBAL exists in the scanner.
    _, globals_seen = scan.scan(fixtures / "system_p4.pkl")
    assert ("os", "system") in [(m, a) for m, a, _ in globals_seen]


def test_eval_payload(fixtures):
    _, globals_seen = scan.scan(fixtures / "eval_p4.pkl")
    assert ("builtins", "eval") in [(m, a) for m, a, _ in globals_seen]


def test_a_plain_dict_has_no_globals(fixtures):
    findings, globals_seen = scan.scan(fixtures / "plain_dict.pkl")
    assert globals_seen == []
    assert findings == []


def test_a_benign_reduce_is_still_reported_for_now(fixtures):
    findings, _ = scan.scan(fixtures / "benign_p4.pkl")
    assert any("REDUCE" in msg for _, msg in findings)


def test_scanning_calls_nothing_the_stream_names(fixtures,
                                                 monkeypatch):
    """The load-bearing test in the whole project.

    If a refactor ever makes the scanner import or call what the stream
    names, this fails, and it fails before the payload in a real file
    gets the chance to matter.
    """
    tripped = []
    monkeypatch.setattr(os, "system",
                        lambda *a, **k: tripped.append(("system", a)))
    monkeypatch.setattr(builtins, "eval",
                        lambda *a, **k: tripped.append(("eval", a)))

    real_import = builtins.__import__

    def watched_import(name, *a, **k):
        if name in ("os", "subprocess", "posix", "nt"):
            tripped.append(("import", name))
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", watched_import)

    for name in ("system_p2.pkl", "system_p4.pkl", "eval_p4.pkl"):
        scan.scan(fixtures / name)
    assert tripped == []


def test_no_marker_file_is_ever_written(fixtures, tmp_path):
    marker = tmp_path / "ckptscan-fixture-ran"
    scan.scan(fixtures / "system_p4.pkl")
    assert not marker.exists()
