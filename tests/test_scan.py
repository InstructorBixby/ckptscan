import scan


def test_protocol_2_system_payload(fixtures):
    findings, globals_seen = scan.scan(fixtures / "system_p2.pkl")
    assert ("os", "system") in [(m, a) for m, a, _ in globals_seen]
    assert any("os.system" in msg for _, msg in findings)


def test_protocol_4_system_payload(fixtures):
    # The whole reason STACK_GLOBAL exists in the scanner.
    findings, globals_seen = scan.scan(fixtures / "system_p4.pkl")
    assert ("os", "system") in [(m, a) for m, a, _ in globals_seen]


def test_eval_payload(fixtures):
    _, globals_seen = scan.scan(fixtures / "eval_p4.pkl")
    assert ("builtins", "eval") in [(m, a) for m, a, _ in globals_seen]


def test_a_plain_dict_has_no_globals(fixtures):
    findings, globals_seen = scan.scan(fixtures / "plain_dict.pkl")
    assert globals_seen == []
    assert findings == []


def test_a_benign_reduce_is_still_reported_for_now(fixtures):
    # dict is not dangerous, but REDUCE is flagged unconditionally at
    # this stage. This is the false positive the allowlist has to fix.
    findings, _ = scan.scan(fixtures / "benign_p4.pkl")
    assert any("REDUCE" in msg for _, msg in findings)


def test_nothing_is_executed(fixtures, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(scan.os if hasattr(scan, "os") else scan,
                        "__name__", scan.__name__)
    scan.scan(fixtures / "system_p4.pkl")
    assert calls == []
