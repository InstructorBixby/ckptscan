from ckptscan.findings import Severity
from ckptscan.registry import RULES, default_severity, unknown_ids


def test_every_rule_has_every_field():
    for rid, rule in RULES.items():
        assert rule.id == rid
        for field in ("title", "what", "why", "fix"):
            value = getattr(rule, field)
            assert value and len(value) > 20, (rid, field)


def test_every_severity_is_real():
    for rule in RULES.values():
        assert rule.default in Severity.ORDER


def test_ids_are_well_formed():
    for rid in RULES:
        assert rid.startswith("CKPT-")
        assert len(rid) == len("CKPT-000")
        assert rid[5:].isdigit()


def test_safe_formats_never_default_above_medium():
    # The recommendation this tool makes is "ship safetensors". A
    # header quirk in a safe format must not read as seriously as
    # os.system in a pickle.
    for rid in ("CKPT-017", "CKPT-019"):
        assert Severity.rank(RULES[rid].default) >= \
            Severity.rank(Severity.MEDIUM)


def test_default_severity_falls_back():
    assert default_severity("CKPT-001") == Severity.CRITICAL
    assert default_severity("CKPT-999") == Severity.MEDIUM


def test_unknown_ids():
    assert unknown_ids(["CKPT-001", "CKPT-404"]) == ["CKPT-404"]
