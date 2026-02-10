import json

from ckptscan.commands.main import main
from ckptscan.registry import RULES


def doc(capsys):
    return json.loads(capsys.readouterr().out)


def test_sarif_shape(fixtures, capsys):
    assert main([str(fixtures / "system_p4.pkl"),
                 "--format", "sarif"]) == 1
    out = doc(capsys)
    assert out["version"] == "2.1.0"
    assert out["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(out["runs"]) == 1


def test_every_rule_is_declared(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl"), "--format", "sarif"])
    rules = doc(capsys)["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == set(RULES)


def test_rules_carry_help_text(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl"), "--format", "sarif"])
    rules = doc(capsys)["runs"][0]["tool"]["driver"]["rules"]
    one = next(r for r in rules if r["id"] == "CKPT-001")
    assert "Remediation" in one["help"]["text"]
    assert one["defaultConfiguration"]["level"] == "error"


def test_a_result_has_a_location_and_a_level(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl"), "--format", "sarif"])
    result = doc(capsys)["runs"][0]["results"][0]
    assert result["ruleId"] == "CKPT-001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"].endswith("system_p4.pkl")


def test_an_internal_location_is_logical_not_a_fake_line(fixtures,
                                                         capsys):
    """SARIF has no vocabulary for "inside this zip member", and a
    fabricated line number in a binary is worse than none."""
    main([str(fixtures / "zip_unsafe.pt"), "--format", "sarif"])
    result = doc(capsys)["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert "region" not in physical
    logical = result["locations"][0]["logicalLocations"][0]
    assert logical["name"] == "archive/data.pkl"
    assert result["message"]["text"].startswith("archive/data.pkl:")


def test_severity_survives_the_four_level_mapping(fixtures, capsys):
    main([str(fixtures), "--format", "sarif"])
    results = doc(capsys)["runs"][0]["results"]
    severities = {r["properties"]["severity"] for r in results}
    assert "critical" in severities
    for r in results:
        assert r["rank"] > 0
