import json

from ckptscan.commands.main import main


def doc(capsys):
    return json.loads(capsys.readouterr().out)


def test_json_is_valid_and_versioned(fixtures, capsys):
    assert main([str(fixtures / "system_p4.pkl"),
                 "--format", "json"]) == 1
    out = doc(capsys)
    assert out["schema_version"] == 1
    assert out["tool"] == "ckptscan"
    assert out["static_analysis_only"] is True


def test_json_carries_the_finding_detail(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl"), "--format", "json"])
    finding = doc(capsys)["findings"][0]
    assert finding["rule"] == "CKPT-001"
    assert finding["detail"]["module"] == "os"
    assert finding["detail"]["attr"] == "system"


def test_json_counts_by_severity(fixtures, capsys):
    main([str(fixtures), "--format", "json"])
    counts = doc(capsys)["counts"]
    assert counts["critical"] >= 3
    assert set(counts) == {"critical", "high", "medium", "low", "info"}


def test_json_lists_suppressions(fixtures, tmp_path, capsys,
                                 monkeypatch):
    (tmp_path / "ckptscan.toml").write_text(
        '[[suppress]]\nrule = "CKPT-001"\n'
        'justification = "a fixture directory full of deliberate '
        'payloads, which is the point of it"\n')
    monkeypatch.chdir(tmp_path)
    assert main([str(fixtures / "system_p4.pkl"),
                 "--format", "json"]) == 0
    out = doc(capsys)
    assert out["findings"] == []
    assert out["suppressed"][0]["rule"] == "CKPT-001"
    assert "fixture directory" in out["suppressed"][0]["justification"]


def test_output_to_a_file(fixtures, tmp_path):
    dest = tmp_path / "report.json"
    main([str(fixtures / "system_p4.pkl"), "--format", "json",
          "--output", str(dest)])
    assert json.loads(dest.read_text())["findings"]
    assert b"\r\n" not in dest.read_bytes()
