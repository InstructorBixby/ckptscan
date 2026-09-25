import json

from ckptscan.commands.main import main
from ckptscan.report import sarif


def results(capsys):
    return json.loads(capsys.readouterr().out)["runs"][0]["results"]


def test_every_result_has_a_fingerprint(samples, capsys):
    main([str(samples / "unsafe"), "--format", "sarif"])
    for r in results(capsys):
        assert r["partialFingerprints"]["ckptscanFinding/v1"]


def test_fingerprints_are_unique_within_a_file(samples, capsys):
    main([str(samples / "unsafe" / "object_array.npy"),
          "--format", "sarif"])
    rows = results(capsys)
    assert len(rows) >= 2
    prints = {r["partialFingerprints"]["ckptscanFinding/v1"]
              for r in rows}
    assert len(prints) == len(rows)


def test_a_fingerprint_is_stable_across_runs(samples, capsys):
    main([str(samples / "unsafe"), "--format", "sarif"])
    first = [r["partialFingerprints"] for r in results(capsys)]
    main([str(samples / "unsafe"), "--format", "sarif"])
    assert [r["partialFingerprints"] for r in results(capsys)] == first


def test_a_reworded_message_does_not_change_the_fingerprint():
    from ckptscan.findings import Finding
    a = Finding(rule="CKPT-001", severity="critical", path="m.pt",
                location="archive/data.pkl", message="one wording")
    b = Finding(rule="CKPT-001", severity="critical", path="m.pt",
                location="archive/data.pkl", message="another")
    assert sarif._fingerprint(a) == sarif._fingerprint(b)


def test_a_different_member_does_change_it():
    from ckptscan.findings import Finding
    a = Finding(rule="CKPT-001", severity="critical", path="m.pt",
                location="archive/data.pkl", message="x")
    b = Finding(rule="CKPT-001", severity="critical", path="m.pt",
                location="extra/inner.zip!archive/data.pkl",
                message="x")
    assert sarif._fingerprint(a) != sarif._fingerprint(b)
