from ckptscan.scanner import scan_file


def rules(path):
    return sorted({f.rule for f in scan_file(path)})


def test_a_clean_zip_checkpoint_is_clean(fixtures):
    assert rules(fixtures / "zip_clean.pt") == []


def test_a_payload_inside_a_zip_checkpoint_is_found(fixtures):
    findings = scan_file(fixtures / "zip_unsafe.pt")
    assert [f.rule for f in findings] == ["CKPT-001"]
    assert findings[0].location == "archive/data.pkl"
    assert "os.system" in findings[0].message


def test_a_nested_archive_is_descended_into(fixtures):
    found = rules(fixtures / "zip_nested.pt")
    assert "CKPT-010" in found
    assert "CKPT-001" in found


def test_the_nested_finding_names_the_full_path(fixtures):
    findings = scan_file(fixtures / "zip_nested.pt")
    inner = [f for f in findings if f.rule == "CKPT-001"]
    assert inner
    assert inner[0].location.startswith("extra/inner.zip!")


def test_a_traversing_member_name_is_reported(fixtures):
    assert "CKPT-012" in rules(fixtures / "zip_traversal.pt")
