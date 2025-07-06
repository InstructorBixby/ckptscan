from ckptscan.commands.main import main


def test_clean_file_exits_zero(fixtures, capsys):
    assert main([str(fixtures / "plain_dict.pkl")]) == 0


def test_unsafe_file_exits_one(fixtures, capsys):
    assert main([str(fixtures / "system_p4.pkl")]) == 1
    assert "CKPT-001" in capsys.readouterr().out


def test_a_directory_is_walked(fixtures, capsys):
    assert main([str(fixtures)]) == 1
    out = capsys.readouterr().out
    assert out.count("CKPT-001") >= 3


def test_fail_on_raises_the_bar(fixtures, capsys):
    # CKPT-002 is medium, so --fail-on critical lets it pass.
    assert main([str(fixtures / "benign_p4.pkl"),
                 "--fail-on", "critical"]) == 0


def test_quiet_prints_no_findings(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl"), "--quiet"])
    assert capsys.readouterr().out == ""


def test_a_missing_path_is_exit_2(tmp_path, capsys):
    assert main([str(tmp_path / "nope.pt")]) == 2
