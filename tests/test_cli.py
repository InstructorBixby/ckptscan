from ckptscan.commands.main import main


def test_clean_file_exits_zero(fixtures):
    assert main([str(fixtures / "plain_dict.pkl")]) == 0


def test_unsafe_file_exits_one(fixtures, capsys):
    assert main([str(fixtures / "system_p4.pkl")]) == 1
    assert "CKPT-001" in capsys.readouterr().out


def test_the_implied_scan_subcommand(fixtures, capsys):
    # `ckptscan model.pt` meant this before subcommands existed.
    assert main([str(fixtures / "system_p4.pkl")]) == 1
    assert main(["scan", str(fixtures / "system_p4.pkl")]) == 1


def test_a_global_flag_before_the_path_still_works(fixtures):
    assert main(["--fail-on", "critical",
                 str(fixtures / "benign_p4.pkl")]) == 0


def test_a_directory_is_walked(fixtures, capsys):
    assert main([str(fixtures)]) == 1
    assert capsys.readouterr().out.count("CKPT-001") >= 3


def test_quiet_prints_no_findings(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl"), "--quiet"])
    assert capsys.readouterr().out == ""


def test_a_missing_path_is_exit_2(tmp_path):
    assert main([str(tmp_path / "nope.pt")]) == 2
