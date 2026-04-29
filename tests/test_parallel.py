from ckptscan.commands.main import main
from ckptscan.commands.scan import default_jobs


def test_results_are_identical_serial_and_parallel(samples, capsys):
    main([str(samples), "--jobs", "1", "--format", "json"])
    serial = capsys.readouterr().out
    main([str(samples), "--jobs", "4", "--format", "json"])
    parallel = capsys.readouterr().out
    assert serial == parallel


def test_findings_are_deterministically_ordered(samples, capsys):
    main([str(samples), "--jobs", "4"])
    first = capsys.readouterr().out
    main([str(samples), "--jobs", "4"])
    assert capsys.readouterr().out == first


def test_default_jobs_is_sane():
    assert 1 <= default_jobs() <= 8


def test_a_missing_path_is_still_exit_2(tmp_path):
    assert main([str(tmp_path / "nope.pt"), "--jobs", "4"]) == 2
