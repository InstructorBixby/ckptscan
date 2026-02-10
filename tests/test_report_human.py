from ckptscan.commands.main import main
from ckptscan.report import human


def test_no_colour_when_not_a_tty(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl")])
    assert "\x1b[" not in capsys.readouterr().out


def test_no_color_env_wins(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("CKPTSCAN_COLOR", "always")
    assert human.use_colour() is False


def test_explain_prints_the_fix(fixtures, capsys):
    main([str(fixtures / "system_p4.pkl"), "--explain"])
    assert "fix:" in capsys.readouterr().out


def test_the_taxonomy_line_appears_when_there_is_one(fixtures, capsys):
    import pickle
    import socket

    class Egress:
        def __reduce__(self):
            return (socket.create_connection,
                    (("example.invalid", 80),))

    p = fixtures / "egress.pkl"
    p.write_bytes(pickle.dumps(Egress(), protocol=4))
    main([str(p)])
    assert "EX-004" in capsys.readouterr().out


def test_the_clean_summary_does_not_say_safe(fixtures, capsys):
    main([str(fixtures / "plain_dict.pkl")])
    err = capsys.readouterr().err
    assert "not the same as safe" in err


def test_findings_are_sorted_worst_first(fixtures, capsys):
    main([str(fixtures)])
    lines = [ln for ln in capsys.readouterr().out.splitlines()
             if ln[:1].isupper()]
    severities = [ln.split()[0] for ln in lines]
    assert severities == sorted(
        severities,
        key=lambda s: ["CRITICAL", "HIGH", "MEDIUM", "LOW",
                       "INFO"].index(s))
