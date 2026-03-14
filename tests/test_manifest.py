import hashlib
import json

import pytest

from ckptscan import manifest
from ckptscan.commands.main import main


def sha(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def published(tmp_path):
    (tmp_path / "model.safetensors").write_bytes(b"weights")
    (tmp_path / "config.json").write_bytes(b"{}")
    sums = (f"{sha(b'weights')}  model.safetensors\n"
            f"{sha(b'{}')}  config.json\n")
    (tmp_path / "SHA256SUMS").write_text(sums)
    return tmp_path


def test_parses_sha256sum_output(published):
    entries = manifest.read(published / "SHA256SUMS")
    assert [e.path for e in entries] == ["model.safetensors",
                                         "config.json"]
    assert entries[0].algorithm == "sha256"


def test_parses_binary_mode_stars(tmp_path):
    p = tmp_path / "sums"
    p.write_text(f"{sha(b'x')} *model.bin\n")
    assert manifest.read(p)[0].path == "model.bin"


def test_parses_a_json_map(tmp_path):
    p = tmp_path / "sums.json"
    p.write_text(json.dumps({"model.bin": sha(b"x")}))
    assert manifest.read(p)[0].path == "model.bin"


def test_parses_a_json_map_under_files(tmp_path):
    p = tmp_path / "sums.json"
    p.write_text(json.dumps(
        {"files": {"model.bin": {"sha256": sha(b"x")}}}))
    assert manifest.read(p)[0].digest == sha(b"x")


def test_parses_a_json_array(tmp_path):
    p = tmp_path / "sums.json"
    p.write_text(json.dumps(
        [{"path": "model.bin", "sha256": "sha256:" + sha(b"x")}]))
    assert manifest.read(p)[0].digest == sha(b"x")


def test_other_algorithms_by_length(tmp_path):
    p = tmp_path / "sums"
    p.write_text(f"{hashlib.md5(b'x').hexdigest()}  a\n")
    assert manifest.read(p)[0].algorithm == "md5"


def test_a_nonsense_length_is_an_error(tmp_path):
    p = tmp_path / "sums"
    p.write_text("abc123  a\n")
    with pytest.raises(manifest.ManifestError):
        manifest.read(p)


def test_an_empty_manifest_is_an_error(tmp_path):
    p = tmp_path / "sums"
    p.write_text("# nothing\n")
    with pytest.raises(manifest.ManifestError):
        manifest.read(p)


def test_digest_is_streamed(tmp_path, monkeypatch):
    p = tmp_path / "big"
    p.write_bytes(b"a" * (3 * manifest.CHUNK + 7))
    reads = []
    real_open = open

    def counting_open(path, mode="r", *a, **k):
        fh = real_open(path, mode, *a, **k)
        if "b" in mode:
            original = fh.read

            def read(n=-1):
                reads.append(n)
                return original(n)
            fh.read = read
        return fh

    monkeypatch.setattr("builtins.open", counting_open)
    manifest.digest_file(p)
    assert len(reads) >= 4
    assert all(n == manifest.CHUNK for n in reads)


# --- the verify command --------------------------------------------

def test_a_matching_directory_is_clean(published):
    assert main(["verify", str(published),
                 "--manifest", str(published / "SHA256SUMS")]) == 0


def test_a_changed_file(published, capsys):
    (published / "model.safetensors").write_bytes(b"tampered")
    assert main(["verify", str(published),
                 "--manifest", str(published / "SHA256SUMS")]) == 1
    out = capsys.readouterr().out
    assert "CKPT-009" in out
    assert "not the file that was published" in out


def test_a_missing_file(published, capsys):
    (published / "config.json").unlink()
    assert main(["verify", str(published),
                 "--manifest", str(published / "SHA256SUMS")]) == 1
    assert "missing" in capsys.readouterr().out


def test_an_extra_file_is_reported(published, capsys):
    (published / "extra.pt").write_bytes(b"surprise")
    assert main(["verify", str(published),
                 "--manifest", str(published / "SHA256SUMS")]) == 1
    assert "not in the manifest" in capsys.readouterr().out


def test_allow_extra_silences_only_that(published, capsys):
    (published / "extra.pt").write_bytes(b"surprise")
    assert main(["verify", str(published), "--allow-extra",
                 "--manifest", str(published / "SHA256SUMS")]) == 0


def test_a_dotfile_is_not_an_extra_file(published):
    (published / ".cache").mkdir()
    (published / ".cache" / "x").write_bytes(b"junk")
    assert main(["verify", str(published),
                 "--manifest", str(published / "SHA256SUMS")]) == 0


def test_a_manifest_entry_that_escapes_is_refused(published, capsys):
    (published / "evil").write_text(f"{sha(b'x')}  ../outside.bin\n")
    assert main(["verify", str(published), "--allow-extra",
                 "--manifest", str(published / "evil")]) == 1
    assert "outside the directory" in capsys.readouterr().out


def test_a_missing_manifest_is_exit_2(published, capsys):
    assert main(["verify", str(published),
                 "--manifest", str(published / "nope")]) == 2
