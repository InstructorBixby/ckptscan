"""The regression test that matters most.

A detector that stops detecting is the failure mode nobody notices,
because the output goes quiet and quiet looks like success. So every
`unsafe/` sample asserts its rules and every `clean/` sample asserts
silence, in the same run -- a change that fixes a false positive by
breaking a detection fails here.
"""
import json

import pytest

from ckptscan import corpus
from ckptscan.findings import Severity
from ckptscan.scanner import scan_file

UNSAFE = [s for s in corpus.SAMPLES if s.expect]
CLEAN = [s for s in corpus.SAMPLES if s.expect_clean]


@pytest.mark.parametrize("sample", UNSAFE, ids=lambda s: s.name)
def test_every_unsafe_sample_is_detected(sample, samples):
    findings = scan_file(samples / sample.name)
    rules = {f.rule for f in findings}
    missing = set(sample.expect) - rules
    assert not missing, (f"{sample.name}: no longer reports "
                         f"{sorted(missing)}; got {sorted(rules)}")


@pytest.mark.parametrize("sample", UNSAFE, ids=lambda s: s.name)
def test_the_worst_severity_is_what_the_manifest_claims(sample,
                                                        samples):
    findings = scan_file(samples / sample.name)
    worst = min((f.severity for f in findings), key=Severity.rank)
    assert worst == sample.severity, sample.name


@pytest.mark.parametrize("sample", CLEAN, ids=lambda s: s.name)
def test_every_clean_sample_stays_clean(sample, samples):
    findings = scan_file(samples / sample.name)
    assert findings == [], (f"{sample.name}: false positive(s) "
                            f"{[f.rule for f in findings]}")


def test_the_manifest_matches_the_samples(samples):
    doc = json.loads((samples / "MANIFEST.json").read_text())
    assert {row["name"] for row in doc} == {s.name
                                            for s in corpus.SAMPLES}


def test_every_sample_has_a_description():
    for s in corpus.SAMPLES:
        assert len(s.description) > 30, s.name


def test_a_sample_is_either_clean_or_expected_to_fire():
    for s in corpus.SAMPLES:
        assert bool(s.expect) != bool(s.expect_clean), s.name


def test_the_corpus_readme_says_not_to_load_them(samples):
    text = (samples / "README.md").read_text()
    assert "do not load these" in text.lower()
    assert "inert" in text


def test_no_payload_touches_the_network():
    """The inertness rule, enforced on the generator's own source."""
    import inspect
    src = inspect.getsource(corpus)
    for forbidden in ("socket", "urllib", "requests", "http.client",
                      "shutil.rmtree", "os.remove", "os.unlink"):
        assert forbidden not in src, forbidden


def test_the_marker_is_under_tmp():
    assert corpus.MARKER
    for s in corpus.SAMPLES:
        data = s.builder()
        assert b"/etc/" not in data
        assert b"rm -rf" not in data
