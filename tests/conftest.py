import pytest

from ckptscan import corpus


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    """The generated corpus. Built once per test session."""
    out = tmp_path_factory.mktemp("corpus")
    corpus.build(out)
    return out


@pytest.fixture(scope="session")
def fixtures(samples):
    """Backwards-compatible alias while the older tests move over."""
    return samples
