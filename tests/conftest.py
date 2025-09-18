import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import mkfixtures  # noqa: E402
import mkkeras  # noqa: E402


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    out = tmp_path_factory.mktemp("fixtures")
    mkfixtures.build(out)
    mkkeras.build(out)
    return out
