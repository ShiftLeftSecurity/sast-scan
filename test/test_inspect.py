import os
import tempfile

import pytest

import lib.inspect as inspect


@pytest.fixture
def test_sarif_files():
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    return [
        os.path.join(curr_dir, "data", "gosec-report.sarif"),
        os.path.join(curr_dir, "data", "staticcheck-report.sarif"),
    ]


def test_convert(test_sarif_files):
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        inspect.convert_sarif("demo-app", {}, test_sarif_files, fp.name)
        data = fp.read()
        assert data
