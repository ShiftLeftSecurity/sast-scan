# -*- coding: utf-8 -*-
import os
import tempfile
from pathlib import Path

import lib.analysis as analysis


def find_test_data():
    data_dir = Path(__file__).parent / "data"
    return [p.as_posix() for p in data_dir.glob("*.sarif")]


def test_summary():
    test_sarif_files = find_test_data()
    report_summary, build_status = analysis.summary(test_sarif_files)
    assert len(report_summary.keys()) == 7
    for k, v in report_summary.items():
        if k == "findsecbugs":
            assert v["status"] == "❌"
        elif k == "nodejsscan":
            assert v["status"] == "✅"
    assert build_status == "fail"


def test_summary_with_agg():
    test_sarif_files = find_test_data()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as afile:
        report_summary, build_status = analysis.summary(test_sarif_files, afile.name)
        assert len(report_summary.keys()) == 7
        afile.close()
        with open(afile.name, "r") as outfile:
            data = outfile.read()
            assert data
        os.unlink(afile.name)


def test_summary_strict():
    test_sarif_files = find_test_data()
    report_summary, build_status = analysis.summary(
        test_sarif_files,
        None,
        {"max_critical": 0, "max_high": 0, "max_medium": 0, "max_low": 0},
    )
    assert len(report_summary.keys()) == 7
    for k, v in report_summary.items():
        assert v["status"] == "❌"
    assert build_status == "fail"
