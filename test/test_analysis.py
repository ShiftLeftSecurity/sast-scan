# -*- coding: utf-8 -*-
import os

import lib.analysis as analysis
import lib.utils as utils


def test_summary():
    test_reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    test_sarif_files = utils.find_files(test_reports_dir, ".sarif")
    report_summary, build_status = analysis.summary(test_sarif_files)
    assert len(report_summary.keys()) == 4
    for k, v in report_summary.items():
        if k == "findsecbugs":
            assert v["status"] == "❌"
        else:
            assert v["status"] == "✅"
    assert build_status == "fail"


def test_summary_strict():
    test_reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    test_sarif_files = utils.find_files(test_reports_dir, ".sarif")
    report_summary, build_status = analysis.summary(
        test_sarif_files,
        {"max_critical": 0, "max_high": 0, "max_medium": 0, "max_low": 0},
    )
    assert len(report_summary.keys()) == 4
    for k, v in report_summary.items():
        assert v["status"] == "❌"
    assert build_status == "fail"
