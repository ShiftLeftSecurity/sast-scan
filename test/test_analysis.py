# -*- coding: utf-8 -*-
import os
import tempfile
from pathlib import Path

import lib.analysis as analysis


def find_test_data():
    data_dir = Path(__file__).parent / "data"
    return [p.as_posix() for p in data_dir.glob("*.sarif")]


def find_test_depscan_data():
    data_dir = Path(__file__).parent / "data"
    return [p.as_posix() for p in data_dir.glob("depscan-report-java.json")]


def find_test_depscan_nodejs_data():
    data_dir = Path(__file__).parent / "data"
    return [p.as_posix() for p in data_dir.glob("depscan-report-nodejs.json")]


def test_summary():
    test_sarif_files = find_test_data()
    report_summary, build_status = analysis.summary(
        test_sarif_files, depscan_files=None
    )
    assert len(report_summary.keys()) == 7
    for k, v in report_summary.items():
        if k == "findsecbugs":
            assert v["status"] == ":cross_mark:"
        elif k == "nodejsscan":
            assert v["status"] == ":white_heavy_check_mark:"
    assert build_status == "fail"


def test_calculate_depscan_metrics():
    test_depscan_files = find_test_depscan_data()
    with open(test_depscan_files[0]) as fp:
        dep_data = analysis.get_depscan_data(fp)
        metrics, required_pkgs_found = analysis.calculate_depscan_metrics(dep_data)
        assert metrics
        assert metrics["critical"] == 29
        assert metrics["optional_critical"] == 26
        assert required_pkgs_found


def test_summary_with_depscan():
    test_sarif_files = find_test_data()
    test_depscan_files = find_test_depscan_data()
    report_summary, build_status = analysis.summary(
        test_sarif_files, depscan_files=test_depscan_files
    )
    assert len(report_summary.keys()) == 8
    for k, v in report_summary.items():
        if k == "depscan-java":
            assert v == {
                "status": ":cross_mark:",
                "tool": "Dependency Scan (java)",
                "critical": 29,
                "high": 25,
                "medium": 5,
                "low": 0,
            }
        if k in ("findsecbugs", "depscan-java"):
            assert v["status"] == ":cross_mark:"
        elif k == "nodejsscan":
            assert v["status"] == ":white_heavy_check_mark:"
    assert build_status == "fail"


def test_summary_with_depscan_usage():
    test_sarif_files = []
    test_depscan_files = find_test_depscan_nodejs_data()
    report_summary, build_status = analysis.summary(
        test_sarif_files, depscan_files=test_depscan_files
    )
    assert len(report_summary.keys()) == 1
    for k, v in report_summary.items():
        if k == "depscan-nodejs":
            assert v == {
                "status": ":white_heavy_check_mark:",
                "tool": "Dependency Scan (nodejs)",
                "critical": 1,
                "high": 20,
                "medium": 9,
                "low": 3,
            }
    assert build_status == "pass"


def test_summary_with_agg():
    test_sarif_files = find_test_data()
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as afile:
        report_summary, build_status = analysis.summary(
            test_sarif_files, depscan_files=None, aggregate_file=afile.name
        )
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
        depscan_files=None,
        aggregate_file=None,
        override_rules={
            "max_critical": 0,
            "max_high": 0,
            "max_medium": 0,
            "max_low": 0,
        },
    )
    assert len(report_summary.keys()) == 7
    for k, v in report_summary.items():
        assert v["status"] == ":cross_mark:"
    assert build_status == "fail"


def test_summary_depscan_strict():
    test_sarif_files = []
    test_depscan_files = find_test_depscan_data()
    report_summary, build_status = analysis.summary(
        test_sarif_files,
        depscan_files=test_depscan_files,
        aggregate_file=None,
        override_rules={
            "depscan": {
                "max_critical": 0,
                "max_required_critical": 0,
                "max_high": 0,
                "max_required_high": 0,
                "max_medium": 0,
                "max_required_medium": 0,
                "max_low": 0,
                "max_required_low": 0,
            }
        },
    )
    assert len(report_summary.keys()) == 1
    for k, v in report_summary.items():
        assert v["critical"] == 29
        assert v["status"] == ":cross_mark:"
    assert build_status == "fail"


def test_summary_depscan_relaxed():
    test_sarif_files = []
    test_depscan_files = find_test_depscan_data()
    report_summary, build_status = analysis.summary(
        test_sarif_files,
        depscan_files=test_depscan_files,
        aggregate_file=None,
        override_rules={
            "depscan": {
                "max_critical": 30,
                "max_required_critical": 30,
                "max_high": 30,
                "max_required_high": 30,
                "max_medium": 30,
                "max_required_medium": 30,
                "max_low": 30,
                "max_required_low": 30,
            }
        },
    )
    assert len(report_summary.keys()) == 1
    for k, v in report_summary.items():
        assert v["critical"] == 29
        assert v["status"] == ":white_heavy_check_mark:"
    assert build_status == "pass"
