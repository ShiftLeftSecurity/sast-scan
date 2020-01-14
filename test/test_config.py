import importlib
import os

import lib.config as config


def test_scan_tools_map():
    test_src = "/app"
    test_reports_dir = "/app/reports"
    test_report_fname_prefix = "/app/reports/tool-report"

    for k, v in config.scan_tools_args_map.items():
        default_cmd = " ".join(v) % dict(
            src=test_src,
            reports_dir=test_reports_dir,
            report_fname_prefix=test_report_fname_prefix,
            type=k,
        )
        assert k
        assert "%(src)s" not in default_cmd


def test_override():
    build_break_rules = config.get("build_break_rules")
    golang_cmd = config.get("scan_tools_args_map").get("golang")
    assert golang_cmd[0] == "gosec"
    test_data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    os.environ["SAST_SCAN_SRC_DIR"] = test_data_dir
    importlib.reload(config)
    # Test if we are able to override the whole dict
    new_rules = config.get("build_break_rules")
    assert build_break_rules != new_rules
    # Test if we are able to override a command
    golang_cmd = config.get("scan_tools_args_map").get("golang")
    assert golang_cmd[0] == "echo"
    assert config.get("scan_type") == "credscan,java"
    del os.environ["SAST_SCAN_SRC_DIR"]
