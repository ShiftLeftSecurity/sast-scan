import os

import lib.config as config


def test_scan_tools_map():
    test_src = "/app"
    test_reports_dir = "/app/reports"
    test_report_fname_prefix = "/app/reports/tool-report"

    for k, v in config.scan_tools_args_map.items():
        if isinstance(v, list):
            default_cmd = " ".join(v) % dict(
                src=test_src,
                src_or_file=test_src,
                reports_dir=test_reports_dir,
                report_fname_prefix=test_report_fname_prefix,
                type=k,
            )
            assert k
            assert "%(src)s" not in default_cmd
        elif isinstance(v, dict):
            for cmd_key, cmd_val in v.items():
                assert cmd_key
                default_cmd = " ".join(cmd_val) % dict(
                    src=test_src,
                    src_or_file=test_src,
                    reports_dir=test_reports_dir,
                    report_fname_prefix=test_report_fname_prefix,
                    type=k,
                )
                assert "%(src)s" not in default_cmd


def test_override():
    build_break_rules = config.get("build_break_rules").copy()
    golang_cmd = config.get("scan_tools_args_map").get("go")
    assert list(golang_cmd.keys()) == ["source-go", "staticcheck"]
    test_data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    config.set("SAST_SCAN_SRC_DIR", test_data_dir)
    config.reload()
    # Test if we are able to override the whole dict
    new_rules = config.get("build_break_rules")
    assert build_break_rules != new_rules
    # Test if we are able to override a command
    golang_cmd = config.get("scan_tools_args_map").get("go")
    assert golang_cmd[0] == "echo"
    assert config.get("scan_type") == "credscan,java"


def test_baseline():
    test_data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    config.set("SAST_SCAN_SRC_DIR", test_data_dir)
    config.reload()
    fps = config.get_suppress_fingerprints("")
    assert fps == {
        "scanPrimaryLocationHash": ["foo"],
        "scanTagsHash": ["bar"],
        "scanFileHash": [],
    }
