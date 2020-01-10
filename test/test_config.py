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
