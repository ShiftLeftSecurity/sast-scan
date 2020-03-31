import os

import lib.xml_parser as xml_parser


def test_findsec_parse():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "findsecbugs-report.xml",
        )
    ) as rf:
        issues, metrics = xml_parser.get_report_data(rf)
        assert len(issues) == 85
        assert len(metrics.keys()) == 1
        assert issues[0]["issue_severity"] == "HIGH"
        assert issues[0]["test_id"] == "CWE-78"
