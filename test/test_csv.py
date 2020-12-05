import os

import lib.csv_parser as csv_parser


def test_pmd_parse():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "data",
            "pmd-report.csv",
        )
    ) as rf:
        headers, report_data = csv_parser.get_report_data(rf)
        assert len(headers) == 8
        assert len(report_data) == 2
