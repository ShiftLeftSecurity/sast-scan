# -*- coding: utf-8 -*-
import json
import os
import tempfile

import lib.aggregate as aggregate
import lib.utils as utils


def test_aggregate():
    test_reports_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")
    test_sarif_files = utils.find_files(test_reports_dir, ".sarif")
    run_data_list = []
    for sf in test_sarif_files:
        with open(sf, mode="r") as report_file:
            report_data = json.loads(report_file.read())
            run_data_list += report_data["runs"]

    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as afile:
        aggregate.jsonl_aggregate(run_data_list, afile.name)
        afile.close()
        with open(afile.name, "r") as outfile:
            data = outfile.read()
            assert data
        os.unlink(afile.name)
