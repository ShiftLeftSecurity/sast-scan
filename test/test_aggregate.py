# -*- coding: utf-8 -*-
import json
import os
import tempfile
from pathlib import Path

import lib.aggregate as aggregate


def find_test_data():
    data_dir = Path(__file__).parent / "data"
    return [p.as_posix() for p in data_dir.glob("*.sarif")]


def test_aggregate():
    test_sarif_files = find_test_data()
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
