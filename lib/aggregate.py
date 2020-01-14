# -*- coding: utf-8 -*-
import json

import lib.config as config


def jsonl_aggregate(run_data_list, out_file_name):
    """Produce aggregated report in jsonl format

    :param run_data_list: List of run data after parsing the sarif files
    :param out_file_name: Output filename
    """
    with open(out_file_name, "w") as outfile:
        for data in run_data_list:
            json.dump(data, outfile)
            outfile.write("\n")
