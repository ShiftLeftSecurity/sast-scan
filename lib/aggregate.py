# -*- coding: utf-8 -*-

# This file is part of Scan.

# Scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Scan.  If not, see <https://www.gnu.org/licenses/>.

import json
import uuid
from datetime import datetime

import sarif_om as om
from jschema_to_python.to_json import to_json

import lib.config as config


def jsonl_aggregate(run_data_list, out_file_name):
    """Produce aggregated report in jsonl format

    :param run_data_list: List of run data after parsing the sarif files
    :param out_file_name: Output filename
    """
    if not run_data_list or not out_file_name:
        return
    with open(out_file_name, "w") as outfile:
        for data in run_data_list:
            json.dump(data, outfile)
            outfile.write("\n")


def sarif_aggregate(run_data_list, out_sarif_name):
    """Produce aggregated sarif data (Unused)

    :param run_data_list:
    :param out_sarif_name:
    :return:
    """
    log_uuid = str(uuid.uuid4())
    run_uuid = config.get("run_uuid")
    log = om.SarifLog(
        schema_uri="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version="2.1.0",
        inline_external_properties=[
            om.ExternalProperties(guid=log_uuid, run_guid=run_uuid)
        ],
        runs=run_data_list,
    )
    serialized_log = to_json(log)
    with open(out_sarif_name, "w") as outfile:
        outfile.write(serialized_log)


def store_baseline(baseline_fingerprints, baseline_file):
    """Produce baseline file

    :param baseline_fingerprints: Fingerprints to store
    :param baseline_file: Baseline filename
    """
    with open(baseline_file, "w") as outfile:
        json.dump(
            {
                "baseline_fingerprints": baseline_fingerprints,
                "created_at": str(datetime.now()),
            },
            outfile,
            indent=2,
        )
