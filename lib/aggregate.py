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
