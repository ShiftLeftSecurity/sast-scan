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

import csv


def get_report_data(csvfile):
    """Convert csv file to dict

    :param csvfile: CSV file to parse
    """
    raw_data = csv.reader(csvfile, delimiter=",")
    report_data = []
    headers = None
    for row in raw_data:
        if not headers:
            headers = [r.lower().replace(" ", "_") for r in row]
        else:
            report_data.append(dict(zip(headers, row)))
    return headers, report_data
