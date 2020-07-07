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

from rich import box
from rich.table import Table

import lib.aggregate as aggregate
import lib.config as config
from lib.logger import LOG, console


def find_tool_shortname(desc):
    """Find the short name for the tool given its description.
    SARIF file contains the description for the tool

    :param desc Description of the tool
    :param return short name
    """
    for key, value in config.tool_purpose_message.items():
        if value.lower() == desc.lower():
            return key
    return desc


def summary(sarif_files, aggregate_file=None, override_rules={}):
    """Generate overall scan summary based on the generated
    SARIF file

    :param sarif_files: List of generated sarif report files
    :param aggregate_file: Filename to store aggregate data
    :param override_rules Build break rules to override for testing
    :returns dict representing the summary
    """
    report_summary = {}
    build_status = "pass"
    # This is the list of all runs which will get stored as an aggregate
    run_data_list = []
    for sf in sarif_files:
        with open(sf, mode="r") as report_file:
            report_data = json.loads(report_file.read())
            # skip this file if the data is empty
            if not report_data or not report_data.get("runs"):
                LOG.warn("Report file {} is invalid. Skipping ...".format(sf))
                continue
            # Iterate through all the runs
            for run in report_data["runs"]:
                # Add it to the run data list for aggregation
                run_data_list.append(run)
                tool_desc = run["tool"]["driver"]["name"]
                tool_name = tool_desc
                # Initialise
                report_summary[tool_name] = {
                    "tool": tool_desc,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "status": "✅",
                }
                results = run.get("results", [])
                metrics = run.get("properties", {}).get("metrics", None)
                # If the result includes metrics use it. If not compute it
                if metrics:
                    report_summary[tool_name].update(metrics)
                    report_summary[tool_name].pop("total", None)
                else:
                    for aresult in results:
                        sev = aresult["properties"]["issue_severity"].lower()
                        report_summary[tool_name][sev] += 1
                # Compare against the build break rule to determine status
                default_rules = config.get("build_break_rules").get("default")
                tool_rules = config.get("build_break_rules").get(tool_name, {})
                build_break_rules = {**default_rules, **tool_rules, **override_rules}
                for rsev in ["critical", "high", "medium", "low"]:
                    if build_break_rules.get("max_" + rsev) is not None:
                        if (
                            report_summary.get(tool_name).get(rsev)
                            > build_break_rules["max_" + rsev]
                        ):
                            report_summary[tool_name]["status"] = "❌"
                            build_status = "fail"
    # Should we store the aggregate data
    if aggregate_file:
        # agg_sarif_file = aggregate_file.replace(".json", ".sarif")
        # aggregate.sarif_aggregate(run_data_list, agg_sarif_file)
        aggregate.jsonl_aggregate(run_data_list, aggregate_file)
        LOG.debug("Aggregate report written to {}\n".format(aggregate_file))
    return report_summary, build_status


def print_table(report_summary):
    """Print summary table
    """
    table = Table(
        title="SAST Scan Summary", box=box.DOUBLE_EDGE, header_style="bold magenta"
    )
    headers = None
    for k, v in report_summary.items():
        if not headers:
            headers = v.keys()
            for h in headers:
                justify = "left"
                if not h == "tool":
                    justify = "right"
                if h == "status":
                    justify = "center"
                table.add_column(header=h.capitalize(), justify=justify)
        rv = [str(val) for val in v.values()]
        table.add_row(*rv)
    console.print(table)
