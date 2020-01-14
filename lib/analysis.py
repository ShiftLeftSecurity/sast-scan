# -*- coding: utf-8 -*-
import io
import json
import logging

from tabulate import tabulate

import lib.aggregate as aggregate
import lib.config as config


LOG = logging.getLogger(__name__)


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
                tool_name = find_tool_shortname(tool_desc)
                # Initialise
                report_summary[tool_name] = {
                    "tool": tool_name,
                    "description": tool_desc,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "status": "✅",
                }
                results = run.get("results", [])
                for aresult in results:
                    sev = aresult["properties"]["issue_severity"].lower()
                    report_summary[tool_name][sev] += 1
                # Compare against the build break rule to determine status
                default_rules = config.get("build_break_rules").get("default")
                tool_rules = config.get("build_break_rules").get(tool_name, {})
                build_break_rules = {**default_rules, **tool_rules, **override_rules}
                for rsev in ["critical", "high", "medium", "low"]:
                    if build_break_rules.get("max_" + rsev) != None:
                        if (report_summary[tool_name][rsev]) > build_break_rules[
                            "max_" + rsev
                        ]:
                            report_summary[tool_name]["status"] = "❌"
                            build_status = "fail"
    # Should we store the aggregate data
    if aggregate_file:
        aggregate.jsonl_aggregate(run_data_list, aggregate_file)
        LOG.info("\nAggregate report written to {}".format(aggregate_file))
    return report_summary, build_status


def print_summary(report_summary):
    """Pretty print report summary
    """
    table = []
    headers = None
    for k, v in report_summary.items():
        if not headers:
            headers = v.keys()
        table.append(v.values())
    print("\n", flush=True)
    print(tabulate(table, headers, tablefmt="simple"), flush=True)
