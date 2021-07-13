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
import os

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


def get_depscan_data(drep_file):
    dataList = []
    for depline in drep_file:
        dataList.append(json.loads(depline))
    return dataList


def calculate_depscan_metrics(dep_data):
    required_pkgs_found = False
    metrics = {
        "total": 0,
        "critical": 0,
        "required_critical": 0,
        "optional_critical": 0,
        "critical": 0,
        "high": 0,
        "required_high": 0,
        "optional_high": 0,
        "medium": 0,
        "required_medium": 0,
        "optional_medium": 0,
        "low": 0,
        "required_low": 0,
        "optional_low": 0,
        "unspecified": 0,
        "required_unspecified": 0,
        "optional_unspecified": 0,
    }
    for finding in dep_data:
        severity = finding.get("severity", "UNKNOWN").lower()
        if finding.get("package_usage"):
            usage = finding.get("package_usage").lower()
            if usage in ("required", "optional"):
                metrics[f"{usage}_{severity}"] += 1
                if usage == "required":
                    required_pkgs_found = True
        # Ignore unknown severity for now
        if severity == "unknown":
            continue
        else:
            metrics[severity] += 1
            metrics["total"] += 1
    return metrics, required_pkgs_found


def summary(
    sarif_files,
    depscan_files=None,
    aggregate_file=None,
    override_rules={},
    baseline_file=None,
):
    """Generate overall scan summary based on the generated
    SARIF file

    :param sarif_files: List of generated sarif report files
    :param depscan_files: Depscan result files
    :param aggregate_file: Filename to store aggregate data
    :param override_rules Build break rules to override for testing
    :param baseline_file: Scan baseline file
    :returns dict representing the summary
    """
    report_summary = {}
    baseline_fingerprints = {
        "scanPrimaryLocationHash": [],
        "scanTagsHash": [],
    }
    build_status = "pass"
    # This is the list of all runs which will get stored as an aggregate
    run_data_list = []
    default_rules = config.get("build_break_rules").get("default")
    depscan_default_rules = config.get("build_break_rules").get("depscan")
    # Collect stats from depscan files if available
    if depscan_files:
        for df in depscan_files:
            # Skip analyzing risk audit files
            if "risk" in df:
                continue
            with open(df, mode="r") as drep_file:
                dep_data = get_depscan_data(drep_file)
                if not dep_data:
                    continue
                # depscan-java or depscan-nodejs based on filename
                dep_type = (
                    os.path.basename(df).replace(".json", "").replace("-report", "")
                )
                metrics, required_pkgs_found = calculate_depscan_metrics(dep_data)
                report_summary[dep_type] = {
                    "tool": f"""Dependency Scan ({dep_type.replace("depscan-", "")})""",
                    "critical": metrics["critical"],
                    "high": metrics["high"],
                    "medium": metrics["medium"],
                    "low": metrics["low"],
                    "status": ":white_heavy_check_mark:",
                }
                report_summary[dep_type].pop("total", None)
                # Compare against the build break rule to determine status
                dep_tool_rules = config.get("build_break_rules").get(dep_type, {})
                build_break_rules = {**depscan_default_rules, **dep_tool_rules}
                if override_rules and override_rules.get("depscan"):
                    build_break_rules = {
                        **build_break_rules,
                        **override_rules.get("depscan"),
                    }
                # Default severity categories for build status
                build_status_categories = (
                    "critical",
                    "required_critical",
                    "optional_critical",
                    "high",
                    "required_high",
                    "optional_high",
                    "medium",
                    "required_medium",
                    "optional_medium",
                    "low",
                    "required_low",
                    "optional_low",
                )
                # Issue 233 - Consider only required packages if available
                if required_pkgs_found:
                    build_status_categories = (
                        "required_critical",
                        "required_high",
                        "required_medium",
                        "required_low",
                    )
                for rsev in build_status_categories:
                    if build_break_rules.get("max_" + rsev) is not None:
                        if metrics.get(rsev) > build_break_rules["max_" + rsev]:
                            report_summary[dep_type]["status"] = ":cross_mark:"
                            build_status = "fail"

    for sf in sarif_files:
        with open(sf, mode="r") as report_file:
            report_data = json.load(report_file)
            existing_tool = False
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
                # Initialise if the referred tool is seen for the first time
                if not report_summary.get(tool_name):
                    report_summary[tool_name] = {
                        "tool": tool_desc,
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "status": ":white_heavy_check_mark:",
                    }
                else:
                    existing_tool = True
                results = run.get("results", [])
                metrics = run.get("properties", {}).get("metrics", None)
                # If the result includes metrics use it. If not compute it
                if metrics and not existing_tool:
                    report_summary[tool_name].update(metrics)
                    report_summary[tool_name].pop("total", None)
                for aresult in results:
                    if not metrics or existing_tool:
                        if aresult.get("properties"):
                            sev = aresult["properties"]["issue_severity"].lower()
                        else:
                            sev = config.get("exttool_default_severity").get(
                                tool_name.lower(), "medium"
                            )
                        report_summary[tool_name][sev] += 1
                    # Track the fingerprints
                    if aresult.get("partialFingerprints"):
                        result_fingerprints = aresult.get("partialFingerprints")
                        for rfk, rfv in result_fingerprints.items():
                            if not rfv:
                                continue
                            # We are only interested in a small subset of hashes namely scanPrimaryLocationHash, scanTagsHash
                            if rfk in ["scanPrimaryLocationHash", "scanTagsHash"]:
                                baseline_fingerprints.setdefault(rfk, []).append(rfv)
                # Compare against the build break rule to determine status
                tool_rules = config.get("build_break_rules").get(tool_name, {})
                build_break_rules = {**default_rules, **tool_rules, **override_rules}
                for rsev in ("critical", "high", "medium", "low"):
                    if build_break_rules.get("max_" + rsev) is not None:
                        if (
                            report_summary.get(tool_name).get(rsev)
                            > build_break_rules["max_" + rsev]
                        ):
                            report_summary[tool_name]["status"] = ":cross_mark:"
                            build_status = "fail"

    # Should we store the aggregate data
    if aggregate_file:
        # agg_sarif_file = aggregate_file.replace(".json", ".sarif")
        # aggregate.sarif_aggregate(run_data_list, agg_sarif_file)
        aggregate.jsonl_aggregate(run_data_list, aggregate_file)
        LOG.debug("Aggregate report written to {}\n".format(aggregate_file))
    if baseline_file:
        aggregate.store_baseline(baseline_fingerprints, baseline_file)
        LOG.info("Baseline file written to {}".format(baseline_file))
    return report_summary, build_status


def print_table(report_summary):
    """Print summary table"""
    table = Table(
        title="Security Scan Summary", box=box.DOUBLE_EDGE, header_style="bold magenta"
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
