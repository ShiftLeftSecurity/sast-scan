import datetime
import io
import json
import logging
import os
import pathlib
import re
import sys
import urllib.parse as urlparse

from lib.issue import issue_from_dict
import lib.csv_parser as csv_parser
import lib.xml_parser as xml_parser

import sarif_om as om
from jschema_to_python.to_json import to_json

LOG = logging.getLogger(__name__)

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

WORKSPACE_PREFIX = None
if "WORKSPACE" in os.environ:
    WORKSPACE_PREFIX = os.environ["WORKSPACE"]


def extract_from_file(tool_name, report_file, file_path_list=None):
    """Extract properties from reports

    :param tool_name: tool name
    :param report_file: Report file
    :param file_path_list: Full file path for any manipulation

    :return issues, metrics, skips information
    """
    issues = []
    metrics = {}
    skips = []
    extn = pathlib.PurePosixPath(report_file).suffix

    with io.open(report_file, "r") as rfile:
        if extn == ".json":
            report_data = json.loads(rfile.read())
            if isinstance(report_data, list):
                issues = report_data
                metrics = {"total": len(issues)}
            else:
                # NodeJsScan uses sec_issues
                if "sec_issues" in report_data:
                    sec_data = report_data["sec_issues"]
                    for key, value in sec_data.items():
                        if isinstance(value, list):
                            issues = issues + value
                        else:
                            issues.append(value)
                if "Issues" in report_data or "results" in report_data:
                    for issue in report_data.get(
                        "Issues", report_data.get("results", [])
                    ):
                        issues.append(issue)
                if "total_count" in report_data:
                    metrics["total_count"] = report_data["total_count"]
                if "vuln_count" in report_data:
                    metrics["vuln_count"] = report_data["vuln_count"]
                if "Stats" in report_data:
                    metrics = report_data["Stats"]
        if extn == ".csv":
            headers, issues = csv_parser.get_report_data(rfile)
            metrics = {"total": len(issues)}
        if extn == ".xml":
            issues, metrics = xml_parser.get_report_data(rfile, file_path_list)

    return issues, metrics, skips


def convert_file(
    tool_name, tool_args, working_dir, report_file, converted_file, file_path_list=None,
):
    """Convert report file

    :param tool_name: tool name
    :param tool_args: tool args
    :param working_dir: Working directory
    :param report_file: Report file
    :param converted_file: Converted file
    :param file_path_list: Full file path for any manipulation

    :return serialized_log: SARIF output data
    """
    issues, metrics, skips = extract_from_file(tool_name, report_file, file_path_list)
    return report(
        tool_name,
        tool_args,
        working_dir,
        metrics,
        skips,
        issues,
        converted_file,
        file_path_list,
    )


def report(
    tool_name,
    tool_args,
    working_dir,
    metrics,
    skips,
    issues,
    crep_fname,
    file_path_list=None,
):
    """Prints issues in SARIF format

    :param tool_name: tool name
    :param tool_args: Args used for the tool
    :param working_dir: Working directory
    :param metrics: metrics data
    :param skips: skips data
    :param issues: issues data
    :param crep_fname: The output file name
    :param file_path_list: Full file path for any manipulation

    :return serialized_log: SARIF output data
    """
    if not tool_args:
        tool_args = []
    tool_args_str = tool_args
    if isinstance(tool_args, list):
        tool_args_str = " ".join(tool_args)

    log = om.SarifLog(
        schema_uri="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version="2.1.0",
        runs=[
            om.Run(
                tool=om.Tool(driver=om.ToolComponent(name=tool_name)),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                        execution_successful=True,
                        working_directory=om.ArtifactLocation(uri=to_uri(working_dir)),
                    )
                ],
                conversion={
                    "tool": om.Tool(
                        driver=om.ToolComponent(name="@AppThreat/sast-scan")
                    ),
                    "invocation": om.Invocation(
                        execution_successful=True,
                        command_line=tool_args_str,
                        arguments=tool_args,
                        working_directory=om.ArtifactLocation(uri=to_uri(working_dir)),
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                    ),
                },
                properties={"metrics": metrics},
            )
        ],
    )

    run = log.runs[0]
    invocation = run.invocations[0]

    add_skipped_file_notifications(skips, invocation)
    add_results(issues, run, file_path_list, working_dir)

    serialized_log = to_json(log)

    if crep_fname:
        with io.open(crep_fname, "w") as fileobj:
            fileobj.write(serialized_log)

        if fileobj.name != sys.stdout.name:
            LOG.info("SARIF output written to file: %s 👍", fileobj.name)
    return serialized_log


def add_skipped_file_notifications(skips, invocation):
    """Method to add skipped files details to the output

    :param skips: List of files skipped by the tool
    :param invocation: Invocation object for the given run
    """
    if skips is None or len(skips) == 0:
        return

    if invocation.tool_configuration_notifications is None:
        invocation.tool_configuration_notifications = []

    for skip in skips:
        (file_name, reason) = skip

        notification = om.Notification(
            level="error",
            message=om.Message(text=reason),
            locations=[
                om.Location(
                    physical_location=om.PhysicalLocation(
                        artifact_location=om.ArtifactLocation(uri=to_uri(file_name))
                    )
                )
            ],
        )

        invocation.tool_configuration_notifications.append(notification)


def add_results(issues, run, file_path_list=None, working_dir=None):
    """Method to convert issues into results schema

    :param issues: Issues found
    :param run: Run object
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    if run.results is None:
        run.results = []

    rules = {}
    rule_indices = {}
    for issue in issues:
        result = create_result(issue, rules, rule_indices, file_path_list, working_dir)
        run.results.append(result)

    if len(rules) > 0:
        run.tool.driver.rules = list(rules.values())


def create_result(issue, rules, rule_indices, file_path_list=None, working_dir=None):
    """Method to convert a single issue into result schema with rules

    :param issue: Issues object
    :param rules: List of rules
    :param rule_indices: Indices of referred rules
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    if isinstance(issue, dict):
        issue = issue_from_dict(issue)

    issue_dict = issue.as_dict()

    rule, rule_index = create_or_find_rule(issue_dict, rules, rule_indices)

    # Substitute workspace prefix
    # Override file path prefix with workspace
    filename = issue_dict["filename"]
    if working_dir and WORKSPACE_PREFIX and filename.startswith(working_dir):
        filename = re.sub(r"^" + working_dir, WORKSPACE_PREFIX, filename)

    physical_location = om.PhysicalLocation(
        artifact_location=om.ArtifactLocation(uri=to_uri(filename))
    )

    add_region_and_context_region(
        physical_location, issue_dict["line_number"], issue_dict["code"]
    )

    return om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(text=issue_dict["issue_text"]),
        level=level_from_severity(issue_dict["issue_severity"]),
        locations=[om.Location(physical_location=physical_location)],
        properties={
            "issue_confidence": issue_dict["issue_confidence"],
            "issue_severity": issue_dict["issue_severity"],
        },
    )


def level_from_severity(severity):
    """Converts tool's severity to the 4 level
        suggested by SARIF
    """
    if severity == "CRITICAL":
        return "error"
    elif severity == "HIGH":
        return "error"
    elif severity == "MEDIUM":
        return "warning"
    elif severity == "LOW":
        return "note"
    else:
        return "warning"


def add_region_and_context_region(physical_location, line_number, code):
    """This adds the region information for displaying the code snippet

    :param physical_location: Points to file
    :param line_number: Line number suggested by the tool
    :param code: Source code snippet
    """
    first_line_number, snippet_lines = parse_code(code)
    end_line_number = first_line_number + len(snippet_lines) - 1
    if end_line_number < first_line_number:
        end_line_number = first_line_number + 3
    index = line_number - first_line_number
    snippet_line = ""
    if len(snippet_lines) > index:
        snippet_line = snippet_lines[index]

    physical_location.region = om.Region(
        start_line=line_number, snippet=om.ArtifactContent(text=snippet_line)
    )

    physical_location.context_region = om.Region(
        start_line=first_line_number,
        end_line=end_line_number,
        snippet=om.ArtifactContent(text="".join(snippet_lines)),
    )


def parse_code(code):
    """Method to parse the code to extract line number and snippets
    """
    code_lines = code.split("\n")

    # The last line from the split has nothing in it; it's an artifact of the
    # last "real" line ending in a newline. Unless, of course, it doesn't:
    last_line = code_lines[len(code_lines) - 1]

    last_real_line_ends_in_newline = False
    if len(last_line) == 0:
        code_lines.pop()
        last_real_line_ends_in_newline = True

    snippet_lines = []
    first = True
    first_line_number = 1
    for code_line in code_lines:
        number_and_snippet_line = code_line.split(" ", 1)
        if first:
            first_line_number = int(number_and_snippet_line[0])
            first = False

        snippet_line = number_and_snippet_line[1] + "\n"
        snippet_lines.append(snippet_line)

    if not last_real_line_ends_in_newline:
        last_line = snippet_lines[len(snippet_lines) - 1]
        snippet_lines[len(snippet_lines) - 1] = last_line[: len(last_line) - 1]

    return first_line_number, snippet_lines


def get_url(rule_id, test_name):
    # Return stackoverflow url for now
    # FIXME: The world needs an opensource SAST issue database!
    if rule_id and rule_id.startswith("CWE"):
        return "https://cwe.mitre.org/data/definitions/%s.html" % rule_id.replace(
            "CWE-", ""
        )
    return "https://stackoverflow.com/search?q=appthreat/sast-scan+{}+{}".format(
        rule_id, test_name
    )


def create_or_find_rule(issue_dict, rules, rule_indices):
    """Creates rules object for the rules section. Different tools make up
        their own id and names so this is identified on the fly

    :param issue_dict: Issue object that is normalized and converted
    :param rules: List of rules identified so far
    :param rule_indices: Rule indices cache

    :return rule and index
    """
    rule_id = issue_dict["test_id"]
    if rule_id in rules:
        return rules[rule_id], rule_indices[rule_id]

    rule = om.ReportingDescriptor(
        id=rule_id,
        name=issue_dict["test_name"],
        help_uri=get_url(rule_id, issue_dict["test_name"]),
    )

    index = len(rules)
    rules[rule_id] = rule
    rule_indices[rule_id] = index
    return rule, index


def to_uri(file_path):
    """Converts to file path to uri prefixed with file://

    :param file_path: File path to convert
    """
    if file_path.startswith("http"):
        return file_path
    pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        posix_path = pure_path.as_posix()  # Replace backslashes with slashes.
        return urlparse.quote(posix_path)  # %-encode special characters.
