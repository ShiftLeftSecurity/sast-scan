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

import datetime
import io
import json
import os
import pathlib
import re
import sys
import uuid
from urllib.parse import quote_plus

import sarif_om as om
from jschema_to_python.to_json import to_json
from reporter.sarif import render_html

import lib.cis as cis
import lib.config as config
import lib.csv_parser as csv_parser
import lib.xml_parser as xml_parser
from lib.context import find_repo_details
from lib.cwe import get_description, get_name
from lib.issue import issue_from_dict
from lib.logger import LOG
from lib.utils import (
    find_path_prefix,
    is_generic_package,
    is_ignored_file,
    to_fingerprint_hash,
)

TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Line number hash size
HASH_DIGEST_SIZE = config.get("HASH_DIGEST_SIZE", 8)


def tweak_severity(tool_name, issue_dict):
    """
    Tweak severity for certain tools.
    TODO: Remove this method somehow since this has to be done by issue.py
    :param tool_name:
    :param issue_dict:
    :return:
    """
    rule_id = issue_dict["test_id"]
    rule_name = issue_dict["test_name"]
    issue_severity = issue_dict["issue_severity"]
    if tool_name in [
        "staticcheck",
        "psalm",
        "phpstan",
        "source-js",
        "source-php",
        "audit-php",
    ]:
        if issue_severity in ["HIGH", "CRITICAL"]:
            return "MEDIUM"
        return "LOW"
    if tool_name in [
        "checkov",
        "source-tf",
        "source-yaml",
        "source-serverless",
        "source-arm",
        "source-aws",
        "source-k8s",
        "source-dockerfile",
    ]:
        cis_rule = cis.get_rule(rule_id)
        if not cis_rule:
            cis_rule = cis.get_rule(rule_name)
        if cis_rule:
            return "CRITICAL" if cis_rule.get("scored") else "HIGH"
    return issue_severity


def get_from_taints(taint_trace):
    """
    Convert taint trace list to source and sink
    """
    source = None
    sink = None
    labels = []
    for taint in taint_trace:
        filename = taint.get("file_name")
        if not filename or "psalm" in filename:
            continue
        if not source:
            source = {"filename": filename, "line_number": taint.get("line_from")}
        if taint.get("label"):
            labels.append(taint.get("label"))
    last = taint_trace[-1]
    sink = {"filename": last.get("file_name"), "line_number": last.get("line_from")}
    return source, sink, labels


def convert_dataflow(working_dir, tool_args, dataflows):
    """
    Convert dataflow into a simpler source and sink format for better representation in SARIF based viewers

    :param working_dir: Work directory
    :param tool_args: Tool args
    :param dataflows: List of dataflows from Inspect
    :return List of filename and location
    """
    if not dataflows:
        return None
    file_name_prefix = ""
    location_list = []
    for flow in dataflows:
        fn = flow["location"].get("fileName")
        if not fn or fn == "N/A":
            continue
        if not is_generic_package(fn):
            location = flow["location"]
            fileName = location.get("fileName")
            if not file_name_prefix:
                file_name_prefix = find_path_prefix(working_dir, fileName)
            location_list.append(
                {
                    "filename": os.path.join(file_name_prefix, fileName),
                    "line_number": location.get("lineNumber"),
                }
            )
    if len(location_list) >= 2:
        first = location_list[0]
        last = location_list[-1]
        if (
            first["filename"] == last["filename"]
            and first["line_number"] == last["line_number"]
        ):
            location_list = [first]
        else:
            location_list = [first, last]
    return location_list


def extract_from_file(
    tool_name, tool_args, working_dir, report_file, file_path_list=None
):
    """Extract properties from reports

    :param tool_name: tool name
    :param tool_args: tool args
    :param working_dir: Working directory
    :param report_file: Report file
    :param file_path_list: Full file path for any manipulation

    :return issues, metrics, skips information
    """
    issues = []
    metrics = None
    skips = []
    # If the tools did not produce any result do not crash
    if not os.path.isfile(report_file):
        return issues, metrics, skips
    extn = pathlib.PurePosixPath(report_file).suffix

    with io.open(report_file, "r") as rfile:
        # Static check use jsonlines format, duh
        if tool_name == "staticcheck":
            contents = rfile.read()
            try:
                issues = [
                    json.loads(str(item)) for item in contents.strip().split("\n")
                ]
            except json.decoder.JSONDecodeError:
                LOG.warning(
                    "staticcheck produced no result since the project was not built before analysis!"
                )
            return issues, metrics, skips
        if extn == ".json":
            try:
                report_data = json.loads(rfile.read())
            except json.decoder.JSONDecodeError:
                return issues, metrics, skips
            # NG SAST (Formerly Inspect) uses vulnerabilities
            if tool_name == "ng-sast":
                for v in report_data.get("vulnerabilities"):
                    if not v:
                        continue
                    vuln = v["vulnerability"]
                    location_list = []
                    if vuln.get("dataFlow") and vuln.get("dataFlow", {}).get(
                        "dataFlow"
                    ):
                        location_list = convert_dataflow(
                            working_dir, tool_args, vuln["dataFlow"]["dataFlow"]["list"]
                        )
                    for location in location_list:
                        issues.append(
                            {
                                "rule_id": vuln["category"],
                                "title": vuln["title"],
                                "description": vuln["description"],
                                "score": vuln["score"],
                                "severity": vuln["severity"],
                                "line_number": location.get("line_number"),
                                "filename": location.get("filename"),
                                "first_found": vuln["firstVersionDetected"],
                                "issue_confidence": "HIGH",
                            }
                        )
            elif tool_name == "taint-php":
                for entry in report_data:
                    taint_trace = entry.get("taint_trace")
                    labels = []
                    if taint_trace:
                        source, sink, labels = get_from_taints(taint_trace)
                    else:
                        source, _, _ = get_from_taints([entry])
                    issues.append(
                        {
                            "rule_id": entry.get("shortcode"),
                            "test_name": entry.get("type"),
                            "description": "{}: {}".format(
                                entry.get("message"), "\\n".join(labels)
                            ),
                            "link": entry.get("link"),
                            "severity": entry.get("severity"),
                            "issue_confidence": "HIGH",
                            "line_number": source.get("line_number"),
                            "filename": source.get("filename"),
                        }
                    )
            elif tool_name == "taint-python":
                taint_list = report_data.get("vulnerabilities")
                for taint in taint_list:
                    source = taint.get("source")
                    sink = taint.get("sink")
                    tags = {}
                    for taint_props in [
                        "source_trigger_word",
                        "source_label",
                        "source_type",
                        "sink_trigger_word",
                        "sink_label",
                        "sink_type",
                    ]:
                        if taint.get(taint_props):
                            tags[taint_props] = taint.get(taint_props)
                    issues.append(
                        {
                            "rule_id": taint.get("rule_id"),
                            "test_name": taint.get("rule_name"),
                            "short_description": taint.get("short_description"),
                            "cwe_category": taint.get("cwe_category"),
                            "owasp_category": taint.get("owasp_category"),
                            "description": taint.get("description"),
                            "severity": taint.get("severity"),
                            "issue_confidence": "HIGH",
                            "line_from": source.get("line_number"),
                            "line_to": sink.get("line_number"),
                            "filename": source.get("path"),
                            "tags": tags,
                        }
                    )
            elif tool_name == "phpstan" or tool_name == "source-php":
                file_errors = report_data.get("files")
                for filename, messageobj in file_errors.items():
                    messages = messageobj.get("messages")
                    for msg in messages:
                        # Create a rule id for phpstan
                        rule_word = msg.get("message", "").split(" ")[0]
                        rule_word = "phpstan-" + rule_word.lower()
                        issues.append(
                            {
                                "rule_id": rule_word,
                                "title": msg.get("message"),
                                "line_number": msg.get("line"),
                                "filename": filename,
                                "severity": "LOW",
                                "issue_confidence": "MEDIUM",
                            }
                        )
            elif tool_name == "source-js":
                njs_findings = report_data.get("nodejs", {})
                njs_findings.update(report_data.get("templates", {}))
                for k, v in njs_findings.items():
                    # Password detection by njsscan is full of false positives
                    if k == "node_password":
                        continue
                    files = v.get("files", [])
                    metadata = v.get("metadata", {})
                    if not files or not metadata:
                        continue
                    for afile in files:
                        line_number = 0
                        if afile.get("match_lines"):
                            line_number = afile.get("match_lines")[0]
                        issues.append(
                            {
                                "rule_id": metadata.get("owasp")
                                .replace(":", "-")
                                .replace(" ", "")
                                .lower(),
                                "title": metadata.get("cwe"),
                                "description": metadata.get("description"),
                                "severity": metadata.get("severity"),
                                "line_number": line_number,
                                "filename": afile.get("file_path"),
                                "issue_confidence": "HIGH",
                            }
                        )
            elif tool_name == "checkov":
                if isinstance(report_data, list):
                    for rd in report_data:
                        issues += rd.get("results", {}).get("failed_checks")
                else:
                    issues = report_data.get("results", {}).get("failed_checks")
            elif tool_name == "source-ruby":
                issues = report_data.get("warnings", [])
                issues += report_data.get("errors", [])
            elif isinstance(report_data, list):
                issues = report_data
            else:
                if "sec_issues" in report_data:
                    # NodeJsScan uses sec_issues
                    sec_data = report_data["sec_issues"]
                    for key, value in sec_data.items():
                        if isinstance(value, list):
                            issues = issues + value
                        else:
                            issues.append(value)
                elif "Issues" in report_data:
                    tmpL = report_data.get("Issues", [])
                    if tmpL:
                        issues += tmpL
                    else:
                        LOG.debug("%s produced no result" % tool_name)
                elif "results" in report_data:
                    tmpL = report_data.get("results", [])
                    if tmpL:
                        issues += tmpL
                    else:
                        LOG.debug("%s produced no result" % tool_name)
        if extn == ".csv":
            headers, issues = csv_parser.get_report_data(rfile)
        if extn == ".xml":
            issues, metrics = xml_parser.get_report_data(
                rfile, file_path_list=file_path_list, working_dir=working_dir
            )
    return issues, metrics, skips


def suppress_issues(issues):
    """Suppress issues based on the presence of certain tags and ignore logic

    :param issues: List of issues to be checked

    :return Filtered issues, Suppressed list
    """
    suppress_list = []
    filtered_list = []
    supress_markers = config.get("suppress_markers", [])
    for issue in issues:
        suppressed = False
        issue_dict = issue_from_dict(issue).as_dict()
        rule_id = issue_dict.get("test_id")
        filename = issue_dict.get("filename")
        code = issue_dict.get("code", "").replace("\n", " ").replace("\t", " ")
        # Is this rule ignored globally?
        if rule_id in config.ignored_rules:
            suppressed = True
        # Is there an ignore marker
        if not suppressed and code:
            for marker in supress_markers:
                if marker in code:
                    suppressed = True
                    break
        if not suppressed and filename:
            if is_ignored_file(None, file_name=filename):
                suppressed = True
            else:
                for igdir in config.get("ignore_directories"):
                    if filename.startswith(f"{igdir}/"):
                        suppressed = True
                        break
        if suppressed:
            suppress_list.append(issue)
        else:
            filtered_list.append(issue)
    return filtered_list, suppress_list


def convert_file(
    tool_name,
    tool_args,
    working_dir,
    report_file,
    converted_file,
    file_path_list=None,
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
    issues, metrics, skips = extract_from_file(
        tool_name, tool_args, working_dir, report_file, file_path_list
    )
    issues, suppress_list = suppress_issues(issues)
    if suppress_list:
        LOG.info(f"Suppressed {len(suppress_list)} issues")
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
    repo_details = find_repo_details(working_dir)
    log_uuid = str(uuid.uuid4())
    run_uuid = config.get("run_uuid")

    # working directory to use in the log
    WORKSPACE_PREFIX = config.get("WORKSPACE", None)
    wd_dir_log = WORKSPACE_PREFIX if WORKSPACE_PREFIX is not None else working_dir
    driver_name = config.tool_purpose_message.get(tool_name, tool_name)
    # Construct SARIF log
    log = om.SarifLog(
        schema_uri="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version="2.1.0",
        inline_external_properties=[
            om.ExternalProperties(guid=log_uuid, run_guid=run_uuid)
        ],
        runs=[
            om.Run(
                automation_details=om.RunAutomationDetails(
                    guid=log_uuid,
                    description=om.Message(
                        text="Static Analysis Security Test results using @ShiftLeft/sast-scan"
                    ),
                ),
                tool=om.Tool(
                    driver=om.ToolComponent(
                        name=driver_name, full_name=driver_name, version="1.0.0-scan"
                    )
                ),
                invocations=[
                    om.Invocation(
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                        execution_successful=True,
                        working_directory=om.ArtifactLocation(uri=to_uri(wd_dir_log)),
                    )
                ],
                conversion={
                    "tool": om.Tool(
                        driver=om.ToolComponent(name="@ShiftLeft/sast-scan")
                    ),
                    "invocation": om.Invocation(
                        execution_successful=True,
                        command_line=tool_args_str,
                        arguments=tool_args,
                        working_directory=om.ArtifactLocation(uri=to_uri(wd_dir_log)),
                        end_time_utc=datetime.datetime.utcnow().strftime(TS_FORMAT),
                    ),
                },
                version_control_provenance=[
                    om.VersionControlDetails(
                        repository_uri=repo_details["repositoryUri"],
                        branch=repo_details["branch"],
                        revision_id=repo_details["revisionId"],
                    )
                ],
            )
        ],
    )

    run = log.runs[0]
    invocation = run.invocations[0]

    add_skipped_file_notifications(skips, invocation)
    add_results(tool_name, issues, run, file_path_list, working_dir)

    serialized_log = to_json(log)

    if crep_fname:
        html_file = crep_fname.replace(".sarif", ".html")
        with io.open(crep_fname, "w") as fileobj:
            fileobj.write(serialized_log)
        if tool_name != "empty-scan":
            render_html(json.loads(serialized_log), html_file)
            if fileobj.name != sys.stdout.name:
                LOG.debug(
                    "SARIF and HTML report written to file: %s, %s :thumbsup:",
                    fileobj.name,
                    html_file,
                )
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


def add_results(tool_name, issues, run, file_path_list=None, working_dir=None):
    """Method to convert issues into results schema

    :param tool_name: tool name
    :param issues: Issues found
    :param run: Run object
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    if run.results is None:
        run.results = []

    rules = {}
    rule_indices = {}
    # Populate metrics
    metrics = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    total = 0

    for issue in issues:
        result = create_result(
            tool_name, issue, rules, rule_indices, file_path_list, working_dir
        )
        if result:
            run.results.append(result)
            issue_dict = issue_from_dict(issue).as_dict()
            rule_id = issue_dict.get("test_id")
            # Is this rule ignored globally?
            if rule_id in config.ignored_rules:
                continue
            total += 1
            issue_severity = issue_dict["issue_severity"]
            # Fix up severity for certain tools
            issue_severity = tweak_severity(tool_name, issue_dict)
            key = issue_severity.lower()
            if not metrics.get(key):
                metrics[key] = 0
            metrics[key] += 1

    if len(rules) > 0:
        run.tool.driver.rules = list(rules.values())

    metrics["total"] = total
    run.properties = {"metrics": metrics}


def should_suppress_fingerprint(fingerprint, working_dir):
    """Method to check if a result has to be suppressed based on its fingerprint hash

    :param fingerprint: Fingerprint hash object
    :param working_dir: Working directory
    """
    if not fingerprint:
        return False
    supress_fps = config.get_suppress_fingerprints(working_dir)
    if not supress_fps or not isinstance(supress_fps, dict):
        return False
    # supress_fps = {"scanPrimaryLocationHash": [], "scanTagsHash": [], "scanFileHash": []}
    for sk, svl in supress_fps.items():
        if not svl:
            continue
        if fingerprint.get(sk) in svl:
            LOG.debug(f"Suppressing fingerprint {fingerprint[sk]} of type {sk}")
            return True
    return False


def create_result(tool_name, issue, rules, rule_indices, file_path_list, working_dir):
    """Method to convert a single issue into result schema with rules

    :param tool_name: tool name
    :param issue: Issues object
    :param rules: List of rules
    :param rule_indices: Indices of referred rules
    :param file_path_list: Full file path for any manipulation
    :param working_dir: Working directory
    """
    WORKSPACE_PREFIX = config.get("WORKSPACE", None)
    if isinstance(issue, dict):
        issue = issue_from_dict(issue)

    issue_dict = issue.as_dict()
    rule_id = issue_dict.get("test_id")
    # Is this rule ignored globally?
    if rule_id in config.ignored_rules:
        return None
    rule, rule_index = create_or_find_rule(tool_name, issue_dict, rules, rule_indices)

    # Substitute workspace prefix
    # Override file path prefix with workspace
    filename = issue_dict["filename"]
    if working_dir:
        # Issue 5 fix. Convert relative to full path automatically
        # Convert to full path only if the user wants
        if WORKSPACE_PREFIX is None and not filename.startswith(working_dir):
            filename = os.path.join(working_dir, filename)
        if WORKSPACE_PREFIX is not None:
            # Make it relative path
            if WORKSPACE_PREFIX == "":
                filename = re.sub(r"^" + working_dir + "/", WORKSPACE_PREFIX, filename)
            elif not filename.startswith(working_dir):
                filename = os.path.join(WORKSPACE_PREFIX, filename)
            else:
                filename = re.sub(r"^" + working_dir, WORKSPACE_PREFIX, filename)
    physical_location = om.PhysicalLocation(
        artifact_location=om.ArtifactLocation(uri=to_uri(filename))
    )

    add_region_and_context_region(
        physical_location, issue_dict["line_number"], issue_dict["code"]
    )
    issue_severity = tweak_severity(tool_name, issue_dict)
    fingerprint = {}
    if physical_location.region and physical_location.region.snippet.text:
        snippet = physical_location.region.snippet.text
        snippet = snippet.strip().replace("\t", "").replace("\n", "")
        fingerprint = {
            "scanPrimaryLocationHash": to_fingerprint_hash(snippet, HASH_DIGEST_SIZE)
        }
    if issue_dict.get("tags"):
        tag_str = ""
        for tk, tv in issue_dict.get("tags", {}).items():
            tag_str += tv
        if tag_str:
            fingerprint["scanTagsHash"] = to_fingerprint_hash(tag_str, HASH_DIGEST_SIZE)
    # Filename hash
    fingerprint["scanFileHash"] = to_fingerprint_hash(filename, HASH_DIGEST_SIZE)

    # Should we suppress this fingerprint?
    if should_suppress_fingerprint(fingerprint, working_dir):
        return None
    return om.Result(
        rule_id=rule.id,
        rule_index=rule_index,
        message=om.Message(
            text=issue_dict["issue_text"],
            markdown=issue_dict["issue_text"] if tool_name == "ng-sast" else "",
        ),
        level=level_from_severity(issue_severity),
        locations=[om.Location(physical_location=physical_location)],
        partial_fingerprints=fingerprint,
        properties={
            "issue_confidence": issue_dict["issue_confidence"],
            "issue_severity": issue_severity,
            "issue_tags": issue_dict.get("tags", {}),
        },
        baseline_state="unchanged" if issue_dict["first_found"] else "new",
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
    # Ensure start line is always non-zero
    if first_line_number == 0:
        first_line_number = 1
    end_line_number = first_line_number + len(snippet_lines) - 1
    if end_line_number < first_line_number:
        end_line_number = first_line_number + 3
    index = line_number - first_line_number
    snippet_line = ""
    if line_number == 0:
        line_number = 1
    if snippet_lines and len(snippet_lines) > index:
        if index > 0:
            snippet_line = snippet_lines[index]
        else:
            snippet_line = snippet_lines[0]
    if snippet_line.strip().replace("\n", "") == "":
        snippet_line = ""
    physical_location.region = om.Region(
        start_line=line_number, snippet=om.ArtifactContent(text=snippet_line)
    )

    physical_location.context_region = om.Region(
        start_line=first_line_number,
        end_line=end_line_number,
        snippet=om.ArtifactContent(text="".join(snippet_lines)),
    )


def parse_code(code):
    """Method to parse the code to extract line number and snippets"""
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
        if len(number_and_snippet_line) > 1:
            snippet_line = number_and_snippet_line[1] + "\n"
            snippet_lines.append(snippet_line)

    if not last_real_line_ends_in_newline:
        last_line = snippet_lines[len(snippet_lines) - 1]
        snippet_lines[len(snippet_lines) - 1] = last_line[: len(last_line) - 1]

    return first_line_number, snippet_lines


def get_rule_short_description(tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a short description for the rule

    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return:
    """
    if rule_id and rule_id.upper().startswith("CWE"):
        return get_name(rule_id)
    if issue_dict.get("cwe_category"):
        return get_name(issue_dict.get("cwe_category"))
    if issue_dict.get("short_description"):
        return issue_dict.get("short_description")
    if test_name:
        if not test_name.endswith("."):
            test_name = test_name + "."
        return test_name
    return "Rule {} from {}.".format(rule_id, tool_name)


def get_rule_full_description(tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a full description for the rule

    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return:
    """
    if rule_id and rule_id.upper().startswith("CWE"):
        return get_description(rule_id, False)
    if issue_dict.get("cwe_category"):
        return get_description(issue_dict.get("cwe_category"), False)
    issue_text = issue_dict.get("issue_text", "")
    # Extract just the first line alone
    if issue_text:
        issue_text = issue_text.split("\n")[0]
    if not issue_text.endswith("."):
        issue_text = issue_text + "."
    return issue_text


def get_help(format, tool_name, rule_id, test_name, issue_dict):
    """
    Constructs a full description for the rule

    :param format: text or markdown
    :param tool_name:
    :param rule_id:
    :param test_name:
    :param issue_dict:
    :return: Help text
    """
    if rule_id and rule_id.upper().startswith("CWE"):
        return get_description(rule_id, True)
    if issue_dict.get("cwe_category"):
        return get_description(issue_dict.get("cwe_category"), True)
    issue_text = issue_dict.get("issue_text", "")
    return issue_text


def get_url(tool_name, rule_id, test_name, issue_dict):
    if issue_dict.get("test_ref_url"):
        return issue_dict.get("test_ref_url")
    if config.tool_ref_url.get(tool_name):
        return config.tool_ref_url.get(tool_name) % dict(
            rule_id=rule_id, tool_name=tool_name, test_name=test_name
        )
    rule_id = quote_plus(rule_id)
    if rule_id and rule_id.startswith("CWE"):
        return "https://cwe.mitre.org/data/definitions/%s.html" % rule_id.replace(
            "CWE-", ""
        )
    if issue_dict.get("cwe_category"):
        return "https://cwe.mitre.org/data/definitions/%s.html" % issue_dict.get(
            "cwe_category"
        ).replace("CWE-", "")
    return "https://slscan.io?q={}".format(rule_id)


def create_or_find_rule(tool_name, issue_dict, rules, rule_indices):
    """Creates rules object for the rules section. Different tools make up
        their own id and names so this is identified on the fly

    :param tool_name: tool name
    :param issue_dict: Issue object that is normalized and converted
    :param rules: List of rules identified so far
    :param rule_indices: Rule indices cache

    :return rule and index
    """
    rule_id = issue_dict["test_id"]
    rule_name = issue_dict["test_name"]
    if rule_id == rule_name:
        rule_name = rule_name.lower().replace("_", " ").capitalize()
    if rule_id in rules:
        return rules[rule_id], rule_indices[rule_id]
    precision = "high"
    if rule_id and rule_id.upper().startswith("CWE") or tool_name == "ng-sast":
        precision = "very-high"
    issue_severity = tweak_severity(tool_name, issue_dict)
    rule = om.ReportingDescriptor(
        id=rule_id,
        name=rule_name,
        short_description={
            "text": get_rule_short_description(
                tool_name, rule_id, issue_dict["test_name"], issue_dict
            )
        },
        full_description={
            "text": get_rule_full_description(
                tool_name, rule_id, issue_dict["test_name"], issue_dict
            )
        },
        help={
            "text": get_help(
                "text", tool_name, rule_id, issue_dict["test_name"], issue_dict
            ),
            "markdown": get_help(
                "markdown", tool_name, rule_id, issue_dict["test_name"], issue_dict
            ),
        },
        help_uri=get_url(tool_name, rule_id, issue_dict["test_name"], issue_dict),
        properties={
            "tags": ["NG SAST" if tool_name == "ng-sast" else "Scan"],
            "precision": precision,
        },
        default_configuration={"level": level_from_severity(issue_severity)},
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
    if "\\" in file_path:
        if "/" in file_path:
            file_path = file_path.replace("/", "\\")
        pure_path = pathlib.PureWindowsPath(file_path)
    else:
        pure_path = pathlib.PurePath(file_path)
    if pure_path.is_absolute():
        return pure_path.as_uri()
    else:
        return pure_path.as_posix()  # Replace backslashes with slashes.
