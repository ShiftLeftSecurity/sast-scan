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

import requests

import lib.config as config
import lib.convert as convertLib
import lib.utils as utils
from lib.executor import exec_tool
from lib.logger import LOG
from lib.telemetry import track


def is_authenticated():
    """
    Method to check if we are authenticated
    """
    sl_home = config.get("SHIFTLEFT_HOME")
    sl_cmd = config.get("SHIFTLEFT_INSPECT_CMD")
    if utils.check_command(sl_cmd):
        sl_config_json = os.path.join(sl_home, "config.json")
        if os.path.exists(sl_config_json):
            return True
    else:
        sl_org = config.get("SHIFTLEFT_ORG_ID", config.get("SHIFTLEFT_ORGANIZATION_ID"))
        sl_token = config.get("SHIFTLEFT_ACCESS_TOKEN")
        return sl_org is not None and sl_token is not None
    return False


def authenticate():
    """
    Method to authenticate with ShiftLeft Inspect cloud when the required tokens gets passed via
    environment variables
    """
    if is_authenticated():
        return
    sl_org = config.get("SHIFTLEFT_ORG_ID", config.get("SHIFTLEFT_ORGANIZATION_ID"))
    sl_token = config.get("SHIFTLEFT_ACCESS_TOKEN")
    sl_cmd = config.get("SHIFTLEFT_INSPECT_CMD")
    run_uuid = config.get("run_uuid")
    if sl_org and sl_token and sl_cmd and utils.check_command(sl_cmd):
        inspect_login_args = [
            sl_cmd,
            "auth",
            "--no-auto-update",
            "--no-diagnostic",
            "--org",
            sl_org,
            "--token",
            sl_token,
        ]
        cp = exec_tool(inspect_login_args)
        if cp.returncode != 0:
            LOG.warning(
                "ShiftLeft Inspect authentication has failed. Please check the credentials"
            )
        else:
            LOG.info("Successfully authenticated with Inspect cloud")
        track({"id": run_uuid, "scan_mode": "inspect", "sl_org": sl_org})


def fetch_findings(app_name, version, report_fname):
    """
    Fetch findings from the Inspect Cloud
    """
    sl_org = config.get("SHIFTLEFT_ORG_ID", config.get("SHIFTLEFT_ORGANIZATION_ID"))
    sl_org_token = config.get(
        "SHIFTLEFT_ORG_TOKEN", config.get("SHIFTLEFT_ORGANIZATION_TOKEN")
    )
    findings_api = config.get("SHIFTLEFT_VULN_API")
    findings_list = []
    if sl_org and sl_org_token:
        findings_api = findings_api % dict(
            sl_org=sl_org, app_name=app_name, version=version
        )
        query_obj = {
            "query": {
                "returnRuntimeData": False,
                "orderByDirection": "VULNERABILITY_ORDER_DIRECTION_DESC",
            }
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + sl_org_token,
        }
        try:
            r = requests.post(findings_api, headers=headers, json=query_obj)
            if r.status_code == 200:
                findings_data = r.json()
                if findings_data:
                    findings_list += findings_data.get("vulnerabilities", [])
                    nextPageBookmark = findings_data.get("nextPageBookmark")
                    # Recurse and fetch all pages
                    while nextPageBookmark:
                        LOG.debug("Retrieving findings from next page")
                        r = requests.post(
                            findings_api,
                            headers=headers,
                            json={"pageBookmark": nextPageBookmark},
                        )
                        if r.status_code == 200:
                            findings_data = r.json()
                            if findings_data:
                                findings_list += findings_data.get(
                                    "vulnerabilities", []
                                )
                                nextPageBookmark = findings_data.get("nextPageBookmark")
                            else:
                                nextPageBookmark = None
                    with open(report_fname, mode="w") as rp:
                        json.dump({"vulnerabilities": findings_list}, rp)
                        LOG.debug(
                            "Data written to {}, {}".format(
                                report_fname, len(findings_list)
                            )
                        )
                return findings_list
            else:
                if not findings_list:
                    LOG.warning(
                        "Unable to retrieve any findings from Inspect Cloud. Status {}".format(
                            r.status_code
                        )
                    )
                else:
                    LOG.debug(
                        "Unable to retrieve some findings from Inspect Cloud. Proceeding with partial list. Status {}".format(
                            r.status_code
                        )
                    )
                return findings_list
        except Exception as e:
            LOG.error(e)
    else:
        return findings_list


def find_app_name(src, repo_context):
    """
    Method to retrieve the app name for inspect

    :param src: Source directory
    :param repo_context: Repo context
    :return: App name string
    """
    app_name = config.get("SHIFTLEFT_PROJECT_NAME")
    if not app_name:
        app_name = config.get("SHIFTLEFT_APP", repo_context.get("repositoryName"))
    if not app_name:
        app_name = os.path.dirname(src)
    return app_name


def inspect_scan(language, src, reports_dir, convert, repo_context):
    """
    Method to perform inspect cloud scan

    Args:
      language Project language
      src Project dir
      reports_dir Directory for output reports
      convert Boolean to enable normalisation of reports json
      repo_context Repo context
    """
    run_uuid = config.get("run_uuid")
    cpg_mode = config.get("SHIFTLEFT_CPG")
    env = os.environ.copy()
    report_fname = utils.get_report_file(
        "inspect", reports_dir, convert, ext_name="json"
    )
    sl_cmd = config.get("SHIFTLEFT_INSPECT_CMD")
    # Check if sl cli is available
    if not utils.check_command(sl_cmd):
        LOG.warning(
            "sl cli is not available. Please check if your build uses shiftleft/scan as the image"
        )
        return
    analyze_files = config.get("SHIFTLEFT_ANALYZE_FILE")
    if not analyze_files:
        if language == "java":
            analyze_target_dir = config.get(
                "SHIFTLEFT_ANALYZE_DIR", os.path.join(src, "target")
            )
            analyze_files = utils.find_java_artifacts(analyze_target_dir)
            env["SCAN_JAVA_HOME"] = os.environ.get("SCAN_JAVA_8_HOME")
        if language == "csharp":
            if not utils.check_dotnet():
                LOG.warning(
                    "dotnet is not available. Please check if your build uses shiftleft/scan-csharp as the image"
                )
                return
            analyze_files = utils.find_csharp_artifacts(src)
            cpg_mode = True
    app_name = find_app_name(src, repo_context)
    branch = repo_context.get("revisionId")
    if not branch:
        branch = "master"
    if not analyze_files:
        LOG.warning(
            "Unable to find any build artifacts. Compile your project first before invoking scan."
        )
        return
    if len(analyze_files) > 1:
        LOG.warning(
            "Multiple files found in {}. Only {} will be analyzed".format(
                analyze_target_dir, analyze_files[0]
            )
        )
    sl_args = [
        sl_cmd,
        "analyze",
        "--no-auto-update" if language == "java" else None,
        "--wait",
        "--cpg" if cpg_mode else None,
        "--" + language,
        "--tag",
        "branch=" + branch,
        "--app",
        app_name,
    ]
    sl_args += [analyze_files[0]]
    sl_args = [arg for arg in sl_args if arg is not None]
    LOG.info(
        "About to perform ShiftLeft Inspect cloud analysis. This might take a few minutes ..."
    )
    cp = exec_tool(sl_args, src, env=env)
    if cp.returncode != 0:
        LOG.warning("Inspect cloud analyze has failed with the below logs")
        LOG.info(cp.stderr)
        return
    findings_data = fetch_findings(app_name, branch, report_fname)
    if findings_data and convert:
        crep_fname = utils.get_report_file(
            "inspect", reports_dir, convert, ext_name="sarif"
        )
        convertLib.convert_file("inspect", sl_args[1:], src, report_fname, crep_fname)
    track({"id": run_uuid, "scan_mode": "inspect", "sl_args": sl_args})


def convert_to_findings(src_dir, repo_context, reports_dir, sarif_files):
    """
    Convert the sarif files to Inspect findings format

    :param src_dir: Source directory
    :param repo_context: Repository context
    :param reports_dir: Reports directory
    :param sarif_files: SARIF files
    :return: None
    """
    app_name = find_app_name(src_dir, repo_context)
    findings_fname = utils.get_report_file(
        "inspect", reports_dir, True, ext_name="findings.json"
    )
    # Exclude any inspect sarif files
    sarif_files = [f for f in sarif_files if "inspect" not in f]
    if sarif_files:
        convert_sarif(app_name, repo_context, sarif_files, findings_fname)


def convert_severity(severity):
    """
    Method to convert SARIF severity to inspect

    :return: Severity string for inspect
    """
    severity = severity.lower()
    if severity == "error":
        return "critical"
    elif severity == "warning":
        return "moderate"
    return "info"


def convert_sarif(app_name, repo_context, sarif_files, findings_fname):
    """
    Method to convert sarif to findings json

    :param app_name: Application name
    :param sarif_file:
    :param findings_fname:
    :return:
    """
    finding_id = 1
    with open(findings_fname, mode="w") as out_file:
        for sf in sarif_files:
            with open(sf, mode="r") as report_file:
                report_data = json.loads(report_file.read())
                # skip this file if the data is empty
                if not report_data or not report_data.get("runs"):
                    continue
                # Iterate through all the runs
                for run in report_data["runs"]:
                    try:
                        results = run.get("results")
                        if not results:
                            continue
                        rules = {
                            r["id"]: r
                            for r in run.get("tool", {}).get("driver", {}).get("rules")
                            if r and r.get("id")
                        }
                        for result in results:
                            rule = rules.get(result.get("ruleId"))
                            for location in result.get("locations"):
                                finding = {
                                    "app": app_name,
                                    "type": "vuln",
                                    "title": result.get("message", {}).get("text"),
                                    "description": rule.get("fullDescription", {}).get(
                                        "text"
                                    ),
                                    "internal_id": "{}/{}".format(
                                        result["ruleId"],
                                        utils.calculate_line_hash(
                                            location.get("physicalLocation", {})[
                                                "region"
                                            ]["snippet"]["text"]
                                        ),
                                    ),
                                    "severity": convert_severity(
                                        result.get("properties", {})["issue_severity"]
                                    ),
                                    "owasp_category": "",
                                    "category": result["ruleId"],
                                    "details": {
                                        "repoContext": repo_context,
                                        "name": result.get("message", {})["text"],
                                        "tags": ",".join(rule["properties"]["tags"]),
                                        "fileName": location["physicalLocation"][
                                            "artifactLocation"
                                        ]["uri"],
                                        "DATA_TYPE": "OSS_SCAN",
                                        "lineNumber": location.get(
                                            "physicalLocation", {}
                                        )["region"]["startLine"],
                                    },
                                }
                                out_file.write(json.dumps(finding))
                                finding_id = finding_id + 1
                    except Exception as e:
                        LOG.warning("Unable to convert the run to findings format")
