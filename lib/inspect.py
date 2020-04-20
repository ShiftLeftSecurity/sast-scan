import json
import logging
import os

import requests

import lib.config as config
import lib.convert as convertLib
import lib.utils as utils
from lib.executor import exec_tool

logging.basicConfig(
    level=logging.INFO, format="%(levelname)s [%(asctime)s] %(message)s"
)
LOG = logging.getLogger(__name__)


def is_authenticated():
    """
    Method to check if we are authenticated
    """
    sl_home = config.get("SHIFTLEFT_HOME")
    sl_config_json = os.path.join(sl_home, "config.json")
    if os.path.exists(sl_config_json):
        return True
    else:
        LOG.debug("ShiftLeft config {} not found".format(sl_config_json))


def authenticate():
    """
    Method to authenticate with shiftleft inspect cloud when the required tokens gets passed via
    environment variables
    """
    if is_authenticated():
        return
    sl_org = config.get("SHIFTLEFT_ORG_ID")
    sl_token = config.get("SHIFTLEFT_ACCESS_TOKEN")
    sl_cmd = config.get("SHIFTLEFT_INSPECT_CMD")
    if sl_org and sl_token and sl_cmd:
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
            LOG.info("Successfully authenticated with inspect cloud")


def fetch_findings(app_name, version, report_fname):
    """
    Fetch findings from the Inspect Cloud
    """
    sl_org = config.get("SHIFTLEFT_ORG_ID")
    sl_org_token = config.get("SHIFTLEFT_ORG_TOKEN")
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
                        LOG.info("Retrieving findings from next page")
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
                        LOG.info(
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
            logging.error(e)
    else:
        return findings_list


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
    report_fname = utils.get_report_file(
        "inspect", reports_dir, convert, ext_name="json"
    )
    sl_cmd = config.get("SHIFTLEFT_INSPECT_CMD")
    analyze_target_dir = config.get(
        "SHIFTLEFT_ANALYZE_DIR", os.path.join(src, "target")
    )
    analyze_files = config.get("SHIFTLEFT_ANALYZE_FILE")
    if not analyze_files:
        if language == "java":
            analyze_files = utils.find_java_artifacts(analyze_target_dir)
    app_name = config.get("SHIFTLEFT_APP", repo_context.get("repositoryName"))
    no_cpg = config.get("SHIFTLEFT_NO_CPG")
    if not app_name:
        app_name = os.path.dirname(src)
    branch = repo_context.get("revisionId")
    if not branch:
        branch = "master"
    if not analyze_files:
        LOG.warning(
            "Unable to find any build artifacts in {}. Run mvn package or a similar command before invoking inspect scan".format(
                analyze_target_dir
            )
        )
        return
    if len(analyze_files) > 1:
        LOG.warning(
            "Multiple jar files found in {}. Only {} will be analyzed".format(
                analyze_target_dir, analyze_files[0]
            )
        )
    sl_args = [
        sl_cmd,
        "analyze",
        "--no-auto-update",
        "--wait",
        "--cpg" if not no_cpg else "",
        "--java",
        "--tag",
        "branch=" + branch,
        "--app",
        app_name,
    ]
    sl_args += [analyze_files[0]]
    env = os.environ.copy()
    env["JAVA_HOME"] = os.environ.get("JAVA_8_HOME")
    LOG.info(
        "About to perform ShiftLeft Inspect cloud analysis. This might take a few minutes ..."
    )
    cp = exec_tool(sl_args, src, env=env)
    if cp.returncode != 0:
        LOG.warning("Inspect cloud analyze has failed with the below logs")
        LOG.info(cp.stdout)
        LOG.info(cp.stderr)
        return
    findings_data = fetch_findings(app_name, branch, report_fname)
    if findings_data and convert:
        crep_fname = utils.get_report_file(
            "inspect", reports_dir, convert, ext_name="sarif"
        )
        convertLib.convert_file("inspect", sl_args[1:], src, report_fname, crep_fname)
