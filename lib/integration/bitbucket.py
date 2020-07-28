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
import lib.utils as utils
from lib.integration import GitProvider
from lib.logger import LOG

# Use local bitbucket proxy to avoid the need for app password
proxies = {
    "http": "http://localhost:29418",
    "https": "http://localhost:29418",
}


class Bitbucket(GitProvider):
    def get_context(self, repo_context):
        return {**repo_context, "repoOwner": os.getenv("BITBUCKET_REPO_OWNER")}

    def get_reports_url(self, repo_context):
        context = self.get_context(repo_context)
        url = f"http://api.bitbucket.org/2.0/repositories/{context.get('repoOwner')}/{context.get('repositoryName')}/commit/{context.get('revisionId')}/reports/shiftleft-scan"
        return url

    def convert_severity(self, severity):
        """Convert ShiftLeft severity to Bitbucket insights"""
        if severity == "critical":
            return "CRITICAL"
        elif severity == "moderate":
            return "MEDIUM"
        return "LOW"

    def annotate_pr(self, repo_context, findings_file, report_summary, build_status):
        with open(findings_file, mode="r") as fp:
            try:
                findings_obj = json.load(fp)
                findings = findings_obj.get("findings")
                if not findings:
                    LOG.debug("No findings from scan available to report")
                    return
                total_count = len(findings)
                data_list = [
                    {
                        "title": "Safe to merge?",
                        "type": "BOOLEAN",
                        "value": build_status != "fail",
                    },
                ]
                for rk, rv in report_summary.items():
                    data_list.append(
                        {
                            "title": rv.get("tool"),
                            "type": "TEXT",
                            "value": rv.get("status"),
                        }
                    )
                scan_id = config.get("run_uuid", "001")
                # Create a PR report based on the total findings
                rr = requests.put(
                    f"{self.get_reports_url(repo_context)}-{scan_id}",
                    proxies=proxies,
                    headers={"Content-Type": "application/json"},
                    json={
                        "title": "ShiftLeft Scan",
                        "details": f"This pull request contains {total_count} issues",
                        "report_type": "SECURITY",
                        "reporter": f"ShiftLeft Scan report for {repo_context.get('repositoryName')}",
                        "link": "https://slscan.io",
                        "logo_url": "https://www.shiftleft.io/static/images/ShiftLeft_logo_white.svg",
                        "result": "FAILED" if build_status == "fail" else "PASSED",
                        "data": data_list,
                    },
                )
                if rr.ok:
                    for f in findings:
                        finternal = f.get("internal_id")
                        tmpA = finternal.split("/")
                        title = tmpA[0]
                        occurrenceHash = tmpA[-1]
                        annotation_url = f"{self.get_reports_url(repo_context)}-{scan_id}/annotations/scan-{occurrenceHash}"
                        fileName = ""
                        lineNumber = None
                        if f.get("details"):
                            fileName = f.get("details", {}).get("fileName")
                            lineNumber = f.get("details", {}).get("lineNumber")
                        workspace = utils.get_workspace(repo_context)
                        # Remove the workspace
                        if workspace:
                            workspace = workspace + "/"
                            fileName = fileName.replace(workspace, "")
                        # Cleanup title and description
                        title = f.get("title")
                        description = f.get("description")
                        if len(title) > len(description) and "\n" in title:
                            description = f.get("title")
                        if "\n" in title:
                            title = title.split("\n")[0]
                        annotation = {
                            "title": "ShiftLeft Scan Report",
                            "annotation_type": "VULNERABILITY",
                            "summary": title,
                            "details": description,
                            "severity": self.convert_severity(f.get("severity")),
                            "path": fileName,
                            "line": lineNumber,
                        }
                        ar = requests.put(
                            annotation_url,
                            proxies=proxies,
                            headers={"Content-Type": "application/json"},
                            json=annotation,
                        )
                        if not ar.ok:
                            break
            except Exception as e:
                LOG.exception(e)
