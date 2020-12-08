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
        return {
            **repo_context,
            "repoOwner": os.getenv("BITBUCKET_REPO_OWNER"),
            "repoFullname": os.getenv("BITBUCKET_REPO_FULL_NAME"),
            "repoWorkspace": os.getenv("BITBUCKET_WORKSPACE"),
            "repoUUID": os.getenv("BITBUCKET_REPO_UUID"),
            "prID": os.getenv("BITBUCKET_PR_ID"),
            "prTargetBranch": os.getenv("BITBUCKET_PR_DESTINATION_BRANCH"),
            "bitbucketToken": os.getenv("BITBUCKET_TOKEN"),
            "commitSHA": os.getenv("BITBUCKET_COMMIT"),
            "repoId": os.getenv("BITBUCKET_REPO_UUID"),
            "projectUrl": os.getenv("BITBUCKET_REPO_SLUG"),
            "jobId": os.getenv("BITBUCKET_BUILD_NUMBER"),
        }

    def get_reports_url(self, repo_context):
        context = self.get_context(repo_context)
        url = f"http://api.bitbucket.org/2.0/repositories/{context.get('repoFullname')}/commit/{context.get('revisionId')}/reports/shiftleft-scan"
        return url

    def get_pr_comments_url(self, repo_context):
        context = self.get_context(repo_context)
        url = f"https://api.bitbucket.org/2.0/repositories/{context.get('repoFullname')}/pullrequests/{context.get('prID')}/comments"
        return url

    def convert_severity(self, severity):
        """Convert scan severity to Bitbucket insights"""
        if severity == "critical":
            return "CRITICAL"
        elif severity == "moderate":
            return "MEDIUM"
        return "LOW"

    def annotate_pr(self, repo_context, findings_file, report_summary, build_status):
        if not findings_file:
            return
        with open(findings_file, mode="r") as fp:
            try:
                findings_obj = json.load(fp)
                findings = findings_obj.get("findings")
                if not findings:
                    LOG.debug("No findings from scan available to report")
                    return
                context = self.get_context(repo_context)
                # Leave a comment on the pull request
                if context.get("prID") and context.get("bitbucketToken"):
                    summary = "| Tool | Critical | High | Medium | Low | Status |\n"
                    summary = (
                        summary + "| ---- | ------- | ------ | ----- | ---- | ---- |\n"
                    )
                    for rk, rv in report_summary.items():
                        status_emoji = self.to_emoji(rv.get("status"))
                        summary = f'{summary}| {rv.get("tool")} | {rv.get("critical")} | {rv.get("high")} | {rv.get("medium")} | {rv.get("low")} | {status_emoji} |\n'
                    template = config.get("PR_COMMENT_BASIC_TEMPLATE")
                    recommendation = (
                        f"Please review the scan reports before approving this pull request for {context.get('prTargetBranch')} branch"
                        if build_status == "fail"
                        else "Looks good"
                    )
                    repoOwner = f"{context.get('BITBUCKET_REPO_OWNER')}"
                    repoFullname = f"{context.get('BITBUCKET_REPO_FULL_NAME')}"
                    repoWorkspace = f"{context.get('BITBUCKET_WORKSPACE')}"
                    repoUUID = f"{context.get('BITBUCKET_REPO_UUID')}"
                    prID = f"{context.get('BITBUCKET_PR_ID')}"
                    prTargetBranch = f"{context.get('BITBUCKET_PR_DESTINATION_BRANCH')}"
                    bitbucketToken = f"{context.get('BITBUCKET_TOKEN')}"
                    commitSHA = f"{context.get('BITBUCKET_COMMIT')}"
                    repoId = f"{context.get('BITBUCKET_REPO_UUID')}"
                    projectUrl = f"{context.get('BITBUCKET_REPO_SLUG')}"
                    jobId = f"{context.get('BITBUCKET_BUILD_NUMBER')}"

                    body = template % dict(
                        summary=summary,
                        recommendation=recommendation,
                        repoOwner=repoOwner,
                        repoFullname=repoFullname,
                        repoWorkspace=repoWorkspace,
                        repoUUID=repoUUID,
                        prID=prID,
                        prTargetBranch=prTargetBranch,
                        bitbucketToken=bitbucketToken,
                        commitSHA=commitSHA,
                        repoId=repoId,
                        projectUrl=projectUrl,
                        jobId=jobId,
                    )
                    rc = requests.post(
                        self.get_pr_comments_url(repo_context),
                        auth=(
                            context.get("repoWorkspace"),
                            context.get("bitbucketToken"),
                        ),
                        headers={"Content-Type": "application/json"},
                        json={"content": {"raw": body}},
                    )
                    if not rc.ok:
                        LOG.debug(rc.json())
                else:
                    LOG.debug(
                        "Either build is not part of a PR or variable BITBUCKET_TOKEN was not set with Pull Request write permission"
                    )
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
                        "title": "Scan",
                        "details": f"This pull request contains {total_count} issues",
                        "report_type": "SECURITY",
                        "reporter": f"Scan report for {repo_context.get('repositoryName')}",
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
                            "title": "Scan Report",
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
                else:
                    LOG.debug(rr.json())
            except Exception as e:
                LOG.debug(e)
