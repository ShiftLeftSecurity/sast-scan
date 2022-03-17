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

import requests

import lib.config as config
from lib.integration import GitProvider
from lib.logger import LOG


class GitLab(GitProvider):
    def get_token(self):
        token = config.get("GITLAB_TOKEN")
        if not token:
            token = config.get("MR_TOKEN")
        return token

    def get_context(self, repo_context):
        apiUrl = os.getenv("CI_API_V4_URL")
        if not apiUrl:
            apiUrl = "https://gitlab.com/api/v4"
        return {
            **repo_context,
            "apiUrl": apiUrl,
            "mergeRequestIID": os.getenv("CI_MERGE_REQUEST_IID"),
            "mergeRequestProjectId": os.getenv("CI_MERGE_REQUEST_PROJECT_ID"),
            "mergeRequestSourceBranch": os.getenv(
                "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
            ),
            "mergeRequestTargetBranch": os.getenv(
                "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
            ),
            "commitSHA": os.getenv("CI_COMMIT_SHA"),
            "projectId": os.getenv("CI_PROJECT_ID"),
            "projectName": os.getenv("CI_PROJECT_NAME"),
            "projectUrl": os.getenv("CI_PROJECT_URL"),
            "jobUrl": os.getenv("CI_JOB_URL"),
            "jobId": os.getenv("CI_JOB_ID"),
            "jobName": os.getenv("CI_JOB_NAME"),
            # CI_JOB_TOKEN is only available to Silver/Enterprise plan of GitLab
            "jobToken": os.getenv("CI_JOB_TOKEN"),
        }

    def get_mr_notes_url(self, repo_context):
        gitlab_context = self.get_context(repo_context)
        return f"""{gitlab_context.get("apiUrl")}/projects/{gitlab_context.get("mergeRequestProjectId")}/merge_requests/{gitlab_context.get("mergeRequestIID")}/notes"""

    def annotate_pr(self, repo_context, findings_file, report_summary, build_status):
        if not findings_file:
            if not list(filter(lambda x: "depscan" in x, report_summary)):
                return
        else:
            with open(findings_file, mode="r") as fp:
                findings_obj = json.load(fp)
                findings = findings_obj.get("findings")
                if not findings:
                    LOG.debug("No findings from scan available to report")
                    return
        try:
            gitlab_context = self.get_context(repo_context)
            if not gitlab_context.get("mergeRequestIID") or not gitlab_context.get(
                "mergeRequestProjectId"
            ):
                LOG.debug(
                    "Scan is not running as part of a merge request. Check if the pipeline is using only: [merge_requests] or rules syntax"
                )
                return
            private_token = self.get_token()
            if not private_token:
                LOG.info(
                    "To create a merge request note, create a personal access token with api scope and set it as GITLAB_TOKEN environment variable"
                )
                return
            summary = "| Tool | Critical | High | Medium | Low | Status |\n"
            summary = (
                summary + "| ---- | ------- | ------ | ----- | ---- | ---- |\n"
            )
            for rk, rv in report_summary.items():
                status_emoji = self.to_emoji(rv.get("status"))
                summary = f'{summary}| {rv.get("tool")} | {rv.get("critical")} | {rv.get("high")} | {rv.get("medium")} | {rv.get("low")} | {status_emoji} |\n'
            template = config.get("PR_COMMENT_TEMPLATE")
            recommendation = (
                f"Please review the [scan reports]({gitlab_context.get('jobUrl')}/artifacts/browse/reports) before approving this merge request."
                if build_status == "fail"
                else "Looks good"
            )
            apiUrl = f"{gitlab_context.get('apiUrl')}"
            mergeRequestIID = f"{gitlab_context.get('mergeRequestIID')}"
            mergeRequestProjectId = f"{gitlab_context.get('mergeRequestProjectId')}"
            mergeRequestSourceBranch = (
                f"{gitlab_context.get('mergeRequestSourceBranch')}"
            )
            mergeRequestTargetBranch = (
                f"{gitlab_context.get('mergeRequestTargetBranch')}"
            )
            commitSHA = f"{gitlab_context.get('commitSHA')}"
            projectId = f"{gitlab_context.get('projectId')}"
            projectName = f"{gitlab_context.get('projectName')}"
            projectUrl = f"{gitlab_context.get('projectUrl')}"
            jobUrl = f"{gitlab_context.get('jobUrl')}"
            jobId = f"{gitlab_context.get('jobId')}"
            jobName = f"{gitlab_context.get('jobName')}"
            jobToken = f"{gitlab_context.get('jobToken')}"

            body = template % dict(
                summary=summary,
                recommendation=recommendation,
                apiUrl=apiUrl,
                mergeRequestIID=mergeRequestIID,
                mergeRequestProjectId=mergeRequestProjectId,
                mergeRequestSourceBranch=mergeRequestSourceBranch,
                mergeRequestTargetBranch=mergeRequestTargetBranch,
                commitSHA=commitSHA,
                projectId=projectId,
                projectName=projectName,
                projectUrl=projectUrl,
                jobUrl=jobUrl,
                jobId=jobId,
                jobName=jobName,
                jobToken=jobToken,
            )
            rr = requests.post(
                self.get_mr_notes_url(repo_context),
                headers={
                    "Content-Type": "application/json",
                    "PRIVATE-TOKEN": self.get_token(),
                },
                json={"body": body},
            )
            if not rr.ok:
                LOG.debug(rr.json())
        except Exception as e:
            LOG.debug(e)
