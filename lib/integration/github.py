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

from github import Github as GitHubLib

import lib.config as config
from lib.integration import GitProvider
from lib.logger import LOG

g = None
if os.getenv("GITHUB_TOKEN"):
    g = GitHubLib(os.getenv("GITHUB_TOKEN"))


class GitHub(GitProvider):
    def get_context(self, repo_context):
        return {
            **repo_context,
            "repoWorkspace": os.getenv("GITHUB_WORKSPACE"),
            "runID": os.getenv("GITHUB_RUN_ID"),
            "repoFullname": os.getenv("GITHUB_REPOSITORY"),
            "triggerEvent": os.getenv("GITHUB_EVENT_NAME"),
            "apiUrl": os.getenv("GITHUB_API_URL"),
            "headRef": os.getenv("GITHUB_HEAD_REF"),
            "baseRef": os.getenv("GITHUB_BASE_REF"),
            "githubToken": os.getenv("GITHUB_TOKEN"),
        }

    def get_workflow(self, github_context):
        if not github_context.get("repoFullname") or not github_context.get("runID"):
            return
        repo = g.get_repo(github_context.get("repoFullname"))
        runID = github_context.get("runID")
        if runID and runID.isdigit():
            runID = int(runID)
        return repo.get_workflow_run(runID)

    def create_status(self, findings, github_context, report_summary, build_status):
        revisionId = github_context.get("revisionId")
        if not github_context.get("repoFullname") or not revisionId:
            return
        repoFullname = github_context.get("repoFullname")
        repo = g.get_repo(repoFullname)
        total_count = len(findings)
        target_url = "https://slscan.io"
        runID = github_context.get("runID")
        if runID:
            target_url = f"https://github.com/{repoFullname}/actions/runs/{runID}"
        repo.get_commit(revisionId).create_status(
            state="success",
            target_url=target_url,
            description=f"Scan has identified {total_count} issues"
            if build_status == "fail"
            else "No issues found by scan",
            context="Scan / Summary",
        )

    def create_review(
        self, pull_requests, findings, github_context, report_summary, build_status
    ):
        repo = g.get_repo(github_context.get("repoFullname"))
        for pr in pull_requests:
            revisionId = github_context.get("revisionId")
            summary = "| Tool | Critical | High | Medium | Low | Status |\n"
            summary = summary + "| ---- | ------- | ------ | ----- | ---- | ---- |\n"
            for rk, rv in report_summary.items():
                summary = f'{summary}| {rv.get("tool")} | {rv.get("critical")} | {rv.get("high")} | {rv.get("medium")} | {rv.get("low")} | {rv.get("status")} |\n'
            template = config.get("PR_COMMENT_TEMPLATE")
            recommendation = (
                """Please review the findings from Code scanning alerts before approving this pull request. You can also configure the [build rules](https://slscan.io/en/latest/integrations/tips/#config-file) or add [suppressions](https://slscan.io/en/latest/getting-started/#suppression) to customize this bot :+1:"""
                if build_status == "fail"
                else "Looks good :heavy_check_mark:"
            )
            body = template % dict(summary=summary, recommendation=recommendation)
            exis_reviews = pr.get_reviews()
            review_comment_made = False
            if exis_reviews:
                for ereview in exis_reviews:
                    if ereview.body == body:
                        review_comment_made = True
            # Only make one comment at any time
            if not review_comment_made:
                pr.create_review(
                    commit=repo.get_commit((revisionId)), body=body, event="COMMENT"
                )
            if build_status == "fail":
                pr.add_to_labels("security findings")
            else:
                pr.remove_from_labels("security findings")

    def annotate_pr(self, repo_context, findings_file, report_summary, build_status):
        if not findings_file:
            return
        with open(findings_file, mode="r") as fp:
            try:
                github_context = self.get_context(repo_context)
                findings_obj = json.load(fp)
                findings = findings_obj.get("findings")
                if not findings:
                    LOG.debug("No findings from scan available to report")
                if not github_context.get("githubToken") or not g:
                    LOG.debug("Did not receive GITHUB_TOKEN")
                    return
                self.create_status(
                    findings, github_context, report_summary, build_status
                )
                workflow_run = self.get_workflow(github_context)
                if not workflow_run:
                    LOG.debug("Unable to find the workflow run for this invocation")
                    return
                pull_requests = workflow_run.pull_requests
                if not pull_requests:
                    LOG.debug("No Pull Requests are associated with this workflow run")
                    return
                if findings:
                    self.create_review(
                        pull_requests,
                        findings,
                        github_context,
                        report_summary,
                        build_status,
                    )
            except Exception as e:
                LOG.debug(e)
