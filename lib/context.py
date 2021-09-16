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

import os
from urllib.parse import urlparse

from git import Repo

from lib.config import known_bot_users
from lib.logger import LOG

repo_url_prefixes = ["http", "git", "ssh"]


def find_repo_details(src_dir=None):
    """Method to find repo details such as url, sha etc
    This will be populated into versionControlProvenance attribute

    :param src_dir: Source directory
    """
    # See if repository uri is specified in the config
    repositoryName = None
    repositoryUri = ""
    revisionId = ""
    branch = ""
    invokedBy = ""
    pullRequest = False
    gitProvider = ""
    ciProvider = ""
    """
    Since CI servers typically checkout repo in detached mode, we need to rely on environment
    variables as a starting point to find the repo details. To make matters worse, since we
    run the tools inside a container these variables should be passed as part of the docker run
    command. With native integrations such as GitHub action and cloudbuild this could be taken
    care by our builders.

    Env variables detection for popular CI server is implemented here anyways. But they are effective
    only in few cases.

    Azure pipelines - https://docs.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml
    BitBucket - https://confluence.atlassian.com/bitbucket/environment-variables-in-bitbucket-pipelines-794502608.html
    GitHub actions - https://help.github.com/en/actions/automating-your-workflow-with-github-actions/using-environment-variables
    Google CloudBuild - https://cloud.google.com/cloud-build/docs/configuring-builds/substitute-variable-values
    CircleCI - https://circleci.com/docs/2.0/env-vars/#built-in-environment-variables
    Travis - https://docs.travis-ci.com/user/environment-variables/#default-environment-variables
    AWS CodeBuild - https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html
    GitLab - https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
    Jenkins - https://jenkins.io/doc/book/pipeline/jenkinsfile/#using-environment-variables
    """
    for key, value in os.environ.items():
        # Check REPOSITORY_URL first followed CI specific vars
        # Some CI such as GitHub pass only the slug instead of the full url :(
        if not gitProvider or not ciProvider:
            if key.startswith("GITHUB_"):
                if key == "GITHUB_REPOSITORY":
                    gitProvider = "github"
                if key == "GITHUB_ACTION":
                    ciProvider = "github"
            elif key.startswith("GITLAB_"):
                gitProvider = "gitlab"
                if key == "GITLAB_CI":
                    ciProvider = "gitlab"
            elif key.startswith("BITBUCKET_"):
                gitProvider = "bitbucket"
                if key == "BITBUCKET_BUILD_NUMBER":
                    ciProvider = "bitbucket"
            elif key.startswith("CIRCLE_"):
                ciProvider = "circle"
            elif key.startswith("TRAVIS_"):
                ciProvider = "travis"
            elif key.startswith("CODEBUILD_"):
                ciProvider = "codebuild"
            elif key.startswith("BUILD_REQUESTEDFOREMAIL"):
                ciProvider = "azure"
            elif key.startswith("JENKINS_"):
                ciProvider = "jenkins"
        if not repositoryName:
            if key in [
                "BUILD_REPOSITORY_NAME",
                "GITHUB_REPOSITORY",
                "BITBUCKET_REPO_SLUG",
                "REPO_NAME",
                "CIRCLE_PROJECT_REPONAME",
                "TRAVIS_REPO_SLUG",
                "CI_PROJECT_NAME",
            ]:
                if "/" in value:
                    repositoryName = value.split("/")[-1]
                else:
                    repositoryName = value
        if not repositoryUri:
            if key in [
                "REPOSITORY_URL",
                "BUILD_REPOSITORY_URI",
                "GITHUB_REPOSITORY",
                "BITBUCKET_GIT_HTTP_ORIGIN",
                "REPO_NAME",
                "CIRCLE_REPOSITORY_URL",
                "TRAVIS_REPO_SLUG",
                "CODEBUILD_SOURCE_REPO_URL",
                "CI_REPOSITORY_URL",
            ]:
                repositoryUri = value
        if key in [
            "COMMIT_SHA",
            "BUILD_SOURCEVERSION",
            "BITBUCKET_COMMIT",
            "GITHUB_SHA",
            "CIRCLE_SHA1",
            "TRAVIS_COMMIT",
            "CODEBUILD_SOURCE_VERSION",
            "CI_COMMIT_SHA",
        ]:
            revisionId = value
        if key in [
            "BRANCH",
            "BUILD_SOURCEBRANCH",
            "BITBUCKET_BRANCH",
            "GITHUB_REF",
            "BRANCH_NAME",
            "CIRCLE_BRANCH",
            "TRAVIS_BRANCH",
            "CI_COMMIT_REF_NAME",
        ]:
            branch = value
        if key in [
            "BUILD_REQUESTEDFOREMAIL",
            "GITHUB_ACTOR",
            "PROJECT_ID",
            "CIRCLE_USERNAME",
            "GITLAB_USER_EMAIL",
        ]:
            invokedBy = value
        if key.startswith("CI_MERGE_REQUEST"):
            pullRequest = True
    if src_dir and os.path.isdir(os.path.join(src_dir, ".git")):
        # Try interacting with git
        try:
            repo = Repo(src_dir)
            head = repo.head
            if not branch and not head.is_detached:
                branch = repo.active_branch.name
            if not revisionId and head:
                revisionId = head.commit.hexsha
            if not repositoryUri:
                repositoryUri = next(iter(repo.remote().urls))
            if not invokedBy or "@" not in invokedBy:
                if head and head.commit.author and head.commit.author.email:
                    invokedBy = "{} <{}>".format(
                        head.commit.author.name, head.commit.author.email
                    )
        except Exception:
            LOG.debug("Unable to find repo details from the local repository")
    if branch.startswith("refs/pull"):
        pullRequest = True
        branch = branch.replace("refs/pull/", "")
    # Cleanup the variables
    branch = branch.replace("refs/heads/", "")
    if repositoryUri:
        githubServerUrl = os.getenv("GITHUB_SERVER_URL", "https://github.com/")
        if not githubServerUrl.endswith("/"):
            githubServerUrl += "/"
        repositoryUri = repositoryUri.replace(
            "git@{}:".format(urlparse(githubServerUrl).netloc), githubServerUrl
        ).replace(".git", "")
        # Is it a repo slug?
        repo_slug = True
        repositoryUri = sanitize_url(repositoryUri)
        for pref in repo_url_prefixes:
            if repositoryUri.startswith(pref):
                repo_slug = False
                break
        if not repo_slug:
            if "vs-ssh" in repositoryUri:
                repo_slug = False
        # For repo slug just assume github for now
        if repo_slug:
            repositoryUri = githubServerUrl + repositoryUri
    if not repositoryName and repositoryUri:
        repositoryName = os.path.basename(repositoryUri)
    if not gitProvider:
        if "github" in repositoryUri:
            gitProvider = "github"
        if "gitlab" in repositoryUri:
            gitProvider = "gitlab"
        if "atlassian" in repositoryUri or "bitbucket" in repositoryUri:
            gitProvider = "bitbucket"
        if "azure" in repositoryUri or "visualstudio" in repositoryUri:
            gitProvider = "azure"
            if not ciProvider:
                ciProvider = "azure"
        if not gitProvider and "tfs" in repositoryUri:
            gitProvider = "tfs"
            ciProvider = "tfs"
    return {
        "gitProvider": gitProvider,
        "ciProvider": ciProvider,
        "repositoryName": "" if not repositoryName else repositoryName,
        "repositoryUri": repositoryUri,
        "revisionId": revisionId,
        "branch": branch,
        "invokedBy": invokedBy,
        "pullRequest": pullRequest,
        "botUser": is_bot(invokedBy),
    }


def sanitize_url(url):
    """
    Method to sanitize url to remove credentials and tokens

    :param url: URL to sanitize
    :return: sanitized url
    """
    result = urlparse(url)
    username = result.username
    password = result.password
    sens_str = ""
    if username and password:
        sens_str = "{}:{}@".format(username, password)
    url = url.replace(sens_str, "")
    if password:
        url = url.replace(password, "")
    return url


def is_bot(invokedBy):
    """
    Method to check if the user triggering this build is a known bot user

    :param invokedBy: Invoking user (str)
    :return: True if bot user. False otherwise.
    """
    for bu in known_bot_users:
        if bu in invokedBy:
            return True
    return False
