import logging
import os

from git import Repo

import lib.config as config

LOG = logging.getLogger(__name__)


def find_repo_details(src_dir=None):
    """Method to find repo details such as url, sha etc
    This will be populated into versionControlProvenance attribute

    :param src_dir: Source directory
    """
    # See if repository uri is specified in the config
    repositoryUri = config.get("repository_uri", "")
    revisionId = ""
    branch = ""
    """
    Since CI servers typically checkout repo in detached mode, we need to rely on environment
    variables as a starting point to find the repo details. To make matters worse, since we
    run the tools inside a container these variables should be passed as part of the docker run
    command. With native integrations such as GitHub action and cloudbuild this could be taken
    care by our builders.

    Env variables detection for popular CI server is implemented here anyways. But they are effective
    only in few cases.

    Azure pipelines - https://docs.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml
    GitHub actions - https://help.github.com/en/actions/automating-your-workflow-with-github-actions/using-environment-variables
    Google CloudBuild - https://cloud.google.com/cloud-build/docs/configuring-builds/substitute-variable-values
    CircleCI - https://circleci.com/docs/2.0/env-vars/#built-in-environment-variables
    Travis - https://docs.travis-ci.com/user/environment-variables/#default-environment-variables
    AWS CodeBuild - https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html
    """
    for key, value in os.environ.items():
        # Check REPOSITORY_URL first followed CI specific vars
        # Some CI such as GitHub pass only the slug instead of the full url :(
        if not repositoryUri:
            if key in [
                "REPOSITORY_URL",
                "BUILD_REPOSITORY_URI",
                "GITHUB_REPOSITORY",
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
            "GITHUB_REF",
            "BRANCH_NAME",
            "CIRCLE_BRANCH",
            "TRAVIS_BRANCH",
            "CI_COMMIT_BRANCH",
        ]:
            branch = value
    if src_dir and os.path.isdir(os.path.join(src_dir, ".git")):
        # Try interacting with git
        try:
            repo = Repo(src_dir)
            if not branch:
                branch = repo.active_branch.name
            if not revisionId:
                head = repo.heads[0]
                revisionId = head.commit.hexsha
            if not repositoryUri:
                repositoryUri = next(iter(repo.remote().urls))
        except Exception:
            LOG.debug(
                "Unable to find repo details from the local repository. Consider adding a local .sastscanrc file with the url details."
            )

    # Cleanup the variables
    branch = branch.replace("refs/heads/", "")
    if repositoryUri:
        repositoryUri = repositoryUri.replace(
            "git@github.com:", "https://github.com/"
        ).replace(".git", "")
        # Is it a repo slug?
        if not repositoryUri.startswith("http"):
            repositoryUri = "https://github.com/" + repositoryUri
    return {"repositoryUri": repositoryUri, "revisionId": revisionId, "branch": branch}
