import os

import lib.context as context


def test_find_repo():
    curr_rep_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
    repo_details = context.find_repo_details(curr_rep_dir)
    assert len(repo_details.keys()) == 3


def test_env_detection():
    os.environ["BUILD_REPOSITORY_URI"] = "https://foo.com/bar"
    os.environ["BUILD_SOURCEVERSION"] = "123"
    os.environ["BUILD_SOURCEBRANCH"] = "develop"

    repo_details = context.find_repo_details(None)
    assert repo_details["repositoryUri"] == "https://foo.com/bar"
    assert repo_details["revisionId"] == "123"
    assert repo_details["branch"] == "develop"
