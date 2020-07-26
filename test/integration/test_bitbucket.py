import os

from lib.integration import bitbucket


def test_context():
    os.environ["BITBUCKET_REPO_OWNER"] = "test"
    context = bitbucket.Bitbucket().get_context({"foo": "bar"})
    assert context == {"foo": "bar", "repoOwner": "test"}


def test_reports_url():
    url = bitbucket.Bitbucket().get_reports_url(
        {"repositoryName": "bar", "revisionId": "123"}
    )
    assert (
        url
        == "http://api.bitbucket.org/2.0/repositories/test/bar/commit/123/reports/shiftleft-scan"
    )
