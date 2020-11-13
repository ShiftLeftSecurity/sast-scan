import os

from lib.integration import bitbucket


def test_context():
    os.environ["BITBUCKET_REPO_OWNER"] = "test"
    os.environ["BITBUCKET_WORKSPACE"] = "foo"
    os.environ["BITBUCKET_REPO_UUID"] = "uuid123"
    os.environ["BITBUCKET_REPO_FULL_NAME"] = "test/bar"
    os.environ["BITBUCKET_PR_ID"] = "pr-123"
    os.environ["BITBUCKET_PR_DESTINATION_BRANCH"] = "main"
    context = bitbucket.Bitbucket().get_context({"foo": "bar"})
    assert context["foo"] == "bar"


def test_reports_url():
    url = bitbucket.Bitbucket().get_reports_url(
        {"repositoryName": "bar", "revisionId": "123", "repoFullname": "test/bar"}
    )
    assert (
        url
        == "http://api.bitbucket.org/2.0/repositories/test/bar/commit/123/reports/shiftleft-scan"
    )


def test_pr_comments_url():
    url = bitbucket.Bitbucket().get_pr_comments_url(
        {
            "repositoryName": "bar",
            "revisionId": "123",
            "prID": "pr-123",
            "repoFullname": "test/bar",
        }
    )
    assert (
        url
        == "https://api.bitbucket.org/2.0/repositories/test/bar/pullrequests/pr-123/comments"
    )


def test_emoji():
    emoji = bitbucket.Bitbucket().to_emoji("foo")
    assert emoji == "foo"
    emoji = bitbucket.Bitbucket().to_emoji(":white_heavy_check_mark:")
    assert emoji == "✅"
    emoji = bitbucket.Bitbucket().to_emoji(":cross_mark:")
    assert emoji == "❌"
