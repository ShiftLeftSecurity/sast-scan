import lib.utils as utils


def test_get_workspace():
    d = utils.get_workspace(
        {"repositoryUri": "https://github.com/AppThreat/WebGoat", "branch": "develop"}
    )
    assert d == "https://github.com/AppThreat/WebGoat/blob/develop"
    d = utils.get_workspace({"repositoryUri": "", "branch": "develop"})
    assert not d
    d = utils.get_workspace(
        {
            "repositoryUri": "https://gitlab.com/prabhu3/helloshiftleft",
            "branch": "develop",
        }
    )
    assert d == "https://gitlab.com/prabhu3/helloshiftleft/-/blob/develop"
    d = utils.get_workspace(
        {
            "repositoryUri": "https://gitlab.com/prabhu3/helloshiftleft",
            "branch": "",
            "revisionId": "fd302c3938a3c58908839ceaf48c2ce8176353f0",
        }
    )
    assert (
        d
        == "https://gitlab.com/prabhu3/helloshiftleft/-/blob/fd302c3938a3c58908839ceaf48c2ce8176353f0"
    )
    d = utils.get_workspace(
        {
            "repositoryUri": "https://dev.azure.com/appthreat/aio",
            "branch": "develop",
            "revisionId": "fd302c3938a3c58908839ceaf48c2ce8176353f0",
        }
    )
    assert (
        d == "https://dev.azure.com/appthreat/aio?_a=contents&version=GBdevelop&path="
    )
