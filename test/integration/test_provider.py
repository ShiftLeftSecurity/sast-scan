from lib.integration import bitbucket, gitlab, provider


def test_get():
    prov = provider.get_git_provider({})
    assert not prov
    prov = provider.get_git_provider({"gitProvider": "bitbucket"})
    assert prov
    assert isinstance(prov, bitbucket.Bitbucket)
    prov = provider.get_git_provider({"gitProvider": "gitlab"})
    assert prov
    assert isinstance(prov, gitlab.GitLab)
