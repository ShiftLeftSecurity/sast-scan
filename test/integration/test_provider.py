from lib.integration import provider, bitbucket


def test_get():
    prov = provider.get_git_provider({})
    assert not prov
    prov = provider.get_git_provider({"gitProvider": "bitbucket"})
    assert prov
    assert isinstance(prov, bitbucket.Bitbucket)
