from lib.integration import github


def test_context():
    context = github.GitHub().get_context({"foo": "bar"})
    assert context["foo"] == "bar"
