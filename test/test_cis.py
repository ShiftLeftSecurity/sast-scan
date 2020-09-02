from lib.cis import get_k8s_rules, get_rule


def test_k8s_all():
    data = get_k8s_rules()
    assert data


def test_k8s_rule():
    data = get_rule("DefaultServiceAccount")
    assert data
