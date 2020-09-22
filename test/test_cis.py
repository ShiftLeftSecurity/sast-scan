from lib.cis import get_cis_rules, get_rule


def test_k8s_all():
    data = get_cis_rules()
    assert data


def test_k8s_rule():
    data = get_rule("DefaultServiceAccount")
    assert data


def test_aws_rule():
    data = get_rule("SecurityGroupUnrestrictedIngress22")
    assert data
