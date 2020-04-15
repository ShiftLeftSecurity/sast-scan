from lib.cwe import get, get_description


def test_cwe_get():
    data = get("cwe-115")
    assert data
    assert (
        data["Description"]
        == "The software misinterprets an input, whether from an attacker or another product, in a security-relevant fashion."
    )
    assert data["Extended Description"] == ""


def test_cwe_get_desc():
    data = get_description("cwe-78")
    assert data
