import os

from lib.issue import Issue


def test_get_code():
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    source_file = os.path.join(curr_dir, "data", "issue-259.php")
    issue = Issue(lineno=12)
    issue.fname = source_file
    text = issue.get_code()
    assert text == "11 \tpublic function test_convert_to_utf8()\n12 \t{\n"
