import os

import lib.context as context


def test_find_repo():
    curr_rep_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
    repo_details = context.find_repo_details(curr_rep_dir)
    assert len(repo_details.keys()) == 3
