import os

from lib.pyt.analysis.constraint_table import initialize_constraint_table
from lib.pyt.analysis.fixed_point import analyse
from lib.pyt.cfg import make_cfg
from lib.pyt.core.ast_helper import generate_ast_from_code
from lib.pyt.vulnerabilities import find_vulnerabilities
from lib.pyt.web_frameworks import FrameworkAdaptor, is_taintable_function

default_blackbox_mapping_file = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "lib",
    "pyt",
    "vulnerability_definitions",
    "blackbox_mapping.json",
)


default_trigger_word_file = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "lib",
    "pyt",
    "vulnerability_definitions",
    "all_sources_sinks.pyt",
)


def ret_vulnerabilities(tree, cfg_list):
    cfg = make_cfg(tree, None, None, "", allow_local_directory_imports=True)
    cfg_list = [cfg]
    FrameworkAdaptor(cfg_list, None, None, is_taintable_function)
    initialize_constraint_table(cfg_list)
    analyse(cfg_list)
    return find_vulnerabilities(
        cfg_list, default_blackbox_mapping_file, default_trigger_word_file
    )


def test_data_leak_sinks_1():
    cfg_list = []
    tree = generate_ast_from_code(
        """
from flask import Flask, request, redirect

app = Flask(__name__)

SECRET_STRING = '<secret-value>'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "")

def log(thing: str):
    print(thing)


@app.route('/')
def index():
    cookie = request.cookies.get('MyCookie')
    if cookie != SECRET_STRING:
        return redirect('/login')
    # Pretend this is a log
    log(cookie)
    return 'You made it!'


@app.route('/login', methods=['POST'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    log(password)
    resp = redirect('/')
    if username == 'admin' and password == 'password':
        # One minute long session
        resp.headers['Set-Cookie'] = f'MyCookie={SECRET_STRING}; Max-Age=60'
    return resp


if __name__ == '__main__':
    app.run()
        """
    )
    vulnerabilities = ret_vulnerabilities(tree, cfg_list)
    assert vulnerabilities
