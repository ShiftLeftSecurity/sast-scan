import lib.pyt.vulnerabilities.insights as insights
from lib.pyt.core.ast_helper import generate_ast_from_code


def test_pymongo_insights():
    tree = generate_ast_from_code(
        """
import pymongo
import ssl

client = pymongo.MongoClient()
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert len(violations) == 2

    tree = generate_ast_from_code(
        """
import pymongo
import ssl

client = pymongo.MongoClient('example.com', ssl=False, ssl_cert_reqs=ssl.CERT_NONE)
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert len(violations) == 3

    tree = generate_ast_from_code(
        """
import pymongo
import ssl

client = pymongo.MongoClient('mongodb://example.com/?ssl=true')
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert len(violations) == 1

    tree = generate_ast_from_code(
        """
from pymongo import MongoClient
import ssl

client = MongoClient('mongodb://example.com/?ssl=true')
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert len(violations) == 1

    tree = generate_ast_from_code(
        """
import pymongo
import ssl
from pymongo.encryption import (Algorithm,
                                ClientEncryption)
from pymongo.encryption_options import AutoEncryptionOpts

client = pymongo.MongoClient('mongodb://example.com/?ssl=true')
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert len(violations) == 1

    tree = generate_ast_from_code(
        """
import pymongo
import ssl
from pymongo.encryption import (Algorithm,
                                ClientEncryption)
from pymongo.encryption_options import AutoEncryptionOpts

client = pymongo.MongoClient('mongodb://example.com/?ssl=true')

client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        coll.codec_options)
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert not violations

    tree = generate_ast_from_code(
        """
import pymongo
import ssl
from pymongo.encryption import (Algorithm,
                                ClientEncryption)
from pymongo.encryption_options import AutoEncryptionOpts

client = MongoClient('example.com',
                      username='user',
                      password='password',
                      authMechanism='MONGODB-CR')

client_encryption = ClientEncryption(
        kms_providers,
        key_vault_namespace,
        client,
        coll.codec_options)
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert len(violations) == 1


def test_django_insights():
    tree = generate_ast_from_code(
        """
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app.apps.AppConfig',
    'bootstrap4',
    'fullcalendar',
]

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'app.middleware.AnalyticsStorageMiddleware'
]
    """
    )
    violations = insights._check_django_common_misconfig(tree, "/tmp/settings.py")
    assert violations
    msg_found = False
    for v in violations:
        if "security middleware" in v.short_description:
            msg_found = True
            break
    assert msg_found

    tree = generate_ast_from_code(
        """
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'app.apps.AppConfig',
    'bootstrap4',
    'fullcalendar',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'app.middleware.AnalyticsStorageMiddleware'
]
    """
    )
    violations = insights._check_django_common_misconfig(tree, "/tmp/settings.py")
    assert violations
    msg_found = False
    for v in violations:
        if "CSRF protection" in v.short_description:
            msg_found = True
            break
    assert msg_found


def test_flask_insights():
    tree = generate_ast_from_code(
        """
from flask import Flask, render_template_string, make_response, request
app = Flask(__name__)


@app.route('/')
def index():
    context = {'title': '<h1>Hello!</h1>', 'body': '<p>No Body here :(</p>'}
    resp = make_response(render_template_string(template))
    return resp


if __name__ == '__main__':
    app.run()        
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "SESSION_COOKIE_SECURE" in v.short_description:
            msg_found = True
            break
    assert msg_found

    tree = generate_ast_from_code(
        """
from flask import Flask, render_template_string, make_response, request
app = Flask(__name__)
app.config.from_file('config.toml', toml.load)

@app.route('/')
def index():
    context = {'title': '<h1>Hello!</h1>', 'body': '<p>No Body here :(</p>'}
    resp = make_response(render_template_string(template))
    return resp


if __name__ == '__main__':
    app.run()        
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "SESSION_COOKIE_SECURE" in v.short_description:
            msg_found = True
            break
    assert not msg_found

    tree = generate_ast_from_code(
        """
from flask import Flask, render_template_string, make_response, request
app = Flask(__name__)
config = app.config
config.from_json('config.toml', toml.load)

@app.route('/')
def index():
    context = {'title': '<h1>Hello!</h1>', 'body': '<p>No Body here :(</p>'}
    resp = make_response(render_template_string(template))
    return resp


if __name__ == '__main__':
    app.run()        
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "SESSION_COOKIE_SECURE" in v.short_description:
            msg_found = True
            break
    assert not msg_found

    tree = generate_ast_from_code(
        """
from flask import Flask, render_template_string, make_response, request
app = Flask(__name__)
config = app.config
app.config.from_pyfile('production.cfg')

@app.route('/')
def index():
    context = {'title': '<h1>Hello!</h1>', 'body': '<p>No Body here :(</p>'}
    resp = make_response(render_template_string(template))
    return resp


if __name__ == '__main__':
    app.run()        
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "PREFERRED_URL_SCHEME" in v.short_description:
            msg_found = True
            break
    assert not msg_found

    tree = generate_ast_from_code(
        """
from flask import Flask, render_template_string, make_response, request
app = Flask(__name__)
config = app.config
app.config.from_pyfile('production.cfg')

@app.route('/')
def index():
    context = {'title': '<h1>Hello!</h1>', 'body': '<p>No Body here :(</p>'}
    resp = make_response(render_template_string(template))
    resp.headers['X-XSS-Protection'] = 0  # for demo purposes >:)
    return resp


if __name__ == '__main__':
    app.run()
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "XSS protection" in v.short_description:
            msg_found = True
            break
    assert msg_found
