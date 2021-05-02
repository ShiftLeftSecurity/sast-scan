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


def test_pymongo_insights1():
    tree = generate_ast_from_code(
        """
from pymongo import MongoClient
client = MongoClient('mongodb://example.com/?ssl=true')
    """
    )
    violations = insights._check_pymongo_common_misconfig(tree, None)
    assert len(violations) == 1


def test_pymongo_insights2():
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

MIDDLEWARE_CLASSES = [
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
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

# A2: Broken Auth and Session Management
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
    """
    )
    violations = insights._check_django_common_misconfig(tree, "/tmp/settings.py")
    assert violations
    msg_found = False
    for v in violations:
        if "signed_cookies" in v.short_description:
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

DEBUG_TOOLBAR_CONFIG = {
        'SHOW_TOOLBAR_CALLBACK': 'badguys.settings.show_toolbar'
}
    """
    )
    violations = insights._check_django_common_misconfig(tree, "/tmp/settings.py")
    assert violations
    msg_found = False
    for v in violations:
        if "django-debug-toolbar" in v.short_description:
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
    jwt_found = False
    for v in violations:
        if "SESSION_COOKIE_SECURE" in v.short_description:
            msg_found = True
        if "JWT_ALGORITHM" in v.short_description:
            jwt_found = True
    assert not msg_found
    assert not jwt_found

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

    tree = generate_ast_from_code(
        """
from flask import Flask, render_template_string, make_response, request

def create_app():
    app = Flask(__name__)
    app.secret_key = "aeZ1iwoh2ree2mo0Eer"


if __name__ == '__main__':
    app.run()
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "Security Misconfiguration" in v.short_description:
            msg_found = True
            break
    assert msg_found


def test_flask_jwt_insights():
    tree = generate_ast_from_code(
        """
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)


# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    if username != 'test' or password != 'test':
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200


# Protect a view with jwt_required, which requires a valid access token
# in the request to access.
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run()
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    rec_found = False
    for v in violations:
        if "JWT_ALGORITHM" in v.short_description:
            msg_found = True
        if "asymmetric RSA based algorithm" in v.short_description:
            rec_found = True
    assert msg_found
    assert rec_found
    tree = generate_ast_from_code(
        """
from flask import session, Flask
import jwt

decoded = jwt.decode(token, verify = False)
decoded2 = jwt.decode(token, app.config['SECRET_KEY_HMAC'], verify=True, issuer = 'we45', leeway=10, algorithms=['HS256'])
"""
    )
    violations = insights._check_flask_common_misconfig(tree, None)
    assert violations
    msg_found = False
    rec_found = False
    for v in violations:
        if "Security Misconfiguration" in v.short_description:
            msg_found = True
        if "asymmetric RSA based algorithm" in v.short_description:
            rec_found = True
    assert msg_found
    assert rec_found


def test_timing_insights():
    tree = generate_ast_from_code(
        """
def authenticate(username, password):
    user = username_table.get(username, None)
    if user and user.password == password:
        return user
        """
    )
    violations = insights._check_timing_attack(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "timing attacks" in v.short_description:
            msg_found = True
            break
    assert msg_found

    tree = generate_ast_from_code(
        """
def authenticate(username, token):
    user = username_table.get(username, None)
    if user and access_token == remote.access_token:
        return user
        """
    )
    violations = insights._check_timing_attack(tree, None)
    assert violations
    msg_found = False
    for v in violations:
        if "timing attacks" in v.short_description:
            msg_found = True
            break
    assert msg_found


def test_fastapi_insights():
    tree = generate_ast_from_code(
        """
from fastapi import Depends, FastAPI

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user
        """
    )
    violations = insights._check_fastapi_misconfig(tree, None)
    assert violations
    msg_found = False
    misconfig_found = False
    for v in violations:
        if "FastAPI security middleware" in v.short_description:
            msg_found = True
        if "Security Misconfiguration" in v.short_description:
            misconfig_found = True
    assert msg_found and misconfig_found

    tree = generate_ast_from_code(
        """
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/users")
def read_users():
    users = session.query(UserTable).all()
    return users
        """
    )
    violations = insights._check_fastapi_misconfig(tree, None)
    assert violations
    msg_found = False
    misconfig_found = False
    creds_found = False
    for v in violations:
        if "FastAPI security middleware" in v.short_description:
            msg_found = True
        if "origins allowed" in v.short_description:
            misconfig_found = True
        if "allowed credentials" in v.short_description:
            creds_found = True
    assert msg_found and misconfig_found and creds_found


def test_django_settings_contrib():
    tree = generate_ast_from_code(
        """
DB_HOSTS = ["host.docker.internal" if STAGING or PRODUCTION else "minidb" if MINI_DB else "db"]
"""
    )
    violations = insights._check_django_common_misconfig(tree, "settings.py")
    assert not violations


def test_aiohttp_insights():
    tree = generate_ast_from_code(
        """
from aiohttp.web import Application
from aiohttp_jinja2 import setup as setup_jinja

app = Application(
    debug=True,
    middlewares=[
        session_middleware,
        error_middleware,
    ]
)
app['config'] = config
setup_jinja(app, loader=PackageLoader('sqli', 'templates'),
    context_processors=[csrf_processor, auth_user_processor],
    autoescape=False)
        """
    )
    violations = insights._check_aiohttp_common_misconfig(tree, "app.py")
    assert violations
    msg_found = False
    esc_found = False
    for v in violations:
        if "csrf_middleware" in v.short_description:
            msg_found = True
        if "Jinja autoescape" in v.short_description:
            esc_found = True
    assert msg_found and esc_found


def test_aioredis_insights():
    tree = generate_ast_from_code(
        """
import asyncio
import aioredis


async def main():
    redis = await aioredis.create_redis_pool('redis://localhost')
    await redis.set('my-key', 'value')
    """
    )
    violations = insights._check_aioredis_common_misconfig(tree, None)
    assert len(violations) == 1

    tree = generate_ast_from_code(
        """
import asyncio
import aioredis


async def main():
    redis = await aioredis.create_redis_pool('redis://localhost/?password=sEcRet')
    await redis.set('my-key', 'value')
    """
    )
    violations = insights._check_aioredis_common_misconfig(tree, None)
    assert len(violations) == 1
    msg_found = False
    for v in violations:
        if "hardcoded password" in v.short_description:
            msg_found = True
    assert msg_found

    tree = generate_ast_from_code(
        """
import asyncio
import aioredis

secret = ''
async def main():
    redis = await aioredis.create_redis_pool('redis://localhost/?password=%s', secret)
    redis = await aioredis.create_redis_pool('redis://localhost/?password=%(secret)s', secret)
    redis = await aioredis.create_redis_pool('redis://localhost/?password=password')
    await redis.set('my-key', 'value')
    """
    )
    violations = insights._check_aioredis_common_misconfig(tree, None)
    assert len(violations) == 0

    tree = generate_ast_from_code(
        """
import asyncio
import aioredis


async def main():
    redis = await aioredis.create_redis_pool('redis://localhost/', password='sEcRet')
    await redis.set('my-key', 'value')
    """
    )
    violations = insights._check_aioredis_common_misconfig(tree, None)
    assert len(violations) == 1
    msg_found = False
    for v in violations:
        if "hardcoded password" in v.short_description:
            msg_found = True
    assert msg_found

    tree = generate_ast_from_code(
        """
import asyncio
import aioredis

secret = ''
async def main():
    redis = await aioredis.create_redis_pool('redis://localhost/', password=secret)
    await redis.set('my-key', 'value')
    """
    )
    violations = insights._check_aioredis_common_misconfig(tree, None)
    assert len(violations) == 0

    tree = generate_ast_from_code(
        """
import asyncio
import aioredis

secret = ''
async def main():
    redis = await aioredis.create_redis_pool('redis://localhost/', db='foo')
    await redis.set('my-key', 'value')
    """
    )
    violations = insights._check_aioredis_common_misconfig(tree, None)
    assert len(violations) == 1
