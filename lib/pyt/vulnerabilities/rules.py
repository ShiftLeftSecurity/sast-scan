# This file is part of Scan.

# Scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Scan.  If not, see <https://www.gnu.org/licenses/>.

flask_nostatic_config = [
    "SECRET_KEY",
    "SECURITY_PASSWORD_SALT",
    "SECURITY_PASSWORD_SINGLE_HASH",
    "SECURITY_CONFIRM_SALT",
    "SECURITY_RESET_SALT",
    "SECURITY_LOGIN_SALT",
    "SECURITY_REMEMBER_SALT",
    "SECRET_KEY_HMAC",
    "SECRET_KEY_HMAC_2",
]
flask_noset_config = [
    "DEBUG",
    "PROPAGATE_EXCEPTIONS",
    "FLASK_ENV",
    "TEMPLATES_AUTO_RELOAD",
]
flask_mustset_config = {
    "PREFERRED_URL_SCHEME": {"recommended": "https", "default": "http"},
    "SESSION_COOKIE_SECURE": {"recommended": True, "default": None},
}
flask_config_message = """Flask application is not configured correctly for deployment to production and live environments. Default settings that are more appropriate for development environment are in use.

NOTE: Some recommended settings may have to be set for every route even when using blueprint design pattern.

## Additional information

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[Flask Security](https://flask-security.readthedocs.io/en/develop/configuration.html)**

**[Flask Security Considerations](https://flask.palletsprojects.com/en/1.1.x/security/#security-considerations)**

**[Flask Configuration](https://flask.palletsprojects.com/en/1.1.x/api/#configuration)**
"""

flask_nosec_message = """Flask-Security allows you to quickly add common security mechanisms to your Flask application. Flask-Social can also be used to add social or OAuth login and connection management.

## Additional information

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[Flask Security](https://flask-security.readthedocs.io/en/develop/index.html)**

**[Flask Configuration](https://flask.palletsprojects.com/en/1.1.x/api/#configuration)**

**[Flask Talisman](https://github.com/GoogleCloudPlatform/flask-talisman)**
"""

flask_jwt_mustset_config = {
    "JWT_ALGORITHM": {"recommended": "RS512", "default": "HS256"},
    "JWT_SECRET_KEY": {"recommended": "unique", "default": "SECRET_KEY"},
    "JWT_PUBLIC_KEY": {"recommended": "unique", "default": ""},
    "JWT_PRIVATE_KEY": {"recommended": "unique", "default": ""},
    "JWT_COOKIE_SECURE": {"recommended": True, "default": False},
    "JWT_COOKIE_DOMAIN": {"recommended": "domain name", "default": ""},
    "JWT_BLACKLIST_ENABLED": {"recommended": True, "default": False},
}

flask_jwt_message = """JWT module is not configured correctly for deployment to production and live environments. Default settings that are more appropriate for development environment are in use.

## Additional information

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[Flask JWT configuration](https://flask-jwt-extended.readthedocs.io/en/stable/options/#configuration-options)**

**[JWT Algorithms](https://pyjwt.readthedocs.io/en/latest/algorithms.html)**
"""

django_nostatic_config = [
    "SECRET_KEY",
    "ACCESS_TOKEN_SALT",
    "DEBUG_PROPAGATE_EXCEPTIONS",
    "EMAIL_HOST_PASSWORD",
    "EMAIL_USE_TLS",
    "EMAIL_USE_SSL",
]
django_noset_config = ["DEBUG", "INTERNAL_IPS"]
django_mustset_config = {
    "ALLOWED_HOSTS": {
        "recommended": "domain name",
        "default": "['localhost', '127.0.0.1', '[::1]']",
    },
    "CSRF_COOKIE_DOMAIN": {"recommended": "domain name", "default": None},
    "CSRF_USE_SESSIONS": {"recommended": True, "default": False},
    "CSRF_COOKIE_SECURE": {"recommended": True, "default": False},
    "CSRF_TRUSTED_ORIGINS": {"recommended": "domain name", "default": []},
    "DATA_UPLOAD_MAX_MEMORY_SIZE": {"recommended": "2621440", "default": "2621440"},
    "DATA_UPLOAD_MAX_NUMBER_FIELDS": {"recommended": "100", "default": "1000"},
    "FILE_UPLOAD_MAX_MEMORY_SIZE": {"recommended": "2621440", "default": "2621440"},
    "SECURE_BROWSER_XSS_FILTER": {"recommended": True, "default": False},
    "SECURE_CONTENT_TYPE_NOSNIFF": {"recommended": True, "default": False},
    "SECURE_HSTS_INCLUDE_SUBDOMAINS": {"recommended": True, "default": False},
    "SECURE_HSTS_PRELOAD": {"recommended": True, "default": False},
    "SECURE_REDIRECT_EXEMPT": {"recommended": "domain name", "default": []},
    "AUTHENTICATION_BACKENDS": {
        "recommended": "['django.contrib.auth.backends.ModelBackend']",
        "default": "['django.contrib.auth.backends.ModelBackend']",
    },
    "SESSION_COOKIE_DOMAIN": {"recommended": "domain name", "default": None},
    "SESSION_COOKIE_SECURE": {"recommended": True, "default": False},
}
django_config_message = """Django application is not configured correctly for deployment to production and live environments. Default settings that are more appropriate for development environment are in use.

## Additional information

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[Django Security](https://docs.djangoproject.com/en/3.1/topics/security/)**

**[Deployment Checklist](https://docs.djangoproject.com/en/dev/howto/deployment/checklist/)**
"""

django_nosec_message = """Django Security Middleware allows you to quickly add common security mechanisms to your Django application

## Additional information

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[Django Security](https://docs.djangoproject.com/en/3.1/topics/security/)**

**[Django Security Middleware](https://docs.djangoproject.com/en/dev/ref/middleware/#django.middleware.security.SecurityMiddleware)**

**[Clickjacking Protection](https://docs.djangoproject.com/en/dev/ref/clickjacking/)**
"""

pymongo_config_message = """MongoDB is quite insecure by default allowing unauthenticated access for all clients. Configuring both MongoDB server and the client using proper authentication, secure tls and client-side field level encryption would improve security by several fold.

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[PyMongo Authentication](https://pymongo.readthedocs.io/en/stable/examples/authentication.html)**

**[TLS/SSL and PyMongo](https://pymongo.readthedocs.io/en/stable/examples/tls.html)**

**[Field Level Encryption](https://pymongo.readthedocs.io/en/stable/examples/encryption.html)**
"""

aioredis_config_message = """Redis is quite insecure by default allowing unauthenticated access for all clients. Configure both server and the client to use authentication and ssl to improve security.

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[aioredis Documentation](https://aioredis.readthedocs.io/en/v1.3.0/start.html#connecting-to-password-protected-redis-instance)**

**[Redis Encryption](https://redis.io/topics/encryption)**
"""

timing_attack_message = """Comparison using == operator leads to content based short-circuiting. By carefully measuring the time, it is possible to guess the correct password or token leading to timing attacks.

To avoid this attack, always use a constant time compare function while comparing sensitive data such as password or secret tokens.

**[Python Compare Digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest)**

**[Django constant time compare](https://github.com/django/django/blob/stable/3.0.x/django/utils/crypto.py#L49)**

**[Passlib consteq function](https://passlib.readthedocs.io/en/stable/lib/passlib.utils.html?highlight=timing#passlib.utils.consteq)**
"""

fastapi_nostatic_config = [
    "SECRET_KEY",
]

fastapi_mustimport_config = [
    "SecurityScopes",
    "CORSMiddleware",
    "TrustedHostMiddleware",
]

fastapi_config_message = """FastAPI is not configured correctly for deployment to production and live environments. Default settings that are more appropriate for development environment are in use.

FastAPI security middleware adds useful tools to add CORS headers as well as implement OAuth2 authentication in the API.

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[FastAPI Security](https://fastapi.tiangolo.com/advanced/security/)**

**[FastAPI Deployment - https](https://fastapi.tiangolo.com/deployment/#https)**
"""

aiohttp_nosec_message = """aiohttp csrf middleware adds xsrf protection to your application

## Additional information

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[aiohttp_csrf](https://pypi.org/project/aiohttp-csrf/)**
"""

jinja_config_message = """Jinja templating is not configured correctly for deployment to production and live environments.

## Additional information

**[OWASP-A6](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)**

**[Jinja2 documentation](https://jinja.palletsprojects.com/en/2.11.x/)**
"""

rules_message_map = {
    "fastapi-misconfiguration-static": fastapi_config_message,
    "fastapi-misconfiguration-recommended": fastapi_config_message,
    "fastapi-misconfiguration-insecure": fastapi_config_message,
    "timing-insecure-operation": timing_attack_message,
    "pymongo-misconfiguration-insecure": pymongo_config_message,
    "django-misconfiguration-static": django_config_message,
    "django-misconfiguration-insecure": django_config_message,
    "django-misconfiguration-recommended": django_config_message,
    "django-sec-recommended": django_nosec_message,
    "flask-misconfiguration-static": flask_config_message,
    "flask-misconfiguration-insecure": flask_config_message,
    "flask-misconfiguration-recommended": flask_config_message,
    "flask-misconfiguration-controls": flask_nosec_message,
    "flask-misconfiguration-jwt": flask_jwt_message,
    "aiohttp-misconfiguration-insecure": aiohttp_nosec_message,
    "jinja-misconfiguration-insecure": jinja_config_message,
    "aioredis-misconfiguration-insecure": aioredis_config_message,
}
