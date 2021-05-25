import ast
import os
import sys
from collections import namedtuple

import lib.pyt.vulnerabilities.rules as rules
from lib.logger import LOG
from lib.pyt.core.ast_helper import (
    get_as_list,
    get_assignments_as_dict,
    get_comparison_as_dict,
    get_method_as_dict,
    has_import_like,
    has_method_call,
)

Source = namedtuple(
    "Source", ("source_type", "trigger_word", "line_number", "label", "path")
)
Sink = namedtuple("Sink", ("sink_type", "trigger_word", "line_number", "label", "path"))

Insight = namedtuple(
    "Insight",
    (
        "short_description",
        "name",
        "code",
        "cwe_category",
        "severity",
        "owasp_category",
        "source",
        "sink",
        "recommendation",
    ),
)


def find_insights(ast_tree, path):
    violations_list = []
    # Invoke all the _check methods
    for mods in sys.modules[__name__].__dict__.keys():
        if mods.startswith("_check"):
            try:
                dfn = getattr(sys.modules[__name__], mods, None)
                if dfn:
                    violations = dfn(ast_tree, path)
                    if violations:
                        violations_list += violations
            except Exception as e:
                LOG.debug(e)
    return violations_list


def convert_node_source_sink(node, path):
    source_line_number = node["left_hand_side"].lineno
    source_trigger = None
    source_label = None
    source_type = "Constant"
    if isinstance(node["left_hand_side"], ast.Name):
        source_trigger = node["left_hand_side"].id
        source_label = node["left_hand_side"].id
    elif isinstance(node["left_hand_side"], ast.Attribute):
        source_trigger = node["left_hand_side"].attr
        source_label = node["left_hand_side"].attr
    elif hasattr(node["left_hand_side"], "value"):
        source_trigger = node["left_hand_side"].value
        source_label = node["left_hand_side"].value
    if hasattr(node["left_hand_side"], "kind"):
        source_type = (
            node["left_hand_side"].kind if node["left_hand_side"].kind else "Constant"
        )
    sink_line_number = ""
    sink_label = None
    sink_type = ""
    sink_trigger = None
    if isinstance(node["right_hand_side"], str):
        sink_trigger = node["right_hand_side"]
        sink_label = node["right_hand_side"]
        sink_type = ""
    if hasattr(node["right_hand_side"], "lineno"):
        sink_line_number = node["right_hand_side"].lineno
    if isinstance(node["right_hand_side"], (ast.Subscript, ast.Constant)):
        sink_trigger = node["right_hand_side"].value
        sink_label = node["right_hand_side"].value
    if isinstance(node["right_hand_side"], ast.Attribute):
        sink_trigger = ""
        sink_label = ""
    if hasattr(node["right_hand_side"], "kind"):
        sink_type = (
            node["right_hand_side"].kind if node["right_hand_side"].kind else "Constant"
        )
    source = Source(
        source_type, str(source_trigger), source_line_number, str(source_label), path
    )
    sink = Sink(sink_type, str(sink_trigger), sink_line_number, str(sink_label), path)
    return source, sink


def convert_dict_source_sink(sdict, path):
    source = Source(
        sdict["source_type"],
        sdict["source_trigger"],
        sdict["source_line_number"],
        sdict["source_trigger"],
        path,
    )
    sink = Sink(
        sdict["sink_type"],
        sdict["sink_trigger"],
        sdict["sink_line_number"],
        sdict["sink_trigger"],
        path,
    )
    return source, sink


def _check_fastapi_misconfig(ast_tree, path):
    violations = []
    if has_import_like("fastapi", ast_tree):
        all_keys = []
        for key in rules.fastapi_nostatic_config:
            config_dict = get_assignments_as_dict(f"{key}=??", ast_tree)
            if not config_dict:
                continue
            for k, v in config_dict.items():
                all_keys.append(k)
                # Static configs
                source, sink = convert_node_source_sink(v, path)
                if sink.trigger_word:
                    obfuscated_label = sink.label
                    if len(obfuscated_label) > 4:
                        obfuscated_label = obfuscated_label[:4] + "****"
                    violations.append(
                        Insight(
                            f"Security Misconfiguration with the config `{source.label}` set to a static value `{obfuscated_label}`",
                            "Security Misconfiguration",
                            "fastapi-misconfiguration-static",
                            "CWE-732",
                            "MEDIUM",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["fastapi-misconfiguration-static"],
                        )
                    )
        # Check for common security extensions
        cors_found = False
        for mid in rules.fastapi_mustimport_config:
            if not has_import_like(mid, ast_tree):
                source, sink = convert_dict_source_sink(
                    {
                        "source_type": "Middleware",
                        "source_trigger": mid,
                        "source_line_number": "1",
                        "sink_type": "Constant",
                        "sink_trigger": "",
                        "sink_line_number": "1",
                    },
                    path,
                )
                violations.append(
                    Insight(
                        f"Consider using FastAPI security middleware {mid} to improve overall security",
                        "Security Misconfiguration",
                        "fastapi-misconfiguration-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["fastapi-misconfiguration-recommended"],
                    )
                )
            else:
                if mid == "CORSMiddleware":
                    cors_found = True
        # Check for overgenerous CORS settings
        if cors_found:
            method_obj_list = get_method_as_dict("??.add_middleware(??)", ast_tree)
            if method_obj_list:
                for method_obj in method_obj_list:
                    if not method_obj:
                        continue
                    start_line = method_obj.get("lineno")
                    method_args = method_obj.get("args")
                    for margs in method_args:
                        if margs.get("id") != "CORSMiddleware":
                            continue
                        method_keywords = method_obj.get("keywords")
                        for mkey_obj in method_keywords:
                            kw_arg = mkey_obj.get("arg")
                            kw_elts = None
                            if mkey_obj.get("value").get("_type") == "List":
                                kw_elts = mkey_obj.get("value").get("elts")
                            if mkey_obj.get("value").get("_type") == "Constant":
                                kw_elts = [mkey_obj.get("value")]
                            if not kw_arg or not kw_elts:
                                continue
                            kw_arg_value = kw_elts[0].get("value")
                            source, sink = convert_dict_source_sink(
                                {
                                    "source_type": "Config",
                                    "source_trigger": kw_arg,
                                    "source_line_number": start_line,
                                    "sink_type": "Constant",
                                    "sink_trigger": kw_arg_value,
                                    "sink_line_number": start_line,
                                },
                                path,
                            )
                            if kw_arg == "allow_origins" and kw_arg_value == "*":
                                violations.append(
                                    Insight(
                                        "Limit the origins allowed for CORS to specific domains to improve security",
                                        "Security Misconfiguration",
                                        "fastapi-misconfiguration-insecure",
                                        "CWE-732",
                                        "MEDIUM",
                                        "a6-misconfiguration",
                                        source,
                                        sink,
                                        rules.rules_message_map[
                                            "fastapi-misconfiguration-insecure"
                                        ],
                                    )
                                )
                            if kw_arg == "allow_credentials" and kw_arg_value:
                                violations.append(
                                    Insight(
                                        "Use of allowed credentials with CORS would decrease the overall API security",
                                        "Security Misconfiguration",
                                        "fastapi-misconfiguration-insecure",
                                        "CWE-732",
                                        "LOW",
                                        "a6-misconfiguration",
                                        source,
                                        sink,
                                        rules.rules_message_map[
                                            "fastapi-misconfiguration-insecure"
                                        ],
                                    )
                                )
    return violations


def _check_timing_attack(ast_tree, path):
    violations = []
    common_patterns = [
        "password==??.password",
        "??.password==password",
        "token==??.token",
        "??.token==token",
        "hash==??.hash",
        "??.hash==hash",
        "access_token==??.access_token",
        "??.access_token==access_token",
    ]
    for cp in common_patterns:
        config_dict = get_comparison_as_dict(cp, ast_tree)
        if not config_dict:
            continue
        for ck, cv in config_dict.items():
            clt = cv.get("left_hand_side")
            if not clt:
                continue
            source, sink = convert_dict_source_sink(
                {
                    "source_type": "Assignment",
                    "source_trigger": ck,
                    "source_line_number": clt.lineno,
                    "sink_type": "Constant",
                    "sink_trigger": "",
                    "sink_line_number": clt.lineno,
                },
                path,
            )
            violations.append(
                Insight(
                    "Insecure comparison using == could lead to timing attacks",
                    "Insecure Operation",
                    "timing-insecure-operation",
                    "CWE-203",
                    "HIGH",
                    "a3-sensitive-data-exposure",
                    source,
                    sink,
                    rules.rules_message_map["timing-insecure-operation"],
                )
            )
    return violations


def _check_aioredis_common_misconfig(ast_tree, path):
    violations = []
    if has_import_like("aioredis", ast_tree):
        # Look for all variations
        method_obj_list = get_method_as_dict("??.create_redis_pool(??)", ast_tree)
        if not method_obj_list:
            method_obj_list = get_method_as_dict("create_redis_pool(??)", ast_tree)
        if not method_obj_list:
            method_obj_list = get_method_as_dict("??.create_pool(??)", ast_tree)
        if not method_obj_list:
            method_obj_list = get_method_as_dict("create_pool(??)", ast_tree)
        if not method_obj_list:
            return None
        method_obj = method_obj_list[0]
        start_line = method_obj.get("lineno")
        source, sink = convert_dict_source_sink(
            {
                "source_type": "Config",
                "source_trigger": "aioredis",
                "source_line_number": start_line,
                "sink_type": "Constant",
                "sink_trigger": "",
                "sink_line_number": start_line,
            },
            path,
        )
        if not method_obj.get("args"):
            # connection to local redis instance
            violations.append(
                Insight(
                    "Connection to a Redis instance running in default mode without any authentication",
                    "Security Misconfiguration",
                    "aioredis-misconfiguration-insecure",
                    "CWE-732",
                    "MEDIUM",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.rules_message_map["aioredis-misconfiguration-insecure"],
                )
            )
        elif method_obj.get("args"):
            # password checks
            args = method_obj.get("args")
            args_value = args[0].get("value", "")
            if not isinstance(args_value, str):
                return violations
            hostname = args_value.replace("redis://", "").split("/")[0]
            keywords = method_obj.get("keywords")
            if not keywords:
                if "password=" not in args_value:
                    violations.append(
                        Insight(
                            f"Connection to a Redis instance at `{hostname}` in default mode without any authentication",
                            "Security Misconfiguration",
                            "aioredis-misconfiguration-insecure",
                            "CWE-732",
                            "MEDIUM",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map[
                                "aioredis-misconfiguration-insecure"
                            ],
                        )
                    )
                else:
                    password_val_list = args_value.split("password=")
                    if len(password_val_list) > 1:
                        password_val = password_val_list[-1].split("&")[0]
                        for spe in ["%(", "{", "%s"]:
                            if spe in password_val:
                                return violations
                        # hardcoded password
                        if password_val and password_val not in [
                            "test",
                            "password",
                            "ignore",
                        ]:
                            violations.append(
                                Insight(
                                    f"Connection to a Redis instance at `{hostname}` with a hardcoded password",
                                    "Security Misconfiguration",
                                    "aioredis-misconfiguration-insecure",
                                    "CWE-732",
                                    "MEDIUM",
                                    "a6-misconfiguration",
                                    source,
                                    sink,
                                    rules.rules_message_map[
                                        "aioredis-misconfiguration-insecure"
                                    ],
                                )
                            )
                return violations
            # Check if password is specified as a keyword
            for kw in keywords:
                arg = kw.get("arg")
                arg_value = ""
                if kw["value"]["_type"] == "Constant":
                    arg_value = kw["value"]["value"]
                if arg == "password" and not arg_value:
                    return violations
                if arg == "password" and arg_value:
                    for spe in ["%(", "{", "%s"]:
                        if spe in arg_value:
                            return violations
                    # hardcoded password
                    if arg_value and arg_value not in [
                        "test",
                        "password",
                        "ignore",
                    ]:
                        violations.append(
                            Insight(
                                f"Connection to a Redis instance at `{hostname}` with a hardcoded password",
                                "Security Misconfiguration",
                                "aioredis-misconfiguration-insecure",
                                "CWE-732",
                                "MEDIUM",
                                "a6-misconfiguration",
                                source,
                                sink,
                                rules.rules_message_map[
                                    "aioredis-misconfiguration-insecure"
                                ],
                            )
                        )
                    return violations
            violations.append(
                Insight(
                    f"Connection to a Redis instance at `{hostname}` in default mode without any authentication",
                    "Security Misconfiguration",
                    "aioredis-misconfiguration-insecure",
                    "CWE-732",
                    "MEDIUM",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.rules_message_map["aioredis-misconfiguration-insecure"],
                )
            )
    return violations


def _check_pymongo_common_misconfig(ast_tree, path):
    violations = []
    if has_import_like("pymongo", ast_tree):
        method_obj_list = get_method_as_dict("??.MongoClient(??)", ast_tree)
        if not method_obj_list:
            method_obj_list = get_method_as_dict("MongoClient(??)", ast_tree)
        if not method_obj_list:
            return None
        method_obj = method_obj_list[0]
        start_line = method_obj.get("lineno")
        source, sink = convert_dict_source_sink(
            {
                "source_type": "Config",
                "source_trigger": "MongoClient",
                "source_line_number": start_line,
                "sink_type": "Constant",
                "sink_trigger": "",
                "sink_line_number": start_line,
            },
            path,
        )
        if not method_obj.get("args"):
            # pymongo connection to local mongodb instance
            violations.append(
                Insight(
                    "Connection to a MongoDB instance running in default mode without any authentication",
                    "Security Misconfiguration",
                    "pymongo-misconfiguration-insecure",
                    "CWE-732",
                    "LOW",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.rules_message_map["pymongo-misconfiguration-insecure"],
                )
            )
        elif method_obj.get("args") and method_obj.get("keywords"):
            # ssl checks
            args = method_obj.get("args")
            hostname = args[0].get("value", "localhost")
            if not isinstance(hostname, str):
                return violations
            # query_args = ""
            # if "?" in hostname:
            #     query_args = hostname.split("?")[1]
            hostname = hostname.replace("mongodb://", "").split("/")[0]
            keywords = method_obj.get("keywords")
            for kw in keywords:
                arg = kw.get("arg")
                arg_value = ""
                if kw["value"]["_type"] == "Constant":
                    arg_value = kw["value"]["value"]
                if kw["value"]["_type"] == "Attribute":
                    arg_value = kw["value"]["attr"]
                # ssl is off
                if arg == "ssl" and not arg_value:
                    violations.append(
                        Insight(
                            f"Connection to a MongoDB instance at `{hostname}` running in default mode without tls encryption",
                            "Security Misconfiguration",
                            "pymongo-misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map[
                                "pymongo-misconfiguration-insecure"
                            ],
                        )
                    )
                if arg == "ssl_cert_reqs" and arg_value == "CERT_NONE":
                    violations.append(
                        Insight(
                            f"Connection to a MongoDB instance at `{hostname}` running in default mode without tls certificate verification",
                            "Security Misconfiguration",
                            "pymongo-misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map[
                                "pymongo-misconfiguration-insecure"
                            ],
                        )
                    )
                if arg == "authMechanism" and arg_value == "MONGODB-CR":
                    violations.append(
                        Insight(
                            f"Connection to a MongoDB instance at `{hostname}` with a deprecated authentication method",
                            "Security Misconfiguration",
                            "pymongo-misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map[
                                "pymongo-misconfiguration-insecure"
                            ],
                        )
                    )
        if not has_import_like("ClientEncryption", ast_tree) or not has_method_call(
            "ClientEncryption(??)", ast_tree
        ):
            # client encryption checks
            violations.append(
                Insight(
                    "Client-side Field Level Encryption allows an application to encrypt specific data fields based on the compliance needs",
                    "Security Misconfiguration",
                    "pymongo-misconfiguration-insecure",
                    "CWE-732",
                    "LOW",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.rules_message_map["pymongo-misconfiguration-insecure"],
                )
            )
    return violations


def _check_aiohttp_common_misconfig(ast_tree, path):
    """Look for common security misconfiguration in aiohttp apps"""
    violations = []

    if os.path.basename(path) == "app.py":
        is_aiohttp = has_import_like("aiohttp", ast_tree) or has_import_like(
            "aiohttp.web", ast_tree
        )
        if not is_aiohttp:
            return violations
        # Middleware check
        uses_csrf = has_import_like("aiohttp_csrf", ast_tree)
        if not uses_csrf:
            source, sink = convert_dict_source_sink(
                {
                    "source_type": "Config",
                    "source_trigger": "middlewares",
                    "source_line_number": 1,
                    "sink_type": "Constant",
                    "sink_trigger": "csrf_middleware",
                    "sink_line_number": 1,
                },
                path,
            )
            violations.append(
                Insight(
                    "Enable csrf_middleware in this aiohttp application",
                    "Security Misconfiguration",
                    "aiohttp-sec-recommended",
                    "CWE-732",
                    "MEDIUM",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.rules_message_map["aiohttp-misconfiguration-insecure"],
                )
            )
        # jinja check
        uses_jinja = has_import_like("aiohttp_jinja2", ast_tree)
        if uses_jinja:
            esc_dict = get_assignments_as_dict(
                "setup_jinja(??, autoescape=False)", ast_tree
            )
            if esc_dict and esc_dict.get("autoescape"):
                esc_value = esc_dict.get("autoescape").get("right_hand_side")
                if not esc_value.value:
                    source, sink = convert_dict_source_sink(
                        {
                            "source_type": "Config",
                            "source_trigger": "setup_jinja",
                            "source_line_number": esc_value.lineno,
                            "sink_type": "Constant",
                            "sink_trigger": "False",
                            "sink_line_number": esc_value.lineno,
                        },
                        path,
                    )
                    violations.append(
                        Insight(
                            "Enable Jinja autoescape by setting this value to True",
                            "Security Misconfiguration",
                            "jinja-sec-recommended",
                            "CWE-732",
                            "MEDIUM",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["jinja-misconfiguration-insecure"],
                        )
                    )
    return violations


def _check_django_common_misconfig(ast_tree, path):
    """Look for common security misconfiguration in Django apps"""
    violations = []

    if os.path.basename(path) == "settings.py":
        config_dict = get_assignments_as_dict("?=?", ast_tree)
        is_django = (
            has_import_like("django", ast_tree)
            or "INSTALLED_APPS" in config_dict.keys()
            or "MIDDLEWARE" in config_dict.keys()
            or "MIDDLEWARE_CLASSES" in config_dict.keys()
        )
        if not is_django:
            return violations
        all_keys = []
        for k, v in config_dict.items():
            all_keys.append(k)
            # Static configs
            if k in rules.django_nostatic_config:
                source, sink = convert_node_source_sink(v, path)
                if sink.trigger_word:
                    obfuscated_label = sink.label
                    if len(obfuscated_label) > 4:
                        obfuscated_label = obfuscated_label[:4] + "****"
                    violations.append(
                        Insight(
                            f"Security Misconfiguration with the config `{source.label}` set to a static value `{obfuscated_label}`",
                            "Security Misconfiguration",
                            "django-misconfiguration-static",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["django-misconfiguration-static"],
                        )
                    )

            # Do not set configs
            if k in rules.django_noset_config:
                source, sink = convert_node_source_sink(v, path)
                if sink.trigger_word:
                    violations.append(
                        Insight(
                            f"Security Misconfiguration with the config `{source.label}` set to a value `{sink.label}` meant for development use",
                            "Security Misconfiguration",
                            "django-misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["django-misconfiguration-insecure"],
                        )
                    )
        # Must set configs
        must_configs = rules.django_mustset_config.keys()
        for mc in must_configs:
            if mc not in all_keys:
                rsetting = rules.django_mustset_config[mc]
                source, sink = convert_dict_source_sink(
                    {
                        "source_type": "Config",
                        "source_trigger": mc,
                        "source_line_number": 1,
                        "sink_type": "Constant",
                        "sink_trigger": rsetting.get("default"),
                        "sink_line_number": 1,
                    },
                    path,
                )
                violations.append(
                    Insight(
                        f"""Security Misconfiguration with the config `{mc}` not set to the recommended value `{rsetting.get("recommended")}` for production use""",
                        "Security Misconfiguration",
                        "django-misconfiguration-recommended",
                        "CWE-732",
                        "MEDIUM",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["django-misconfiguration-recommended"],
                    )
                )
        # Django toolbar check
        django_toolbar_ast = get_assignments_as_dict(
            "DEBUG_TOOLBAR_CONFIG=??", ast_tree
        )
        if django_toolbar_ast and django_toolbar_ast.get("DEBUG_TOOLBAR_CONFIG"):
            toolbar_value = django_toolbar_ast.get("DEBUG_TOOLBAR_CONFIG").get(
                "right_hand_side"
            )
            source, sink = convert_dict_source_sink(
                {
                    "source_type": "Config",
                    "source_trigger": "DEBUG_TOOLBAR_CONFIG",
                    "source_line_number": toolbar_value.lineno,
                    "sink_type": "Constant",
                    "sink_trigger": "signed_cookies",
                    "sink_line_number": toolbar_value.lineno,
                },
                path,
            )
            violations.append(
                Insight(
                    "Disable django-debug-toolbar completely or ensure SHOW_TOOLBAR_CALLBACK performs an explicit check for administrative roles",
                    "Security Misconfiguration",
                    "django-sec-recommended",
                    "CWE-732",
                    "MEDIUM",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.rules_message_map["django-misconfiguration-insecure"],
                )
            )
        # Django session check - Version 1.8.x
        django_session_ast = get_assignments_as_dict("SESSION_ENGINE=??", ast_tree)
        if django_session_ast and django_session_ast.get("SESSION_ENGINE"):
            session_value = django_session_ast.get("SESSION_ENGINE").get(
                "right_hand_side"
            )
            if (
                isinstance(session_value, ast.Constant)
                and "signed_cookies" in session_value.value
            ):
                source, sink = convert_dict_source_sink(
                    {
                        "source_type": "Config",
                        "source_trigger": "SESSION_ENGINE",
                        "source_line_number": session_value.lineno,
                        "sink_type": "Constant",
                        "sink_trigger": "signed_cookies",
                        "sink_line_number": session_value.lineno,
                    },
                    path,
                )
                violations.append(
                    Insight(
                        "Replace signed_cookies with a db backend for storing session data",
                        "Security Misconfiguration",
                        "django-sec-recommended",
                        "CWE-732",
                        "MEDIUM",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["django-misconfiguration-insecure"],
                    )
                )
        # Django middlewares check - Version 1.8.x
        django_middlewares_ast = get_assignments_as_dict(
            "MIDDLEWARE_CLASSES=??", ast_tree
        )
        if django_middlewares_ast and django_middlewares_ast.get("MIDDLEWARE_CLASSES"):
            assign_ast = django_middlewares_ast.get("MIDDLEWARE_CLASSES").get(
                "left_hand_side"
            )
            included_mids = get_as_list(
                django_middlewares_ast.get("MIDDLEWARE_CLASSES").get("right_hand_side")
            )
            if not included_mids:
                return violations
            source, sink = convert_dict_source_sink(
                {
                    "source_type": "Config",
                    "source_trigger": "MIDDLEWARE_CLASSES",
                    "source_line_number": assign_ast.lineno,
                    "sink_type": "Constant",
                    "sink_trigger": "",
                    "sink_line_number": assign_ast.lineno,
                },
                path,
            )
            if (
                "django.middleware.clickjacking.XFrameOptionsMiddleware"
                not in included_mids
            ):
                violations.append(
                    Insight(
                        "Consider including the clickjacking middleware which provides easy-to-use protection against clickjacking",
                        "Security Misconfiguration",
                        "django-sec-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["django-sec-recommended"],
                    )
                )
            if "django.middleware.csrf.CsrfViewMiddleware" not in included_mids:
                violations.append(
                    Insight(
                        "Consider including CSRF protection middleware for django 1.x applications",
                        "Security Misconfiguration",
                        "django-sec-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["django-sec-recommended"],
                    )
                )

        # Django middlewares check - Version 3.x
        django_middlewares_ast = get_assignments_as_dict("MIDDLEWARE=??", ast_tree)
        if django_middlewares_ast and django_middlewares_ast.get("MIDDLEWARE"):
            assign_ast = django_middlewares_ast.get("MIDDLEWARE").get("left_hand_side")
            included_mids = get_as_list(
                django_middlewares_ast.get("MIDDLEWARE").get("right_hand_side")
            )
            if not included_mids:
                return violations
            source, sink = convert_dict_source_sink(
                {
                    "source_type": "Config",
                    "source_trigger": "MIDDLEWARE",
                    "source_line_number": assign_ast.lineno,
                    "sink_type": "Constant",
                    "sink_trigger": "",
                    "sink_line_number": assign_ast.lineno,
                },
                path,
            )
            if "django.middleware.security.SecurityMiddleware" not in included_mids:
                violations.append(
                    Insight(
                        "Consider including the security middleware which provides several security enhancements to django applications",
                        "Security Misconfiguration",
                        "django-sec-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["django-sec-recommended"],
                    )
                )
            if (
                "django.middleware.clickjacking.XFrameOptionsMiddleware"
                not in included_mids
            ):
                violations.append(
                    Insight(
                        "Consider including the clickjacking middleware which provides easy-to-use protection against clickjacking",
                        "Security Misconfiguration",
                        "django-sec-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["django-sec-recommended"],
                    )
                )
            if "django.middleware.csrf.CsrfViewMiddleware" not in included_mids:
                violations.append(
                    Insight(
                        "Consider including CSRF protection middleware for django applications",
                        "Security Misconfiguration",
                        "django-sec-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["django-sec-recommended"],
                    )
                )
    return violations


def _check_flask_common_misconfig(ast_tree, path):
    """Look for common security misconfiguration in Flask apps"""
    violations = []
    has_flask_run = has_method_call("app.run(??)", ast_tree)
    if not has_flask_run:
        has_flask_run = has_method_call("Flask(??)", ast_tree)
    if not has_flask_run:
        has_flask_run = has_method_call("register_blueprint(??)", ast_tree)
    if not has_flask_run:
        has_flask_run = has_method_call("http_server.listen(??)", ast_tree)
    if has_import_like("flask", ast_tree) and has_flask_run:
        config_method_patterns = [
            "??.from_file(??)",
            "??.from_json(??)",
            "??.from_envvar(??)",
            "??.from_mapping(??)",
            "??.from_object(??)",
            "??.from_pyfile(??)",
        ]
        uses_config_import = False
        for cmpattern in config_method_patterns:
            uses_config_import = has_method_call(cmpattern, ast_tree)
            if uses_config_import:
                break
        all_keys = []
        config_dict = get_assignments_as_dict("?.config[?] = ?", ast_tree)
        app_config_dict = get_assignments_as_dict("app.?? = ?", ast_tree)
        config_dict.update(app_config_dict)
        for k, v in config_dict.items():
            all_keys.append(k)
            # Static configs
            if k.upper() in rules.flask_nostatic_config:
                source, sink = convert_node_source_sink(v, path)
                if sink.trigger_word:
                    obfuscated_label = sink.label
                    if len(obfuscated_label) > 4:
                        obfuscated_label = obfuscated_label[:4] + "****"
                    violations.append(
                        Insight(
                            f"Security Misconfiguration with the config `{source.label}` set to a static value `{obfuscated_label}`",
                            "Security Misconfiguration",
                            "flask-misconfiguration-static",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["flask-misconfiguration-static"],
                        )
                    )

            # Do not set configs
            if k in rules.flask_noset_config:
                source, sink = convert_node_source_sink(v, path)
                if sink.trigger_word:
                    violations.append(
                        Insight(
                            f"Security Misconfiguration with the config `{source.label}` set to a value `{sink.label}` meant for development use",
                            "Security Misconfiguration",
                            "flask-misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["flask-misconfiguration-insecure"],
                        )
                    )

        # Must set configs
        if not uses_config_import:
            must_configs = rules.flask_mustset_config.keys()
            for mc in must_configs:
                if mc not in all_keys:
                    rsetting = rules.flask_mustset_config[mc]
                    source, sink = convert_dict_source_sink(
                        {
                            "source_type": "Config",
                            "source_trigger": mc,
                            "source_line_number": 1,
                            "sink_type": "Constant",
                            "sink_trigger": rsetting.get("default"),
                            "sink_line_number": 1,
                        },
                        path,
                    )
                    violations.append(
                        Insight(
                            f"""Security Misconfiguration with the config `{mc}` not set to the recommended value `{rsetting.get("recommended")}` for production use""",
                            "Security Misconfiguration",
                            "flask-misconfiguration-recommended",
                            "CWE-732",
                            "MEDIUM",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map[
                                "flask-misconfiguration-recommended"
                            ],
                        )
                    )

        # Check for flask security
        if not has_import_like("flask_security", ast_tree) and not has_import_like(
            "flask_talisman", ast_tree
        ):
            source, sink = convert_dict_source_sink(
                {
                    "source_type": "Extension",
                    "source_trigger": "flask_security",
                    "source_line_number": 1,
                    "sink_type": "Extension",
                    "sink_trigger": None,
                    "sink_line_number": 1,
                },
                path,
            )
            violations.append(
                Insight(
                    "Consider adding Flask-Security and Flask-Talisman security extensions to your Flask apps",
                    "Missing Security Controls",
                    "flask-misconfiguration-controls",
                    "CWE-732",
                    "LOW",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.rules_message_map["flask-misconfiguration-controls"],
                )
            )

        # Check for xss protection headers set to 0
        # response.headers['X-XSS-Protection'] = '0'
        xss_protect_dict = get_assignments_as_dict(
            "??.headers['X-XSS-Protection'] = ??", ast_tree
        )
        if xss_protect_dict:
            xssh_key = xss_protect_dict.get("X-XSS-Protection").get("left_hand_side")
            xssh_value = xss_protect_dict.get("X-XSS-Protection").get("right_hand_side")
            if hasattr(xssh_value, "value") and not xssh_value.value:
                source, sink = convert_dict_source_sink(
                    {
                        "source_type": "Header",
                        "source_trigger": "X-XSS-Protection",
                        "source_line_number": xssh_key.lineno,
                        "sink_type": "Constant",
                        "sink_trigger": None,
                        "sink_line_number": xssh_key.lineno,
                    },
                    path,
                )
                violations.append(
                    Insight(
                        "Disabling XSS protection directly in the code would make the application more vulnerable to XSS attacks",
                        "Security Misconfiguration",
                        "flask-misconfiguration-insecure",
                        "CWE-732",
                        "MEDIUM",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.rules_message_map["flask-misconfiguration-insecure"],
                    )
                )

        # Flask jwt checks
        if (
            has_import_like("flask_jwt_extended", ast_tree)
            or has_import_like("flask_jwt", ast_tree)
        ) and not uses_config_import:
            must_configs = rules.flask_jwt_mustset_config.keys()
            for mc in must_configs:
                if mc not in all_keys:
                    rsetting = rules.flask_jwt_mustset_config[mc]
                    source, sink = convert_dict_source_sink(
                        {
                            "source_type": "Config",
                            "source_trigger": mc,
                            "source_line_number": 1,
                            "sink_type": "Constant",
                            "sink_trigger": rsetting.get("default"),
                            "sink_line_number": 1,
                        },
                        path,
                    )
                    violations.append(
                        Insight(
                            f"""Security Misconfiguration with the config `{mc}` not set to the recommended value `{rsetting.get("recommended")}` for production use""",
                            "Missing Security Controls",
                            "flask-misconfiguration-jwt",
                            "CWE-732",
                            "MEDIUM",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["flask-misconfiguration-jwt"],
                        )
                    )
                if mc == "JWT_SECRET_KEY" and mc in all_keys:
                    # Discourage symmetric key
                    source, sink = convert_dict_source_sink(
                        {
                            "source_type": "Config",
                            "source_trigger": mc,
                            "source_line_number": 1,
                            "sink_type": "Constant",
                            "sink_trigger": "",
                            "sink_line_number": 1,
                        },
                        path,
                    )
                    violations.append(
                        Insight(
                            "Use an asymmetric RSA based algorithm such as RS512 for JWT",
                            "Security Misconfiguration",
                            "flask-misconfiguration-jwt",
                            "CWE-327",
                            "MEDIUM",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.rules_message_map["flask-misconfiguration-jwt"],
                        )
                    )
    # jwt checks
    if has_import_like("jwt", ast_tree):
        method_obj_list = get_method_as_dict("jwt.decode(??)", ast_tree)
        if method_obj_list:
            for method_obj in method_obj_list:
                if not method_obj:
                    continue
                start_line = method_obj.get("lineno")
                method_args = method_obj.get("args")
                for margs in method_args:
                    method_keywords = method_obj.get("keywords")
                    for mkey_obj in method_keywords:
                        kw_arg = mkey_obj.get("arg")
                        kw_elts = None
                        if mkey_obj.get("value").get("_type") == "List":
                            kw_elts = mkey_obj.get("value").get("elts")
                        if mkey_obj.get("value").get("_type") == "Constant":
                            kw_elts = [mkey_obj.get("value")]
                        if not kw_arg or not kw_elts:
                            continue
                        kw_arg_value = kw_elts[0].get("value")
                        source, sink = convert_dict_source_sink(
                            {
                                "source_type": "Config",
                                "source_trigger": kw_arg,
                                "source_line_number": start_line,
                                "sink_type": "Constant",
                                "sink_trigger": kw_arg_value,
                                "sink_line_number": start_line,
                            },
                            path,
                        )
                        if kw_arg == "verify" and not kw_arg_value:
                            violations.append(
                                Insight(
                                    f"""Security Misconfiguration with the config `{kw_arg}` not set to the recommended value `True` for production use""",
                                    "Missing Security Controls",
                                    "flask-misconfiguration-jwt",
                                    "CWE-732",
                                    "MEDIUM",
                                    "a6-misconfiguration",
                                    source,
                                    sink,
                                    rules.rules_message_map[
                                        "flask-misconfiguration-jwt"
                                    ],
                                )
                            )
                        elif kw_arg == "algorithms" and (
                            "HS256" in kw_arg_value
                            or "HS384" in kw_arg_value
                            or "HS512" in kw_arg_value
                        ):
                            violations.append(
                                Insight(
                                    "Use an asymmetric RSA based algorithm such as RS512 for JWT",
                                    "Security Misconfiguration",
                                    "flask-misconfiguration-jwt",
                                    "CWE-327",
                                    "LOW",
                                    "a6-misconfiguration",
                                    source,
                                    sink,
                                    rules.rules_message_map[
                                        "flask-misconfiguration-jwt"
                                    ],
                                )
                            )

    return violations
