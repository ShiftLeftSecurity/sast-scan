import ast
import os
import sys
from collections import namedtuple

import lib.pyt.vulnerabilities.rules as rules
from lib.logger import LOG
from lib.pyt.core.ast_helper import (
    get_as_list,
    get_assignments_as_dict,
    get_method_as_dict,
    has_import,
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
    if hasattr(node["left_hand_side"], "value"):
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
    if isinstance(node["right_hand_side"], ast.Subscript) or isinstance(
        node["right_hand_side"], ast.Constant
    ):
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


def _check_pymongo_common_misconfig(ast_tree, path):
    violations = []
    if has_import_like("pymongo", ast_tree):
        method_obj = get_method_as_dict("??.MongoClient(??)", ast_tree)
        if not method_obj:
            method_obj = get_method_as_dict("MongoClient(??)", ast_tree)
        if not method_obj:
            return None
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
                    f"Connection to a MongoDB instance running in default mode without any authentication",
                    "Security Misconfiguration",
                    "misconfiguration-insecure",
                    "CWE-732",
                    "LOW",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.pymongo_config_message,
                )
            )
        elif method_obj.get("args") and method_obj.get("keywords"):
            # ssl checks
            args = method_obj.get("args")
            hostname = args[0].get("value", "localhost")
            query_args = ""
            if "?" in hostname:
                query_args = hostname.split("?")[1]
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
                            "misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.pymongo_config_message,
                        )
                    )
                if arg == "ssl_cert_reqs" and arg_value == "CERT_NONE":
                    violations.append(
                        Insight(
                            f"Connection to a MongoDB instance at `{hostname}` running in default mode without tls certificate verification",
                            "Security Misconfiguration",
                            "misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.pymongo_config_message,
                        )
                    )
                if arg == "authMechanism" and arg_value == "MONGODB-CR":
                    violations.append(
                        Insight(
                            f"Connection to a MongoDB instance at `{hostname}` with a deprecated authentication method",
                            "Security Misconfiguration",
                            "misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.pymongo_config_message,
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
                    "misconfiguration-insecure",
                    "CWE-732",
                    "LOW",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.pymongo_config_message,
                )
            )
    return violations


def _check_django_common_misconfig(ast_tree, path):
    """Look for common security misconfiguration in Django apps
    """
    violations = []

    if os.path.basename(path) == "settings.py":
        config_dict = get_assignments_as_dict("?=?", ast_tree)
        is_django = (
            has_import_like("django", ast_tree)
            or "INSTALLED_APPS" in config_dict.keys()
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
                            "misconfiguration-static",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.django_config_message,
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
                            "misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.django_config_message,
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
                        "misconfiguration-recommended",
                        "CWE-732",
                        "MEDIUM",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.django_config_message,
                    )
                )
        # Django middlewares check
        django_middlewares_ast = get_assignments_as_dict("MIDDLEWARE=??", ast_tree)
        if django_middlewares_ast and django_middlewares_ast.get("MIDDLEWARE"):
            assign_ast = django_middlewares_ast.get("MIDDLEWARE").get("left_hand_side")
            included_mids = get_as_list(
                django_middlewares_ast.get("MIDDLEWARE").get("right_hand_side")
            )
            if not included_mids:
                return
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
                        f"""Consider including the security middleware which provides several security enhancements to django applications""",
                        "Security Misconfiguration",
                        "misconfiguration-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.django_nosec_message,
                    )
                )
            if (
                "django.middleware.clickjacking.XFrameOptionsMiddleware"
                not in included_mids
            ):
                violations.append(
                    Insight(
                        f"""Consider including the clickjacking middleware which provides easy-to-use protection against clickjacking""",
                        "Security Misconfiguration",
                        "misconfiguration-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.django_nosec_message,
                    )
                )
            if "django.middleware.csrf.CsrfViewMiddleware" not in included_mids:
                violations.append(
                    Insight(
                        f"""Consider including CSRF protection middleware for django applications""",
                        "Security Misconfiguration",
                        "misconfiguration-recommended",
                        "CWE-732",
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.django_nosec_message,
                    )
                )
    return violations


def _check_flask_common_misconfig(ast_tree, path):
    """Look for common security misconfiguration in Flask apps
    """
    violations = []
    has_flask_run = has_method_call("app.run(??)", ast_tree)
    if has_import("flask", ast_tree) and has_flask_run:
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
        for k, v in config_dict.items():
            all_keys.append(k)
            # Static configs
            if k in rules.flask_nostatic_config:
                source, sink = convert_node_source_sink(v, path)
                if sink.trigger_word:
                    obfuscated_label = sink.label
                    if len(obfuscated_label) > 4:
                        obfuscated_label = obfuscated_label[:4] + "****"
                    violations.append(
                        Insight(
                            f"Security Misconfiguration with the config `{source.label}` set to a static value `{obfuscated_label}`",
                            "Security Misconfiguration",
                            "misconfiguration-static",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.flask_config_message,
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
                            "misconfiguration-insecure",
                            "CWE-732",
                            "LOW",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.flask_config_message,
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
                            "misconfiguration-recommended",
                            "CWE-732",
                            "MEDIUM",
                            "a6-misconfiguration",
                            source,
                            sink,
                            rules.flask_config_message,
                        )
                    )

        # Check for flask security
        if not has_import("flask_security", ast_tree) and not has_import(
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
                    "misconfiguration-controls",
                    "CWE-732",
                    "LOW",
                    "a6-misconfiguration",
                    source,
                    sink,
                    rules.flask_nosec_message,
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
                        "Missing Security Controls",
                        "misconfiguration-controls",
                        "CWE-732",
                        "MEDIUM",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.flask_config_message,
                    )
                )
    return violations
