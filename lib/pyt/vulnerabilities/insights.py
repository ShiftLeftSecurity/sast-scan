import ast
import os
import sys
from collections import namedtuple

import lib.pyt.vulnerabilities.rules as rules
from lib.logger import LOG
from lib.pyt.core.ast_helper import (
    get_assignments_as_dict,
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
        "description",
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


def _check_django_common_misconfig(ast_tree, path):
    """Look for common security misconfiguration in Django apps
    """
    violations = []
    config_dict = get_assignments_as_dict("?=?", ast_tree)
    is_django = (
        has_import_like("django", ast_tree)
        or "INSTALLED_APPS" in config_dict.keys()
        or "MIDDLEWARE_CLASSES" in config_dict.keys()
    )
    if os.path.basename(path) == "settings.py" and is_django:
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
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.django_config_message,
                    )
                )
    return violations


def _check_flask_common_misconfig(ast_tree, path):
    """Look for common security misconfiguration in Flask apps
    """
    violations = []
    has_flask_run = has_method_call("app.run(??)", ast_tree)
    if has_import("flask", ast_tree) and has_flask_run:
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
                        "LOW",
                        "a6-misconfiguration",
                        source,
                        sink,
                        rules.flask_config_message,
                    )
                )

        # Check for flask security
        if not has_import("flask_security", ast_tree):
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
                    "Consider adding Flask-Security or any alternative security extension to your Flask apps",
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
    return violations
