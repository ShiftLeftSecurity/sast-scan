"""Provides helper functions that help with determining if a function is a route function."""
import ast
import json
import os

from lib.pyt.core.ast_helper import get_call_names

default_blackbox_mapping_file = os.path.join(
    os.path.dirname(__file__),
    "..",
    "vulnerability_definitions",
    "blackbox_mapping.json",
)
safe_decorators = []
with open(default_blackbox_mapping_file) as fp:
    bb_mapping = json.load(fp)
    safe_decorators = bb_mapping.get("safe_decorators")


def is_django_view_function(ast_node):
    if len(ast_node.args.args):
        first_arg_name = ast_node.args.args[0].arg
        return first_arg_name == "request"
    return False


def is_flask_route_function(ast_node):
    """Check whether function uses a route decorator."""
    for decorator in ast_node.decorator_list:
        if isinstance(decorator, ast.Call):
            if _get_last_of_iterable(get_call_names(decorator.func)) == "route":
                return True
    return False


def is_taintable_function(ast_node):
    """Returns only functions without a sanitization decorator"""
    for decorator in ast_node.decorator_list:
        if isinstance(decorator, ast.Call):
            if _get_last_of_iterable(get_call_names(decorator.func)) in safe_decorators:
                return False
            # Flask route and Django tag
            if _get_last_of_iterable(get_call_names(decorator.func)) in [
                "route",
                "errorhandler",
                "simple_tag",
                "inclusion_tag",
                "to_end_tag",
                "expose",
                "view_config",
                "template",
                "get",
                "post",
                "put",
                "delete",
                "middleware",
                "api_view",
                "action",
                "csrf_exempt",
                "deserialise_with",
                "marshal_with",
                "before",
                "csrf_protect",
                "requires_csrf_token",
                "xframe_options_exempt",
                "xframe_options_deny",
                "xframe_options_sameorigin",
                "before_first_request",
                "receiver",
                "require_http_methods",
                "application",
                "command",
                "option",
                "group",
                "argument",
            ]:
                return True
    # Ignore database functions
    if len(ast_node.args.args):
        first_arg_name = ast_node.args.args[0].arg
        if first_arg_name == "self" and len(ast_node.args.args) > 1:
            first_arg_name = ast_node.args.args[1].arg
        # Common view functions such as django, starlette, falcon
        if first_arg_name in ["req", "request", "context", "scope", "environ"]:
            return True
        # Ignore dao classes due to potential FP
        if first_arg_name in ["conn", "connection", "cls", "session", "session_cls"]:
            return False
    # Ignore internal functions prefixed with _
    if is_function_with_leading_(ast_node):
        return False
    # Ignore known validation and sanitization functions
    for n in ["valid", "sanitize", "sanitise", "is_", "set_", "assert"]:
        if n in ast_node.name:
            return False
    # Should we limit the scan only to web routes?
    web_route_only = os.environ.get("WEB_ROUTE_ONLY", False)
    if web_route_only:
        return False
    return True


def is_function_with_leading_(ast_node):
    if ast_node.name.startswith("_"):
        return True
    return False


def _get_last_of_iterable(iterable):
    """Get last element of iterable."""
    item = None
    for item in iterable:
        pass
    return item
