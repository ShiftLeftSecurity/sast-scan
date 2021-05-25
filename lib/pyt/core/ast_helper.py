"""This module contains helper function.
Useful when working with the ast module."""
import ast
import codecs
import logging
import os
import subprocess
from functools import lru_cache

from _ast import AST

from lib.pyt.core.astsearch import ASTPatternFinder, prepare_pattern
from lib.pyt.core.transformer import PytTransformer

log = logging.getLogger(__name__)
BLACK_LISTED_CALL_NAMES = ["self"]
recursive = False


def _convert_to_3(path):  # pragma: no cover
    """Convert python 2 file to python 3."""
    try:
        subprocess.call(["2to3", "-w", path])
    except Exception:
        log.debug(
            "Check if 2to3 is installed. https://docs.python.org/2/library/2to3.html"
        )


@lru_cache()
def generate_py2_ast(path):
    """Generate an Abstract Syntax Tree using the ast module for python 2 code

    Args:
        path(str): The path to the file e.g. example/foo/bar.py
    """
    if os.path.isfile(path) and os.path.getsize(path):
        with open(path, mode="r", encoding="utf-8") as f:
            return generate_ast_from_code(f.read())
    return None


@lru_cache()
def generate_ast(path):
    """Generate an Abstract Syntax Tree using the ast module.

    Args:
        path(str): The path to the file e.g. example/foo/bar.py
    """
    if os.path.isfile(path) and os.path.getsize(path):
        with open(path, mode="r", encoding="utf-8") as f:
            return generate_ast_from_code(f.read(), path)
    return None


def generate_ast_from_code(code, path=None):
    """Generate an Abstract Syntax Tree using the ast module.

    Args:
        code(str): Code snippet
    """
    try:
        tree = ast.parse(code)
        return PytTransformer().visit(tree) if tree else None
    except SyntaxError:  # pragma: no cover
        global recursive
        if not recursive and path:
            recursive = True
            return generate_py2_ast(path)
        else:
            return None
    return None


def _get_call_names_helper(node):
    """Recursively finds all function names."""
    if isinstance(node, ast.Name):
        if node.id not in BLACK_LISTED_CALL_NAMES:
            yield node.id
    elif isinstance(node, ast.Subscript):
        yield from _get_call_names_helper(node.value)
    elif isinstance(node, ast.Str):
        yield node.s
    elif isinstance(node, ast.Attribute):
        yield node.attr
        yield from _get_call_names_helper(node.value)


def get_call_names(node):
    """Get a list of call names."""
    return reversed(list(_get_call_names_helper(node)))


def _list_to_dotted_string(list_of_components):
    """Convert a list to a string seperated by a dot."""
    return ".".join(list_of_components)


def get_call_names_as_string(node):
    """Get a list of call names as a string."""
    return _list_to_dotted_string(get_call_names(node))


def _get_matches(pattern, ast_tree):
    return list(ASTPatternFinder(pattern).scan_ast(ast_tree))


def get_comparison_as_dict(pattern, ast_tree):
    pat = prepare_pattern(pattern)
    node_list = _get_matches(pat, ast_tree)
    literals_dict = {}
    for node in node_list:
        if isinstance(node, ast.Compare):
            left_hand_side = node.comparators[0]
            right_hand_side = node.comparators[-1]
            key = ""
            if isinstance(left_hand_side, ast.Name):
                key = left_hand_side.id
            elif isinstance(left_hand_side, ast.Attribute):
                key = left_hand_side.attr
            if key:
                literals_dict[key] = {
                    "left_hand_side": left_hand_side,
                    "right_hand_side": right_hand_side,
                }
    return literals_dict


def get_assignments_as_dict(pattern, ast_tree):
    pat = prepare_pattern(pattern)
    node_list = _get_matches(pat, ast_tree)
    literals_dict = {}
    if not node_list:
        return literals_dict
    for node in node_list:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                left_hand_side = target
                right_hand_side = node.value
                if isinstance(right_hand_side, ast.Call):
                    right_hand_side = node.value.func
                if isinstance(right_hand_side, ast.Constant):
                    right_hand_side = node.value
                if isinstance(target, ast.Subscript):
                    # python 3.9 fix
                    if isinstance(target.slice.value, str):
                        left_hand_side = target.slice
                    else:
                        left_hand_side = target.slice.value
                key = ""
                if isinstance(left_hand_side, ast.Attribute):
                    key = left_hand_side.attr
                elif hasattr(left_hand_side, "value"):
                    key = left_hand_side.value
                elif hasattr(left_hand_side, "id"):
                    key = left_hand_side.id
                if key:
                    literals_dict[key] = {
                        "left_hand_side": left_hand_side,
                        "right_hand_side": right_hand_side,
                    }
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if isinstance(keyword.value, ast.Constant):
                    literals_dict[keyword.arg] = {
                        "left_hand_side": keyword,
                        "right_hand_side": keyword.value,
                    }
    return literals_dict


def get_as_list(ast_list):
    ret = []
    if not ast_list:
        return ret
    if isinstance(ast_list, (ast.List, ast.Tuple)):
        for li in ast_list.elts:
            if isinstance(li, ast.Constant):
                ret.append(li.value)
    return ret


def is_static_assignment(left_hand_side, right_hand_side):
    ret = False
    if (
        left_hand_side
        and right_hand_side
        and isinstance(left_hand_side, ast.Constant)
        and isinstance(right_hand_side, ast.Constant)
    ):
        left_value = left_hand_side.value
        right_value = right_hand_side.value
        if isinstance(left_value, str) and isinstance(right_value, str):
            ret = True
    return ret


def has_import_like(module_name, ast_tree):
    pat = prepare_pattern("import ??")
    matches = _get_matches(pat, ast_tree)
    if not matches:
        pat = prepare_pattern("from ?? import ??")
        matches = _get_matches(pat, ast_tree)
    if not matches:
        return False
    ret = False
    for match in matches:
        if isinstance(match, (ast.Import, ast.ImportFrom)):
            for name in match.names:
                if name.name.lower().startswith(module_name.lower()):
                    return True
    # Repeat with from lookup
    if not ret:
        pat = prepare_pattern("from ?? import ??")
        matches = _get_matches(pat, ast_tree)
    for match in matches:
        if isinstance(match, ast.ImportFrom):
            if match.module.lower().startswith(module_name.lower()):
                return True
            for name in match.names:
                if name.name.lower().startswith(module_name.lower()):
                    return True
    return ret


def has_import(module_name, ast_tree):
    pat = prepare_pattern(f"import {module_name}")
    matches = _get_matches(pat, ast_tree)
    if not matches:
        pat = prepare_pattern(f"from {module_name} import ??")
        matches = _get_matches(pat, ast_tree)
    if not matches:
        return False
    for match in matches:
        if isinstance(match, (ast.Import, ast.ImportFrom)):
            for name in match.names:
                if name.name.lower() == module_name.lower():
                    return True
    return False


def has_method_call(pattern, ast_tree):
    pat = prepare_pattern(pattern)
    node_list = _get_matches(pat, ast_tree)
    for node in node_list:
        if isinstance(node, ast.Call):
            return True
    return False


def get_method_as_dict(pattern, ast_tree):
    pat = prepare_pattern(pattern)
    node_list = _get_matches(pat, ast_tree)
    if not node_list:
        return None
    invocations = []
    for node in node_list:
        if isinstance(node, ast.Call):
            node_obj = ast2dict(node)
            invocations.append(node_obj)
    return invocations


BUILTIN_PURE = (int, float, bool)
BUILTIN_BYTES = (bytearray, bytes)
BUILTIN_STR = str


def decode_str(value):
    return value


def decode_bytes(value):
    try:
        return value.decode("utf-8")
    except Exception:
        return codecs.getencoder("hex_codec")(value)[0].decode("utf-8")


def ast2dict(node):
    assert isinstance(node, AST)
    to_return = dict()
    to_return["_type"] = node.__class__.__name__
    for attr in dir(node):
        if attr.startswith("_"):
            continue
        to_return[attr] = get_value(getattr(node, attr))
    return to_return


def get_value(attr_value):
    if attr_value is None:
        return attr_value
    if isinstance(attr_value, BUILTIN_PURE):
        return attr_value
    if isinstance(attr_value, BUILTIN_BYTES):
        return decode_bytes(attr_value)
    if isinstance(attr_value, BUILTIN_STR):
        return decode_str(attr_value)
    if isinstance(attr_value, complex):
        return str(attr_value)
    if isinstance(attr_value, list):
        return [get_value(x) for x in attr_value]
    if isinstance(attr_value, AST):
        return ast2dict(attr_value)
    else:
        raise Exception(
            "unknown case for '%s' of type '%s'" % (attr_value, type(attr_value))
        )


class Arguments:
    """Represents arguments of a function."""

    def __init__(self, args):
        """Argument container class.

        Args:
            args(list(ast.args): The arguments in a function AST node.
        """
        self.args = args.args
        self.varargs = args.vararg
        self.kwarg = args.kwarg
        self.kwonlyargs = args.kwonlyargs
        self.defaults = args.defaults
        self.kw_defaults = args.kw_defaults

        self.arguments = list()
        if self.args:
            self.arguments.extend([x.arg for x in self.args])
        if self.varargs:
            self.arguments.extend(self.varargs.arg)
        if self.kwarg:
            self.arguments.extend(self.kwarg.arg)
        if self.kwonlyargs:
            self.arguments.extend([x.arg for x in self.kwonlyargs])

    def __getitem__(self, key):
        return self.arguments.__getitem__(key)

    def __len__(self):
        return self.args.__len__()
