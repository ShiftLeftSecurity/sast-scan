"""Intelligently search Python source code"""
# https://github.com/takluyver/astsearch
import ast
import os.path
import sys
import tokenize
import warnings

import lib.pyt.core.astcheck as astcheck
from lib.pyt.core.astcheck import assert_ast_like

__version__ = "0.2.0"


class ASTPatternFinder(object):
    """Scans Python code for AST nodes matching pattern.

    :param ast.AST pattern: The node pattern to search for
    """

    def __init__(self, pattern):
        self.pattern = pattern

    def scan_ast(self, tree):
        """Walk an AST and yield nodes matching pattern.

        :param ast.AST tree: The AST in which to search
        """
        nodetype = type(self.pattern)
        for node in ast.walk(tree):
            if isinstance(node, nodetype) and astcheck.is_ast_like(node, self.pattern):
                yield node

    def scan_file(self, file):
        """Parse a file and yield AST nodes matching pattern.

        :param file: Path to a Python file, or a readable file object
        """
        if isinstance(file, str):
            with open(file, mode="rb") as f:
                tree = ast.parse(f.read())
        else:
            tree = ast.parse(file.read())
        yield from self.scan_ast(tree)

    def filter_subdirs(self, dirnames):
        dirnames[:] = [d for d in dirnames if d != "build"]

    def scan_directory(self, directory):
        """Walk files in a directory, yielding (filename, node) pairs matching
        pattern.

        :param str directory: Path to a directory to search

        Only files with a ``.py`` or ``.pyw`` extension will be scanned.
        """
        for dirpath, dirnames, filenames in os.walk(directory):
            self.filter_subdirs(dirnames)

            for filename in filenames:
                if filename.endswith((".py", ".pyw")):
                    filepath = os.path.join(dirpath, filename)
                    try:
                        for match in self.scan_file(filepath):
                            yield filepath, match
                    except SyntaxError as e:
                        warnings.warn("Failed to parse {}:\n{}".format(filepath, e))


def must_exist_checker(node, path):
    """Checker function to ensure a field is not empty"""
    if (node is None) or (node == []):
        raise astcheck.ASTMismatch(path, node, "non empty")


def must_not_exist_checker(node, path):
    """Checker function to ensure a field is empty"""
    if (node is not None) and (node != []):
        raise astcheck.ASTMismatch(path, node, "empty")


class ArgsDefChecker:
    """Checks the arguments of a function definition against pattern arguments."""

    def __init__(self, args, defaults, vararg, kwonly_args_dflts, koa_subset, kwarg):
        self.args = args
        self.defaults = defaults
        self.vararg = vararg
        self.kwonly_args_dflts = kwonly_args_dflts
        self.koa_subset = koa_subset
        self.kwarg = kwarg

    def __repr__(self):
        return (
            "astsearch.ArgsDefChecker(args={s.args}, defaults={s.defaults}, "
            "vararg={s.vararg}, kwonly_args_dflts={s.kwonly_args_dflts}, "
            "koa_subset={s.koa_subset}, kwarg={s.kwarg}"
        ).format(s=self)

    def __call__(self, sample_node, path):
        # Check positional-or-keyword args
        if self.args:
            if isinstance(self.args, list):
                astcheck._check_node_list(path + ["args"], sample_node.args, self.args)
            else:
                assert_ast_like(sample_node.args, self.args)

        # Check defaults for positional-or-keyword args
        if self.defaults:
            sample_args_w_defaults = sample_node.args[-len(sample_node.defaults) :]
            sample_arg_defaults = {
                a.arg: d for a, d in zip(sample_args_w_defaults, sample_node.defaults)
            }
            for argname, dflt in self.defaults:
                try:
                    sample_dflt = sample_arg_defaults[argname]
                except KeyError:
                    raise astcheck.ASTMismatch(
                        path + ["defaults", argname], "(missing default)", dflt
                    )
                else:
                    assert_ast_like(sample_dflt, dflt, path + ["defaults", argname])

        # *args
        if self.vararg:
            assert_ast_like(sample_node.vararg, self.vararg)

        # keyword-only arguments
        sample_kwonlyargs = {
            k.arg: (k, d)
            for k, d in zip(sample_node.kwonlyargs, sample_node.kw_defaults)
        }

        for template_arg, template_dflt in self.kwonly_args_dflts:
            argname = template_arg.arg
            try:
                sample_arg, sample_dflt = sample_kwonlyargs[argname]
            except KeyError:
                raise astcheck.ASTMismatch(
                    path + ["kwonlyargs"], "(missing)", "keyword arg %s" % argname
                )
            else:
                assert_ast_like(
                    sample_arg, template_arg, path + ["kwonlyargs", argname]
                )
                if template_dflt is not None:
                    assert_ast_like(
                        sample_dflt, template_dflt, path + ["kw_defaults", argname]
                    )

        # If keyword-only-args weren't wildcarded, then there shouldn't
        # be any more args in the sample than the template
        if not self.koa_subset:
            template_kwarg_names = {k.arg for k, d in self.kwonly_args_dflts}
            excess_names = set(sample_kwonlyargs) - template_kwarg_names
            if excess_names:
                raise astcheck.ASTMismatch(
                    path + ["kwonlyargs"], excess_names, "(not present in template)"
                )

        # **kwargs
        if self.kwarg:
            assert_ast_like(sample_node.kwarg, self.kwarg)


WILDCARD_NAME = "__astsearch_wildcard"
MULTIWILDCARD_NAME = "__astsearch_multiwildcard"


class TemplatePruner(ast.NodeTransformer):
    def visit_Name(self, node):
        if node.id == WILDCARD_NAME:
            return must_exist_checker  # Allow any node type for a wildcard
        elif node.id == MULTIWILDCARD_NAME:
            # This shouldn't happen, but users will probably confuse their
            # wildcards at times. If it's in a block, it should have been
            # transformed before it's visited.
            return must_exist_checker

        # Generalise names to allow attributes as well, because these are often
        # interchangeable.
        return astcheck.name_or_attr(node.id)

    def prune_wildcard(self, node, attrname, must_exist=False):
        """Prunes a plain string attribute if it matches WILDCARD_NAME"""
        if getattr(node, attrname, None) in (WILDCARD_NAME, MULTIWILDCARD_NAME):
            setattr(node, attrname, must_exist_checker)

    def prune_wildcard_body(self, node, attrname, must_exist=False):
        """Prunes a code block (e.g. function body) if it is a wildcard"""
        body = getattr(node, attrname, [])

        def _is_multiwildcard(n):
            return astcheck.is_ast_like(
                n, ast.Expr(value=ast.Name(id=MULTIWILDCARD_NAME))
            )

        if len(body) == 1 and _is_multiwildcard(body[0]):
            setattr(node, attrname, must_exist_checker)
            return

        # Find a ?? node within the block, and replace it with listmiddle
        for i, n in enumerate(body):
            if _is_multiwildcard(n):
                newbody = body[:i] + astcheck.listmiddle() + body[i + 1 :]
                setattr(node, attrname, newbody)

    def visit_Attribute(self, node):
        self.prune_wildcard(node, "attr")
        return self.generic_visit(node)

    def visit_Constant(self, node):
        # From Python 3.8, Constant nodes have a .kind attribute, which
        # distuingishes u"" from "": https://bugs.python.org/issue36280
        # astsearch isn't interested in that distinction.
        if hasattr(node, "kind"):
            del node.kind
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.prune_wildcard(node, "name")
        self.prune_wildcard_body(node, "body")
        return self.generic_visit(node)

    visit_ClassDef = visit_FunctionDef

    def visit_arguments(self, node):
        positional_final_wildcard = False
        for i, a in enumerate(node.args):
            if a.arg == MULTIWILDCARD_NAME:
                from_end = len(node.args) - (i + 1)
                if from_end == 0:
                    # Last positional argument - wildcard may extend to other groups
                    positional_final_wildcard = True

                args = (
                    self._visit_list(node.args[:i])
                    + astcheck.listmiddle()
                    + self._visit_list(node.args[i + 1 :])
                )
                break
        else:
            if node.args:
                args = self._visit_list(node.args)
            else:
                args = must_not_exist_checker

        defaults = [
            (a.arg, self.visit(d))
            for a, d in zip(node.args[-len(node.defaults) :], node.defaults)
            if a.arg not in {WILDCARD_NAME, MULTIWILDCARD_NAME}
        ]

        if node.vararg is None:
            if positional_final_wildcard:
                vararg = None
            else:
                vararg = must_not_exist_checker
        else:
            vararg = self.visit(node.vararg)

        kwonly_args_dflts = [
            (self.visit(a), (d if d is None else self.visit(d)))
            for a, d in zip(node.kwonlyargs, node.kw_defaults)
            if a.arg != MULTIWILDCARD_NAME
        ]

        koa_subset = (
            positional_final_wildcard and vararg is None and (not node.kwonlyargs)
        ) or any(a.arg == MULTIWILDCARD_NAME for a in node.kwonlyargs)

        if node.kwarg is None:
            if koa_subset:
                kwarg = None
            else:
                kwarg = must_not_exist_checker
        else:
            kwarg = self.visit(node.kwarg)

        return ArgsDefChecker(
            args=args,
            defaults=defaults,
            vararg=vararg,
            kwonly_args_dflts=kwonly_args_dflts,
            koa_subset=koa_subset,
            kwarg=kwarg,
        )

    def visit_arg(self, node):
        self.prune_wildcard(node, "arg")
        return self.generic_visit(node)

    def visit_If(self, node):
        self.prune_wildcard_body(node, "body")
        self.prune_wildcard_body(node, "orelse")
        return self.generic_visit(node)

    # All of these have body & orelse node lists
    visit_For = visit_While = visit_If

    def visit_Try(self, node):
        self.prune_wildcard_body(node, "body")
        self.prune_wildcard_body(node, "orelse")
        self.prune_wildcard_body(node, "finalbody")
        return self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.prune_wildcard(node, "name")
        self.prune_wildcard_body(node, "body")
        return self.generic_visit(node)

    def visit_With(self, node):
        self.prune_wildcard_body(node, "body")
        return self.generic_visit(node)

    def visit_Call(self, node):
        kwargs_are_subset = False
        for i, n in enumerate(node.args):
            if astcheck.is_ast_like(n, ast.Name(id=MULTIWILDCARD_NAME)):
                if i + 1 == len(node.args):
                    # Last positional argument - wildcard may extend to kwargs
                    kwargs_are_subset = True

                node.args = (
                    self._visit_list(node.args[:i])
                    + astcheck.listmiddle()
                    + self._visit_list(node.args[i + 1 :])
                )

                # Don't try to handle multiple multiwildcards
                break

        if kwargs_are_subset or any(k.arg == MULTIWILDCARD_NAME for k in node.keywords):
            template_keywords = [
                self.visit(k) for k in node.keywords if k.arg != MULTIWILDCARD_NAME
            ]

            def kwargs_checker(sample_keywords, path):
                sample_kwargs = {k.arg: k.value for k in sample_keywords}

                for k in template_keywords:
                    if k.arg == MULTIWILDCARD_NAME:
                        continue
                    if k.arg in sample_kwargs:
                        astcheck.assert_ast_like(
                            sample_kwargs[k.arg], k.value, path + [k.arg]
                        )
                    else:
                        raise astcheck.ASTMismatch(
                            path, "(missing)", "keyword arg %s" % k.arg
                        )

            if template_keywords:
                node.keywords = kwargs_checker
            else:
                # Shortcut if there are no keywords to check
                del node.keywords

        # In block contexts, we want to avoid checking empty lists (for optional
        # nodes), but here, an empty list should mean that there are no
        # arguments in that group. So we need to override the behaviour in
        # generic_visit
        if node.args == []:
            node.args = must_not_exist_checker
        if getattr(node, "keywords", None) == []:
            node.keywords = must_not_exist_checker
        return self.generic_visit(node)

    def prune_import_names(self, node):
        if len(node.names) == 1 and node.names[0].name == MULTIWILDCARD_NAME:
            del node.names
        else:
            for alias in node.names:
                self.visit_alias(alias)

    def visit_ImportFrom(self, node):
        self.prune_wildcard(node, "module")
        self.prune_import_names(node)
        if node.level == 0:
            del node.level
        return node

    def visit_Import(self, node):
        self.prune_import_names(node)
        return node

    def visit_alias(self, node):
        self.prune_wildcard(node, "name")
        if node.asname is None:
            del node.asname
        else:
            self.prune_wildcard(node, "asname")

    def generic_visit(self, node):
        # Copied from ast.NodeTransformer; changes marked PATCH
        for field, old_value in ast.iter_fields(node):
            old_value = getattr(node, field, None)
            if isinstance(old_value, list):
                new_values = []
                for value in old_value:
                    if isinstance(value, ast.AST):
                        value = self.visit(value)
                        if value is None:
                            continue
                        # PATCH: We want to put checker functions in the AST
                        # elif not isinstance(value, ast.AST):
                        elif isinstance(value, list):
                            # -------
                            new_values.extend(value)
                            continue
                    new_values.append(value)
                # PATCH: Delete field if list is empty
                if not new_values:
                    delattr(node, field)
                # ------
                old_value[:] = new_values
            elif isinstance(old_value, ast.AST):
                new_node = self.visit(old_value)
                if new_node is None:
                    delattr(node, field)
                else:
                    setattr(node, field, new_node)
        return node

    def _visit_list(self, vl):
        return [self.visit(n) for n in vl]


def prepare_pattern(s):
    """Turn a string pattern into an AST pattern

    This parses the string to an AST, and generalises it a bit for sensible
    matching. ``?`` is treated as a wildcard that matches anything. Names in
    the pattern will match names or attribute access (i.e. ``foo`` will match
    ``bar.foo`` in files).
    """
    s = s.replace("??", MULTIWILDCARD_NAME).replace("?", WILDCARD_NAME)
    pattern = ast.parse(s).body[0]
    if isinstance(pattern, ast.Expr):
        pattern = pattern.value
    if isinstance(pattern, (ast.Attribute, ast.Subscript)):
        # If the root of the pattern is like a.b or a[b], we want to match it
        # regardless of context: `a.b=2` and `del a.b` should match as well as
        # `c = a.b`
        del pattern.ctx
    return TemplatePruner().visit(pattern)


def main(argv=None):
    """Run astsearch from the command line.

    :param list argv: Command line arguments; defaults to :data:`sys.argv`
    """
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("pattern", help="AST pattern to search for; see docs for examples")
    ap.add_argument(
        "path", nargs="?", default=".", help="file or directory to search in"
    )
    ap.add_argument(
        "-l",
        "--files-with-matches",
        action="store_true",
        help="output only the paths of matching files, not the " "lines that matched",
    )
    ap.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)

    args = ap.parse_args(argv)
    ast_pattern = prepare_pattern(args.pattern)
    if args.debug:
        print(ast.dump(ast_pattern))

    patternfinder = ASTPatternFinder(ast_pattern)

    def _printline(node, filelines):
        print("{:>4}|{}".format(node.lineno, filelines[node.lineno - 1].rstrip()))

    current_filelines = []
    if os.path.isdir(args.path):
        # Search directory
        current_filepath = None
        if args.files_with_matches:
            for filepath, node in patternfinder.scan_directory(args.path):
                if filepath != current_filepath:
                    print(filepath)
                    current_filepath = filepath
        else:
            for filepath, node in patternfinder.scan_directory(args.path):
                if filepath != current_filepath:
                    with tokenize.open(filepath) as f:
                        current_filelines = f.readlines()
                    if current_filepath is not None:
                        print()  # Blank line between files
                    current_filepath = filepath
                    print(filepath)
                _printline(node, current_filelines)

    elif os.path.exists(args.path):
        # Search file
        if args.files_with_matches:
            try:
                node = next(patternfinder.scan_file(args.path))
            except StopIteration:
                pass
            else:
                print(args.path)
        else:
            for node in patternfinder.scan_file(args.path):
                if not current_filelines:
                    with tokenize.open(args.path) as f:
                        current_filelines = f.readlines()
                _printline(node, current_filelines)

    else:
        sys.exit("No such file or directory: {}".format(args.path))


if __name__ == "__main__":
    main()
