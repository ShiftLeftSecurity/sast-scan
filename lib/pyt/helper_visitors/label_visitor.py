import ast
import sys


class LabelVisitor(ast.NodeVisitor):
    def __init__(self):
        self.result = ""

    def handle_comma_separated(self, comma_separated_list):
        if comma_separated_list:
            for element in range(len(comma_separated_list) - 1):
                self.visit(comma_separated_list[element])
                self.result += ", "

            self.visit(comma_separated_list[-1])

    def visit_Tuple(self, node):
        self.result += "("

        self.handle_comma_separated(node.elts)

        self.result += ")"

    def visit_List(self, node):
        self.result += "["

        self.handle_comma_separated(node.elts)

        self.result += "]"

    def visit_Raise(self, node):
        self.result += "raise"
        if node.exc:
            self.result += " "
            self.visit(node.exc)
        if node.cause:
            self.result += " from "
            self.visit(node.cause)

    def visit_withitem(self, node):
        self.result += "with "
        self.visit(node.context_expr)
        if node.optional_vars:
            self.result += " as "
            self.visit(node.optional_vars)

    def visit_Return(self, node):
        if node.value:
            self.visit(node.value)

    def visit_Assign(self, node):
        for target in node.targets:
            self.visit(target)
        self.result = " ".join((self.result, "="))
        self.insert_space()

        self.visit(node.value)

    def visit_AugAssign(self, node):
        self.visit(node.target)

        self.insert_space()
        self.visit(node.op)
        self.result += "="
        self.insert_space()
        self.visit(node.value)

    def visit_Compare(self, node):
        self.visit(node.left)
        self.insert_space()

        for op, com in zip(node.ops, node.comparators):
            self.visit(op)
            self.insert_space()
            self.visit(com)
            self.insert_space()

        self.result = self.result.rstrip()

    def visit_BinOp(self, node):
        self.visit(node.left)

        self.insert_space()
        self.visit(node.op)
        self.insert_space()

        self.visit(node.right)

    def visit_UnaryOp(self, node):
        self.visit(node.op)
        self.visit(node.operand)

    def visit_BoolOp(self, node):
        for i, value in enumerate(node.values):
            if i == len(node.values) - 1:
                self.visit(value)
            else:
                self.visit(value)
                self.visit(node.op)

    def comprehensions(self, node):
        self.visit(node.elt)

        for expression in node.generators:
            self.result += " for "
            self.visit(expression.target)
            self.result += " in "
            self.visit(expression.iter)

    def visit_GeneratorExp(self, node):
        self.result += "("
        self.comprehensions(node)
        self.result += ")"

    def visit_ListComp(self, node):
        self.result += "["
        self.comprehensions(node)
        self.result += "]"

    def visit_SetComp(self, node):
        self.result += "{"
        self.comprehensions(node)
        self.result += "}"

    def visit_DictComp(self, node):
        self.result += "{"

        self.visit(node.key)
        self.result += " : "
        self.visit(node.value)

        for expression in node.generators:
            self.result += " for "
            self.visit(expression.target)
            self.result += " in "
            self.visit(expression.iter)

        self.result += "}"

    def visit_Attribute(self, node):
        self.visit(node.value)
        self.result += "."
        self.result += node.attr

    def visit_Call(self, node):
        self.visit(node.func)
        self.result += "("

        if node.keywords and node.args:
            self.handle_comma_separated(node.args)
            self.result += ","
        else:
            self.handle_comma_separated(node.args)
        self.handle_comma_separated(node.keywords)
        self.result += ")"

    def visit_keyword(self, node):
        if node.arg:
            self.result += node.arg
            self.result += "="
        self.visit(node.value)

    def insert_space(self):
        self.result += " "

    def visit_Constant(self, node):
        self.result += str(node.value)

    def visit_Subscript(self, node):
        self.visit(node.value)

        self.result += "["

        self.slicev(node.slice)

        self.result += "]"

    def slicev(self, node):
        if isinstance(node, ast.Slice):
            if node.lower:
                self.visit(node.lower)
            if node.upper:
                self.visit(node.upper)
            if node.step:
                self.visit(node.step)
        elif isinstance(node, ast.ExtSlice):
            if node.dims:
                for d in node.dims:
                    self.visit(d)
        else:
            if sys.version_info.major == 3 and sys.version_info.minor == 9:
                self.visit(node)
            else:
                self.visit(node.value)

    #  operator = Add | Sub | Mult | MatMult | Div | Mod | Pow | LShift | RShift | BitOr | BitXor | BitAnd | FloorDiv
    def visit_Add(self, node):
        self.result += "+"

    def visit_Sub(self, node):
        self.result += "-"

    def visit_Mult(self, node):
        self.result += "*"

    def vist_MatMult(self, node):
        self.result += "x"

    def visit_Div(self, node):
        self.result += "/"

    def visit_Mod(self, node):
        self.result += "%"

    def visit_Pow(self, node):
        self.result += "**"

    def visit_LShift(self, node):
        self.result += "<<"

    def visit_RShift(self, node):
        self.result += ">>"

    def visit_BitOr(self, node):
        self.result += "|"

    def visit_BitXor(self, node):
        self.result += "^"

    def visit_BitAnd(self, node):
        self.result += "&"

    def visit_FloorDiv(self, node):
        self.result += "//"

    # cmpop = Eq | NotEq | Lt | LtE | Gt | GtE | Is | IsNot | In | NotIn
    def visit_Eq(self, node):
        self.result += "=="

    def visit_Gt(self, node):
        self.result += ">"

    def visit_Lt(self, node):
        self.result += "<"

    def visit_NotEq(self, node):
        self.result += "!="

    def visit_GtE(self, node):
        self.result += ">="

    def visit_LtE(self, node):
        self.result += "<="

    def visit_Is(self, node):
        self.result += "is"

    def visit_IsNot(self, node):
        self.result += "is not"

    def visit_In(self, node):
        self.result += "in"

    def visit_NotIn(self, node):
        self.result += "not in"

    # unaryop = Invert | Not | UAdd | USub
    def visit_Invert(self, node):
        self.result += "~"

    def visit_Not(self, node):
        self.result += "not "

    def visit_UAdd(self, node):
        self.result += "+"

    def visit_USub(self, node):
        self.result += "-"

    # boolop = And | Or
    def visit_And(self, node):
        self.result += " and "

    def visit_Or(self, node):
        self.result += " or "

    def visit_Num(self, node):
        self.result += str(node.n)

    def visit_Name(self, node):
        self.result += node.id

    def visit_Str(self, node):
        self.result += "'" + node.s + "'"

    def visit_joined_str(self, node, surround=True):
        for val in node.values:
            if isinstance(val, ast.Str):
                self.result += val.s
            else:
                self.visit(val)

    def visit_JoinedStr(self, node):
        """
        JoinedStr(expr* values)
        """
        self.result += "f'"
        self.visit_joined_str(node)
        self.result += "'"

    def visit_FormattedValue(self, node):
        """
        FormattedValue(expr value, int? conversion, expr? format_spec)
        """
        self.result += "{"
        self.visit(node.value)
        self.result += {
            -1: "",  # no formatting
            97: "!a",  # ascii formatting
            114: "!r",  # repr formatting
            115: "!s",  # string formatting
        }[node.conversion]
        if node.format_spec:
            self.result += ":"
            self.visit_joined_str(node.format_spec)
        self.result += "}"

    def visit_Starred(self, node):
        self.result += "*"
        self.visit(node.value)

    def visit_IfExp(self, node):
        self.result += "("
        self.visit(node.test)
        self.result += ") ? ("
        self.visit(node.body)
        self.result += ") : ("
        self.visit(node.orelse)
        self.result += ")"
