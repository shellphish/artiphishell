"""The ply parser definitions for the query language.

You only care about ``expr_parser.parse(str)``.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring

from typing import List, Tuple, Union
from dataclasses import dataclass
from enum import Enum, auto

from ply import lex, yacc
from typing_extensions import TypeAlias

# Token definitions
tokens = (
    "KW_FN",
    "KW_LET",
    "STRING_LITERAL",
    "INT_LITERAL",
    "BOOL_LITERAL",
    "KEY_LITERAL",
    "IDENTIFIER",
    "OR",
    "AND",
    "PLUS",
    "MINUS",
    "TIMES",
    "DIVIDE",
    "MODULUS",
    "AMPERSAND",
    "CARET",
    "PIPE",
    "EQ",
    "NEQ",
    "GT",
    "LT",
    "GEQ",
    "LEQ",
    "LPAREN",
    "RPAREN",
    "LBRACKET",
    "RBRACKET",
    "LBRACE",
    "RBRACE",
    "COMMA",
    "DOT",
    "NOT",
    "TILDE",
    "SEMI",
    "ARROW",
    "COLON",
    "ASSIGN",
    "QUESTION",
)

# Regular expressions for tokens
t_STRING_LITERAL = r'"[^"]*"'
t_INT_LITERAL = r"[+-]?\d+"
t_BOOL_LITERAL = r"true|false"
t_KEY_LITERAL = r"`[a-zA-Z0-9_]*`"
t_OR = r"\|\|"
t_AND = r"&&"
t_PLUS = r"\+"
t_MINUS = r"-"
t_TIMES = r"\*"
t_DIVIDE = r"/"
t_MODULUS = r"%"
t_AMPERSAND = r"&"
t_CARET = r"\^"
t_PIPE = r"\|"
t_EQ = r"=="
t_NEQ = r"!="
t_GT = r">"
t_LT = r"<"
t_GEQ = r">="
t_LEQ = r"<="
t_LPAREN = r"\("
t_RPAREN = r"\)"
t_LBRACKET = r"\["
t_RBRACKET = r"\]"
t_LBRACE = r"\{"
t_RBRACE = r"\}"
t_COMMA = r","
t_DOT = r"\."
t_NOT = r"!"
t_TILDE = r"~"
t_SEMI = r";"
t_ARROW = r"->"
t_COLON = r":"
t_ASSIGN = r"="
t_QUESTION = r"\?"
t_ignore = " \t"

reserved = {
    "fn": "KW_FN",
    "let": "KW_LET",
    "true": "BOOL_LITERAL",
    "false": "BOOL_LITERAL",
}


def t_IDENTIFIER(t):
    r"[a-zA-Z_][a-zA-Z0-9_]*"
    t.type = reserved.get(t.value, "IDENTIFIER")
    return t


def t_newline(t):
    r"\n+"
    t.lexer.lineno += len(t.value)


def t_error(t):
    raise SyntaxError(f"Illegal character '{t.value[0]}'")


lexer = lex.lex()
lexer.line_start = 0

# Define precedence and associativity
precedence = (
    ("left", "SEMI"),
    ("left", "OR"),
    ("left", "AND"),
    ("left", "PIPE"),
    ("left", "CARET"),
    ("left", "AMPERSAND"),
    ("left", "EQ", "NEQ"),
    ("left", "LT", "LEQ", "GT", "GEQ"),
    ("left", "PLUS", "MINUS"),
    ("left", "TIMES", "DIVIDE", "MODULUS"),
    ("right", "UMINUS", "NOT", "TILDE"),
    ("right", "COLON", "QUESTION"),
    ("left", "LBRACKET", "RBRACKET"),
    ("left", "DOT"),
)


def p_expr_def(p):
    "expr : defn SEMI expr"
    if isinstance(p[3], ScopedExpression):
        p[0] = p[3]
    else:
        p[0] = ScopedExpression([], [], p[3])
    p[0].value_defns = p[1][0] + p[0].value_defns
    p[0].func_defns = p[1][1] + p[0].func_defns


def p_defn_fn_notemplate(p):
    "defn : KW_FN IDENTIFIER LPAREN typarams RPAREN ARROW tyexpr COLON expr"
    p[0] = [], [
        (p[2], FunctionDefinition([], [x[0] for x in p[4]], FunctionType((), tuple(x[1] for x in p[4]), p[7]), p[9]))
    ]


def p_defn_fn_yestemplate(p):
    "defn : KW_FN IDENTIFIER LBRACKET typarams RBRACKET LPAREN typarams RPAREN ARROW tyexpr COLON expr"
    p[0] = [], [
        (
            p[2],
            FunctionDefinition(
                [x[0] for x in p[4]],
                [x[0] for x in p[7]],
                FunctionType(tuple(x[1] for x in p[4]), tuple(x[1] for x in p[7]), p[10]),
                p[12],
            ),
        )
    ]


def p_defn_let(p):
    "defn : KW_LET IDENTIFIER ASSIGN expr"
    p[0] = [(p[2], p[4])], []


def p_typarams_empty(p):
    "typarams :"
    p[0] = []


def p_typarams_one(p):
    "typarams : typaram"
    p[0] = [p[1]]


def p_typarams_multiple(p):
    "typarams : typaram COMMA typarams"
    p[0] = [p[1]] + p[3]


def p_tyexprs_empty(p):
    "tyexprs :"
    p[0] = []


def p_tyexprs_one(p):
    "tyexprs : tyexpr"
    p[0] = [p[1]]


def p_tyexprs_multiple(p):
    "tyexprs : tyexpr COMMA tyexprs"
    p[0] = [p[1]] + p[3]


def p_typaram(p):
    "typaram : IDENTIFIER COLON tyexpr"
    p[0] = (p[1], p[3])


def p_tyexpr_basic(p):
    "tyexpr : IDENTIFIER"
    p[0] = tyexpr_basic_to_type(p[1])


def tyexpr_basic_to_type(s: str) -> "QueryValueType":
    if s == "Bool":
        return QueryValueType.Bool
    elif s == "Int":
        return QueryValueType.Int
    elif s == "Str":
        return QueryValueType.String
    elif s == "Key":
        return QueryValueType.Key
    elif s == "List":
        return QueryValueType.List
    elif s == "Repo":
        return QueryValueType.Repository
    elif s == "Data":
        return QueryValueType.RepositoryData
    else:
        raise ValueError(f"Bad type: {s}")


def p_tyexpr_fn_notemplate(p):
    "tyexpr : KW_FN LPAREN tyexprs RPAREN ARROW tyexpr"
    p[0] = FunctionType((), p[3], p[6])


def p_tyexpr_fn_yestemplate(p):
    "tyexpr : KW_FN LBRACKET tyexprs RBRACKET LPAREN tyexprs RPAREN ARROW tyexpr"
    p[0] = FunctionType(p[3], p[6], p[9])


def p_expr_name(p):
    "expr : IDENTIFIER"
    p[0] = IdentExpression(p[1])


def p_expr_stringlit(p):
    """expr : STRING_LITERAL"""
    p[0] = StringLiteral(p[1][1:-1])


def p_expr_intlit(p):
    """expr : INT_LITERAL"""
    p[0] = IntLiteral(int(p[1], 0))


def p_expr_boollit(p):
    """expr : BOOL_LITERAL"""
    p[0] = BoolLiteral(p[1] == "true")


def p_expr_keylit(p):
    """expr : KEY_LITERAL"""
    p[0] = KeyLiteral(p[1][1:-1])


def p_expr_list(p):
    """expr : LBRACE args RBRACE"""
    p[0] = ListLiteral(p[2])


def p_expr_index(p):
    """expr : expr LBRACKET expr RBRACKET"""
    p[0] = FunctionCall(FuncExpr("__index__", []), [p[1], p[3]])


def p_expr_binop(p):
    """expr : expr OR expr
    | expr AND expr
    | expr PLUS expr
    | expr MINUS expr
    | expr TIMES expr
    | expr DIVIDE expr
    | expr MODULUS expr
    | expr AMPERSAND expr
    | expr CARET expr
    | expr PIPE expr
    | expr EQ expr
    | expr NEQ expr
    | expr GT expr
    | expr LT expr
    | expr GEQ expr
    | expr LEQ expr"""
    p[0] = FunctionCall(FuncExpr(BINOP_TOKEN_MAPPING[p[2]], []), [p[1], p[3]])


def p_expr_unop(p):
    """expr : NOT expr
    | TILDE expr
    | PLUS expr %prec UMINUS
    | MINUS expr %prec UMINUS"""
    p[0] = FunctionCall(FuncExpr(UNOP_TOKEN_MAPPING[p[1]], []), [p[2]])


def p_expr_parentheses(p):
    "expr : LPAREN expr RPAREN"
    p[0] = p[2]


def p_expr_function_call(p):
    "expr : funcexpr LPAREN args RPAREN"
    p[0] = FunctionCall(p[1], p[3])


def p_expr_method_call(p):
    "expr : expr funcexpr LPAREN args RPAREN"
    p[0] = FunctionCall(p[2], [p[1]] + p[4])


def p_expr_ternary(p):
    "expr : expr QUESTION expr COLON expr"
    p[0] = TernaryExpr(p[1], p[3], p[5])


def p_funcexpr_template(p):
    "funcexpr : DOT IDENTIFIER LBRACKET tempargs RBRACKET"
    p[0] = FuncExpr(p[2], p[4])


def p_funcexpr_notemplate(p):
    "funcexpr : DOT IDENTIFIER"
    p[0] = FuncExpr(p[2], [])


def p_args_empty(p):
    "args :"
    p[0] = []


def p_args_one(p):
    "args : expr"
    p[0] = [p[1]]


def p_args_multiple(p):
    "args : expr COMMA args"
    p[0] = [p[1]] + p[3]


def p_tempargs_empty(p):
    "tempargs :"
    p[0] = []


def p_tempargs_one(p):
    "tempargs : tempexpr"
    p[0] = [p[1]]


def p_tempargs_multiple(p):
    "tempargs : tempexpr COMMA tempargs"
    p[0] = [p[1]] + p[3]


def p_tempexpr(p):
    """
    tempexpr : funcexpr
             | expr
    """
    p[0] = p[1]


def p_error(p):
    # AUGH GIVE ME COLUMN NUMBER
    raise SyntaxError(f"Syntax error at line {p.lineno}, position {p.lexpos}: Unexpected token '{p.value}'")


BINOP_TOKEN_MAPPING = {
    "+": "__add__",
    "-": "__sub__",
    "*": "__mul__",
    "/": "__div__",
    "%": "__mod__",
    "&": "__bitand__",
    "|": "__bitor__",
    "^": "__bitxor__",
    "&&": "__logand__",
    "||": "__logor__",
    "==": "__eq__",
    "!=": "__ne__",
    ">": "__gt__",
    "<": "__lt__",
    ">=": "__ge__",
    "<=": "__le__",
}


UNOP_TOKEN_MAPPING = {
    "~": "__inv__",
    "!": "__not__",
    "-": "__neg__",
    "+": "__plus__",
}


@dataclass
class Expression:
    pass


@dataclass
class IdentExpression(Expression):
    name: str


@dataclass
class StringLiteral(Expression):
    value: str


@dataclass
class KeyLiteral(Expression):
    value: str


@dataclass
class IntLiteral(Expression):
    value: int


@dataclass
class BoolLiteral(Expression):
    value: bool


@dataclass
class FuncExpr:
    name: str
    template_args: List[Union["FuncExpr", Expression]]


@dataclass
class FunctionCall(Expression):
    function: FuncExpr
    args: List[Expression]


@dataclass
class TernaryExpr(Expression):
    condition: Expression
    iftrue: Expression
    iffalse: Expression


@dataclass
class ListLiteral(Expression):
    values: List[Expression]


class QueryValueType(Enum):
    """The enum for the kinds of types which are representable in the query language."""

    Bool = auto()
    Int = auto()
    String = auto()
    Key = auto()
    List = auto()
    Repository = auto()
    RepositoryData = auto()


ArgTypes: TypeAlias = Tuple[QueryValueType, ...]
TemplateType: TypeAlias = Union["FunctionType", QueryValueType]
TemplateTypes: TypeAlias = Tuple[TemplateType, ...]


@dataclass(frozen=True)
class FunctionType:
    template_types: TemplateTypes
    arg_types: ArgTypes
    return_type: QueryValueType

    def strip_template(self) -> "FunctionType":
        return FunctionType((), self.arg_types, self.return_type)


@dataclass
class FunctionDefinition:
    template_names: List[str]
    arg_names: List[str]
    type: FunctionType
    body: Expression


@dataclass
class ScopedExpression(Expression):
    value_defns: List[Tuple[str, Expression]]
    func_defns: List[Tuple[str, FunctionDefinition]]
    value: Expression


expr_parser = yacc.yacc(start="expr")

if __name__ == "__main__":
    # Test the parser
    while True:
        input_expr = input()
        if not input_expr:
            break
        result = expr_parser.parse(input_expr)
        print(result)
