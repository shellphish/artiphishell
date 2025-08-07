# pylint: disable=missing-module-docstring,missing-function-docstring
from abc import ABC, abstractmethod

from .parser import (
    BoolLiteral,
    Expression,
    FuncExpr,
    FunctionCall,
    IdentExpression,
    IntLiteral,
    KeyLiteral,
    ListLiteral,
    ScopedExpression,
    StringLiteral,
)


class Visitor(ABC):
    """A visitor base class for parsed pydatatask query ASTs."""

    async def visit(self, obj):
        name = type(obj).__name__
        func = getattr(self, f"visit_{name}")
        return await func(obj)

    async def visit_Expression(self, obj: Expression):
        raise TypeError(f"Unknown expression type {type(obj)}")

    @abstractmethod
    async def visit_IdentExpression(self, obj: IdentExpression):
        raise NotImplementedError

    @abstractmethod
    async def visit_StringLiteral(self, obj: StringLiteral):
        raise NotImplementedError

    @abstractmethod
    async def visit_KeyLiteral(self, obj: KeyLiteral):
        raise NotImplementedError

    @abstractmethod
    async def visit_IntLiteral(self, obj: IntLiteral):
        raise NotImplementedError

    @abstractmethod
    async def visit_BoolLiteral(self, obj: BoolLiteral):
        raise NotImplementedError

    @abstractmethod
    async def visit_ListLiteral(self, obj: ListLiteral):
        raise NotImplementedError

    @abstractmethod
    async def visit_FuncExpr(self, obj: FuncExpr):
        raise NotImplementedError

    @abstractmethod
    async def visit_FunctionCall(self, obj: FunctionCall):
        raise NotImplementedError

    @abstractmethod
    async def visit_ScopedExpression(self, obj: ScopedExpression):
        raise NotImplementedError
