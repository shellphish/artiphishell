"""In order to actually execute query language internal ASTs, use the visitor subclass `Executor` in this module.

The rest of this module is runtime support for this naive form of execution.
"""

# pylint: disable=missing-function-docstring,missing-class-docstring

from __future__ import annotations

from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
)
from collections import defaultdict
from dataclasses import dataclass
from itertools import product as iproduct

from typing_extensions import Mapping, TypeAlias

from pydatatask import repository as repomodule
from pydatatask.query.parser import ArgTypes
from pydatatask.query.parser import FunctionDefinition as ParsedFunctionDefinition
from pydatatask.query.parser import (
    FunctionType,
    QueryValueType,
    TemplateType,
    TemplateTypes,
)
from pydatatask.query.visitor import Visitor


class Key(str):
    """The representation of query language keys, which are just strings."""


@dataclass
class QueryValue:
    """A tagged union for query language values."""

    type: QueryValueType
    bool_value: Optional[bool] = None
    int_value: Optional[int] = None
    string_value: Optional[str] = None
    key_value: Optional[str] = None
    list_value: Optional[List["QueryValue"]] = None
    repo_value: Optional[repomodule.Repository] = None
    data_value: Optional[Any] = None

    def typecheck(self, ty: "TemplateType"):
        """Check whether the given type matches this object."""
        return isinstance(ty, QueryValueType) and self.type == ty

    def unwrap(self):
        """Extract the untagged value from the union."""
        if self.type == QueryValueType.String:
            return self.string_value
        if self.type == QueryValueType.Key:
            return Key(self.key_value)
        if self.type == QueryValueType.Int:
            return self.int_value
        if self.type == QueryValueType.Bool:
            return self.bool_value
        if self.type == QueryValueType.Repository:
            return self.repo_value
        if self.type == QueryValueType.List:
            return self.list_value
        return self.data_value

    @staticmethod
    def wrap(value, cache: bool = True) -> "QueryValue":
        """Create a QueryValue from an untagged value based on its type."""
        if isinstance(value, Key):
            return QueryValue(QueryValueType.Key, key_value=str(value))
        if isinstance(value, str):
            return QueryValue(QueryValueType.String, string_value=value)
        if isinstance(value, bool):
            return QueryValue(QueryValueType.Bool, bool_value=value)
        if isinstance(value, int):
            return QueryValue(QueryValueType.Int, int_value=value)
        if cache and isinstance(value, repomodule.MetadataRepository):
            return QueryValue(QueryValueType.Repository, repo_value=repomodule.CacheInProcessMetadataRepository(value))
        if isinstance(value, repomodule.Repository):
            return QueryValue(QueryValueType.Repository, repo_value=value)
        if isinstance(value, list):
            return QueryValue(QueryValueType.List, list_value=value)
        return QueryValue(QueryValueType.RepositoryData, data_value=value)


TemplateValue: TypeAlias = Union[QueryValue, "TemplatedFunction"]


@dataclass
class FunctionDefinition:
    template_names: List[str]
    arg_names: List[str]
    type: FunctionType
    impl: Callable[["Scope"], Awaitable[QueryValue]]


@dataclass
class TemplatedFunction:
    template_params: List[TemplateValue]
    defns: Dict[ArgTypes, FunctionDefinition]
    name: str

    def resolve(self, args: Iterable[QueryValue]) -> "ResolvedFunction":
        argtypes = tuple(arg.type for arg in args)

        if argtypes not in self.defns:
            raise NameError(f"No overload available for {self.name} that matches {argtypes}")
        defn = self.defns[argtypes]
        return ResolvedFunction(defn, self.template_params, self.name)


@dataclass
class ResolvedFunction:
    defn: FunctionDefinition
    template_params: List[TemplateValue]
    name: str

    def make_scope(self, base_scope: "Scope", args: Iterable[QueryValue]) -> Tuple["Scope", FunctionDefinition]:
        local_functions: Dict[str, TemplatedFunction] = {}
        local_values = dict(zip(self.defn.arg_names, args))
        for name, value, ty in zip(self.defn.template_names, self.template_params, self.defn.type.template_types):
            if isinstance(ty, QueryValueType):
                assert isinstance(value, QueryValue)
                local_values[name] = value
            else:
                assert isinstance(ty, FunctionType)
                assert isinstance(value, TemplatedFunction)
                local_functions[name] = value

        return (
            Scope(
                local_values,
                base_scope.global_values,
                base_scope.global_functions,
                local_functions,
                base_scope.global_templates,
                {},
            ),
            self.defn,
        )


@dataclass
class Scope:
    """The data storage for the query executor."""

    local_values: Dict[str, QueryValue]
    global_values: Dict[str, QueryValue]
    global_functions: Dict[str, Dict[ArgTypes, FunctionDefinition]]
    local_functions: Dict[str, TemplatedFunction]
    global_templates: Dict[Tuple[str, TemplateTypes], Dict[ArgTypes, FunctionDefinition]]
    local_templates: Dict[Tuple[str, TemplateTypes], Dict[ArgTypes, FunctionDefinition]]

    def copy(self) -> "Scope":
        return Scope(
            local_values=dict(self.local_values),
            global_values=dict(self.global_values),
            global_functions=dict(self.global_functions),
            local_functions=dict(self.local_functions),
            global_templates=dict(self.global_templates),
            local_templates=defaultdict(dict, self.local_templates),
        )

    def overlay(self, other: "Scope") -> "Scope":
        result = self.copy()
        result.local_values.update(other.local_values)
        result.global_values.update(other.global_values)
        result.global_functions.update(other.global_functions)
        result.local_functions.update(other.local_functions)
        result.global_templates.update(other.global_templates)
        result.local_templates.update(other.local_templates)
        return result

    @classmethod
    def base_scope(cls, values: Mapping[str, QueryValue], functions: Mapping[str, List[FunctionDefinition]]) -> "Scope":
        """Create a brand new data store with the given values and functions in scope."""
        values_2 = {}
        values_2["true"] = QueryValue(QueryValueType.Bool, bool_value=True)
        values_2["false"] = QueryValue(QueryValueType.Bool, bool_value=False)
        values_2.update(values)
        global_functions: Mapping[str, Dict[ArgTypes, FunctionDefinition]] = defaultdict(dict)
        global_templates: Mapping[Tuple[str, TemplateTypes], Dict[ArgTypes, FunctionDefinition]] = defaultdict(dict)
        for name, funclist in functions.items():
            for func in funclist:
                if func.type.template_types:
                    global_templates[(name, func.type.template_types)][func.type.arg_types] = func
                else:
                    global_functions[name][func.type.arg_types] = func

        return Scope({}, values_2, dict(global_functions), {}, dict(global_templates), defaultdict(dict))

    def lookup_value(self, name: str) -> QueryValue:
        r = self.local_values.get(name, None)
        if r is not None:
            return r
        return self.global_values[name]

    def lookup_function(self, name: str, args: Iterable[Union[QueryValue, QueryValueType]]) -> ResolvedFunction:
        argtypes = tuple(arg if isinstance(arg, QueryValueType) else arg.type for arg in args)
        if name in self.local_functions and argtypes in self.local_functions[name].defns:
            return ResolvedFunction(
                self.local_functions[name].defns[argtypes], self.local_functions[name].template_params, name
            )
        if name in self.global_functions and argtypes in self.global_functions[name]:
            return ResolvedFunction(self.global_functions[name][argtypes], [], name)
        if name in self.local_functions or name in self.global_functions:
            raise NameError(f"No overload available for {name} that matches {argtypes}")
        if any(availname == name for availname, _ in self.global_templates):
            raise NameError(f"Function {name} exists, but needs to be templated first")
        raise NameError(f"No function with name {name}")

    def lookup_template(
        self, name: str, args: Iterable[Union[TemplateValue, TemplateType]]
    ) -> Dict[ArgTypes, FunctionDefinition]:
        args = list(args)

        # this is insanely ill-defined. what's going on?
        # we are trying to identify all possible valid concrete template signatures that could be matched by this query
        # this is because you can provide either types or values to this method.
        # if you provide a type it's pretty well-defined what you want
        # but if you provide a value it could be a function and functions have nasty overloading properties
        #
        result: Dict[ArgTypes, FunctionDefinition] = {}
        targtype_options = [
            (
                [arg]
                if isinstance(arg, (QueryValueType, FunctionType))
                else (
                    [x.type.strip_template() for x in arg.defns.values()]
                    if isinstance(arg, TemplatedFunction)
                    else [arg.type]
                )
            )
            for arg in args
        ]
        for targtypes in product(targtype_options):
            if (name, targtypes) in self.global_templates:
                result.update(self.global_templates[(name, targtypes)])
            if (name, targtypes) in self.local_templates:
                result.update(self.local_templates[(name, targtypes)])
        if result:
            return result
        if name in self.local_functions or name in self.global_functions:
            if args:
                raise NameError(f"Function {name} exists, but has already been templated")
            if name in self.local_functions:
                return self.local_functions[name].defns
            return self.global_functions[name]
        if any(availname == name for availname, _ in self.global_templates):
            raise NameError(f"No overload available for {name} that matches the given template arguments")
        if any(availname == name for availname, _ in self.local_templates):
            raise NameError(f"No overload available for {name} that matches the given template arguments")
        raise NameError(f"No function with name {name}")


T = TypeVar("T")


def product(args: Iterable[Union[Iterable[FunctionType], Iterable[TemplateType]]]) -> Iterator[TemplateTypes]:
    # args: a list of arguments, some of which are lists of possible signatures and some of which are lists containing
    # a single type (for simplicity)
    # result: an iterator of lists of arguments, each of which has only one possible signature per argument
    yield from iproduct(*args)


class Executor(Visitor):
    """The star of the show!

    Visit an expression with this class to return its computed value.
    """

    def __init__(self, scope: Scope):
        self.scope = scope

    async def visit_IdentExpression(self, obj) -> QueryValue:
        return self.scope.lookup_value(obj.name)

    async def visit_IntLiteral(self, obj) -> QueryValue:
        return QueryValue(QueryValueType.Int, int_value=obj.value)

    async def visit_StringLiteral(self, obj) -> QueryValue:
        return QueryValue(QueryValueType.String, string_value=obj.value)

    async def visit_BoolLiteral(self, obj) -> QueryValue:
        return QueryValue(QueryValueType.Bool, bool_value=obj.value)

    async def visit_KeyLiteral(self, obj) -> QueryValue:
        return QueryValue(QueryValueType.Key, key_value=obj.value)

    async def visit_ListLiteral(self, obj) -> QueryValue:
        return QueryValue(QueryValueType.List, list_value=[(await self.visit(expr)).unwrap() for expr in obj.values])

    async def visit_FuncExpr(self, obj) -> TemplatedFunction:
        targs = [await self.visit(expr) for expr in obj.template_args]
        defns = self.scope.lookup_template(obj.name, targs)
        return TemplatedFunction(targs, defns, obj.name)

    async def visit_FunctionCall(self, obj) -> QueryValue:
        funcexpr = await self.visit_FuncExpr(obj.function)
        args = [await self.visit(expr) for expr in obj.args]
        scope, defn = funcexpr.resolve(args).make_scope(self.scope, args)
        return await defn.impl(scope)

    async def visit_TernaryExpr(self, obj) -> QueryValue:
        cond: QueryValue = await self.visit(obj.condition)
        if cond.unwrap():
            return await self.visit(obj.iftrue)
        else:
            return await self.visit(obj.iffalse)

    async def visit_ScopedExpression(self, obj) -> QueryValue:
        newscope = self.scope.copy()
        newvis = Executor(newscope)
        for name, func in obj.func_defns:
            closed = close_function(newscope, func)
            if closed.template_names:
                newscope.local_templates[(name, closed.type.template_types)][closed.type.arg_types] = closed
            else:
                if name in newscope.local_functions:
                    newscope.local_functions[name].defns[closed.type.arg_types] = closed
                else:
                    newscope.local_functions[name] = TemplatedFunction([], {closed.type.arg_types: closed}, name)
        for name, expr in obj.value_defns:
            newscope.local_values[name] = await newvis.visit(expr)
        return await newvis.visit(obj.value)


def close_function(outer_scope: Scope, defn: ParsedFunctionDefinition) -> FunctionDefinition:
    async def inner(inner_scope: Scope):
        new_scope = outer_scope.overlay(inner_scope)
        new_vis = Executor(new_scope)
        return await new_vis.visit(defn.body)

    return FunctionDefinition(template_names=defn.template_names, arg_names=defn.arg_names, type=defn.type, impl=inner)
