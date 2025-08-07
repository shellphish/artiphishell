"""Home of the Query class."""

from typing import Any, Dict

import jq as jq_module
import yaml

from pydatatask import repository as repomodule
from pydatatask.utils import AWriteStreamBase

from .builtins import builtins, checked_incast
from .executor import Executor, FunctionDefinition, QueryValue, Scope
from .parser import Expression, FunctionType, QueryValueType, expr_parser


class Query:
    """A pythonic interface to a single expression with a scope and some parameters."""

    def __init__(
        self,
        result_type: QueryValueType,
        query: str,
        parameters: Dict[str, QueryValueType],
        getters: Dict[str, QueryValueType],
        repos: Dict[str, "repomodule.Repository"],
        jq_args: Dict[str, str],
    ):
        self.result_type = result_type
        self.expr: Expression = expr_parser.parse(query)
        self.query = query
        self.parameters = parameters
        self.getters = getters
        self.repos = repos
        self.jq = {k: jq_module.compile(v) for k, v in jq_args.items()}

    def _checked_incast(self, ty: QueryValueType, val: Any, reason: str) -> QueryValue:
        if ty == QueryValueType.String and isinstance(val, int):
            val = str(val)
        return checked_incast(ty, val, reason)

    def _make_getter(self, getter: str, ty: QueryValueType) -> FunctionDefinition:
        async def inner(scope: Scope):
            gotten = scope.lookup_value("arg").unwrap()
            if not isinstance(gotten, dict):
                raise TypeError(f"Can only run get{getter} on dicts, got {gotten}")
            return checked_incast(ty, gotten[getter], f"Return value of get{getter}")

        return FunctionDefinition([], ["arg"], FunctionType((), (QueryValueType.RepositoryData,), ty), inner)

    def _make_query(self, name: str, query) -> FunctionDefinition:
        async def inner(scope: Scope):
            gotten = scope.lookup_value("arg").unwrap()
            if not isinstance(gotten, (dict, list, str, int, float, bool)):
                raise TypeError(f"Can only run {name} on json types, got {gotten}")
            return QueryValue.wrap(query.input_value(self._scorch(gotten)).first())

        return FunctionDefinition(
            [], ["arg"], FunctionType((), (QueryValueType.RepositoryData,), QueryValueType.RepositoryData), inner
        )

    @classmethod
    def _scorch(cls, obj):
        if isinstance(obj, bytes):
            return obj.decode("latin-1")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                obj[i] = cls._scorch(v)
        elif isinstance(obj, dict):
            oldkeys = []
            newkeys = []
            for k, v in obj.items():
                k2 = cls._scorch(k)
                v = cls._scorch(v)
                if k2 is not k:
                    oldkeys.append(k)
                    newkeys.append((k, v))
                else:
                    obj[k2] = v
            for k in oldkeys:
                obj.pop(k)
            for k2, v in newkeys:
                obj[k2] = v
        return obj

    def _make_scope(self, parameters: Dict[str, Any]) -> Scope:
        values = {}
        functions = dict(builtins)
        if set(parameters) != set(self.parameters):
            raise ValueError(f"Passed incorrect parameters: got {set(parameters)}, expected {set(self.parameters)}")
        for getter, ty in self.getters.items():
            functions[f"get{getter}"] = [self._make_getter(getter, ty)]
        for name, repo in self.repos.items():
            values[name] = QueryValue.wrap(repo)
        for name, ty in self.parameters.items():
            values[name] = self._checked_incast(ty, parameters[name], f"Parameter {name} to Query")
        for name, query in self.jq.items():
            functions[name] = [self._make_query(name, query)]
        return Scope.base_scope(values, functions)

    async def execute(self, parameters: Dict[str, Any]) -> QueryValue:
        """Execute the query against a set of parameters.

        Returns a QueryValue, which may be formatted with
        `format_response`.
        """
        scope = self._make_scope(parameters)
        executor = Executor(scope)
        return await executor.visit(self.expr)

    async def format_response(self, result: QueryValue, response: AWriteStreamBase):
        """Format a QueryValue into an asynchronous bytestream."""
        if self.result_type in (QueryValueType.String, QueryValueType.Key) and result.type == QueryValueType.String:
            str_result = result.string_value
            assert str_result is not None
        elif (
            self.result_type in (QueryValueType.String, QueryValueType.Key)
            and result.type == QueryValueType.RepositoryData
            and isinstance(result.data_value, str)
        ):
            str_result = result.data_value
        else:
            str_result = yaml.safe_dump(result.unwrap())
            assert isinstance(str_result, str)
        await response.write(str_result.encode())
