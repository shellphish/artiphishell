"""Tools for communicating between python and the pydatatask query langauge."""

from __future__ import annotations

from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    DefaultDict,
    Dict,
    List,
    Optional,
    Union,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)
from collections import defaultdict
from collections.abc import Awaitable as ABCAwaitable
from collections.abc import Callable as ABCCallable
import inspect

from typing_extensions import TypeAlias

from pydatatask import repository as repomodule
from pydatatask.query.executor import (
    FunctionDefinition,
    FunctionType,
    Key,
    QueryValue,
    QueryValueType,
    ResolvedFunction,
    Scope,
)

builtins: DefaultDict[str, List[FunctionDefinition]] = defaultdict(list)

incast = QueryValue.wrap

IntoQueryValue: TypeAlias = Any


def checked_outcast(ty: Union[QueryValueType, FunctionType], value: Union[QueryValue, ResolvedFunction], scope: Scope):
    """Given a query language internal value and its type, convert it to a python object.

    Requires the scope so that functions can be handled. If you don't have a scope and don't need to manage functions,
    use `QueryValue.unwrap`.
    """
    if isinstance(value, ResolvedFunction):
        assert isinstance(ty, FunctionType)
        assert not ty.template_types

        async def inner(*args):
            assert isinstance(ty, FunctionType)
            if len(args) != len(ty.arg_types):
                raise TypeError(f"Bad number of args: Expected {len(ty.arg_types)}, got {len(args)}")
            inargs = [
                checked_incast(argty, arg, f"Argument {arg} to {value}") for arg, argty in zip(args, ty.arg_types)
            ]
            (
                newscope,
                defn,
            ) = value.make_scope(scope, inargs)
            return checked_outcast(ty.return_type, await defn.impl(newscope), scope)

        return inner
    if ty not in (value.type, QueryValueType.RepositoryData):
        raise TypeError(f"Outcast failed: expected a {ty}, got {value}")
    return value.unwrap()


def checked_incast_template(
    ty: Union[QueryValueType, FunctionType], value, reason: str
) -> Union[FunctionDefinition, QueryValue]:
    """Given a python object and the type to cast it to, convert it to a query language internal object.

    This function can handle functions.
    """
    if isinstance(ty, FunctionType):
        assert callable(ty)
        return wrap_function(value)
    return checked_incast(ty, value, reason)


def checked_incast(ty: QueryValueType, value: IntoQueryValue, reason: str) -> QueryValue:
    """Given a python object and the type to cast it to, convert it to a query language internal object.

    This function cannot handle functions.
    """
    if ty == QueryValueType.RepositoryData:
        return QueryValue(ty, data_value=value)
    if ty == QueryValueType.Key and isinstance(value, (int, str)):
        value = Key(value)
    result = QueryValue.wrap(value)
    if result.type != ty:
        raise TypeError(f"Incast failed: expected a {ty}, got {result} ({reason})")
    return result


def translate_pytype_template(ty) -> Union[QueryValueType, FunctionType]:
    """Given a python type annotation, convert it to a query language internal type.

    This function can handle function types.
    """
    if get_origin(ty) is ABCCallable:
        args, retval = get_args(ty)
        if get_origin(retval) is not ABCAwaitable:
            raise TypeError("Can only handle async functions")
        (retval,) = get_args(retval)
        return FunctionType((), tuple(translate_pytype(a) for a in args), translate_pytype(retval))
    return translate_pytype(ty)


def translate_pytype(ty) -> QueryValueType:
    """Given a python type annotation, convert it to a query language internal type.

    This function cannot handle function types.
    """
    if ty is int:
        return QueryValueType.Int
    if ty is str:
        return QueryValueType.String
    if ty is bool:
        return QueryValueType.Bool
    if isinstance(ty, type) and issubclass(ty, repomodule.Repository):
        return QueryValueType.Repository
    if get_origin(ty) is list:
        return QueryValueType.List
    if ty is Key:
        return QueryValueType.Key
    return QueryValueType.RepositoryData


def wrap_function(f: Callable[..., Awaitable[Any]], template_args: Optional[List[str]] = None) -> FunctionDefinition:
    """Given a python function, convert it to a query language internal function."""
    pytypes = get_type_hints(f)
    spec = inspect.getfullargspec(f)
    all_args = spec.args
    args = list(all_args)
    template_nargs = template_args or []
    for argname in args:
        if argname not in template_nargs and get_origin(pytypes[argname]) is ABCCallable:
            template_nargs.append(argname)
    for argname in template_nargs:
        args.remove(argname)
    template_types = tuple(translate_pytype_template(pytypes[name]) for name in template_nargs)
    arg_types = tuple(translate_pytype(pytypes[name]) for name in args)
    ty = FunctionType(template_types, arg_types, translate_pytype(pytypes["return"]))

    async def inner(scope: Scope):
        all_args_types = [
            arg_types[args.index(a)] if a in args else template_types[template_nargs.index(a)] for a in all_args
        ]
        stuff = [
            checked_outcast(
                ty,
                scope.lookup_value(a) if isinstance(ty, QueryValueType) else scope.lookup_function(a, ty.arg_types),
                scope,
            )
            for ty, a in zip(all_args_types, all_args)
        ]
        return checked_incast(ty.return_type, await f(*stuff), f"Return value of {f.__name__}")

    obj = FunctionDefinition(template_nargs, args, ty, inner)
    return obj


# pylint: disable=missing-function-docstring


def _builtin(name: Optional[str] = None, template_args: Optional[List[str]] = None):
    def wrapper(f: Callable[..., Awaitable[Any]]):
        obj = wrap_function(f, template_args)
        builtins[name or f.__name__].append(obj)
        return obj

    return wrapper


@_builtin("__eq__")
async def int_eq(a: int, b: int) -> bool:
    return a == b


@_builtin("__eq__")
async def bool_eq(a: bool, b: bool) -> bool:
    return a == b


@_builtin("__eq__")
async def str_eq(a: str, b: str) -> bool:
    return a == b


@_builtin("__eq__")
async def key_eq(a: Key, b: Key) -> bool:
    return a == b


@_builtin("__add__")
async def int_add(a: int, b: int) -> int:
    return a + b


@_builtin("__add__")
async def str_add(a: str, b: str) -> str:
    return a + b


@_builtin("int")
async def str_to_int(a: str) -> int:
    return int(a)


@_builtin("str")
async def int_to_str(a: int) -> str:
    return str(a)


@_builtin("str")
async def key_to_str(a: Key) -> str:
    return str(a)


@_builtin("__sub__")
async def int_sub(a: int, b: int) -> int:
    return a - b


@_builtin("__mul__")
async def int_mul(a: int, b: int) -> int:
    return a * b


@_builtin("__mul__")
async def str_mul(a: str, b: int) -> str:
    return a * b


@_builtin("__div__")
async def int_div(a: int, b: int) -> int:
    return int(a / b)


@_builtin("__mod__")
async def int_mod(a: int, b: int) -> int:
    return a % b


@_builtin("__bitand__")
async def int_bitand(a: int, b: int) -> int:
    return a & b


@_builtin("__bitand__")
async def bool_bitand(a: bool, b: bool) -> bool:
    return a & b


@_builtin("__bitor__")
async def int_bitor(a: int, b: int) -> int:
    return a | b


@_builtin("__bitor__")
async def bool_bitor(a: bool, b: bool) -> bool:
    return a | b


@_builtin("__bitxor__")
async def int_bitxor(a: int, b: int) -> int:
    return a ^ b


@_builtin("__bitxor__")
async def bool_bitxor(a: bool, b: bool) -> bool:
    return a ^ b


@_builtin("__gt__")
async def int_gt(a: int, b: int) -> bool:
    return a > b


@_builtin("__gt__")
async def str_gt(a: str, b: str) -> bool:
    return a > b


@_builtin("__gt__")
async def bool_gt(a: bool, b: bool) -> bool:
    return a > b


@_builtin("__lt__")
async def int_lt(a: int, b: int) -> bool:
    return a < b


@_builtin("__lt__")
async def str_lt(a: str, b: str) -> bool:
    return a < b


@_builtin("__lt__")
async def bool_lt(a: bool, b: bool) -> bool:
    return a < b


@_builtin("__ge__")
async def int_ge(a: int, b: int) -> bool:
    return a >= b


@_builtin("__ge__")
async def str_ge(a: str, b: str) -> bool:
    return a >= b


@_builtin("__ge__")
async def bool_ge(a: bool, b: bool) -> bool:
    return a >= b


@_builtin("__le__")
async def int_le(a: int, b: int) -> bool:
    return a <= b


@_builtin("__le__")
async def str_le(a: str, b: str) -> bool:
    return a <= b


@_builtin("__le__")
async def bool_le(a: bool, b: bool) -> bool:
    return a <= b


@_builtin("__inv__")
async def int_inv(a: int) -> int:
    return ~a


@_builtin("__not__")
async def bool_not(a: bool) -> bool:
    return not a


@_builtin("__not__")
async def int_not(a: int) -> bool:
    return not bool(a)


@_builtin("__not__")
async def str_not(a: str) -> bool:
    return not a


@_builtin("__neg__")
async def int_neg(a: int) -> int:
    return -a


@_builtin("__plus__")
async def int_plus(a: int) -> int:
    return +a


@_builtin("map")
async def map_values(a: repomodule.Repository, b: Callable[[object], Awaitable[object]]) -> repomodule.Repository:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Only MetadataRepository can be used with map()")

    async def inner(_key, obj):
        return await b(obj)

    return a.map(inner, [])


@_builtin("map")
async def map_list(a: List, b: Callable[[object], Awaitable[object]]) -> List:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Only MetadataRepository can be used with map()")

    return [await b(x) for x in a]


@_builtin("map")
async def map_key_values(
    a: repomodule.Repository, b: Callable[[Key, object], Awaitable[object]]
) -> repomodule.Repository:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Only MetadataRepository can be used with map()")

    async def inner(key, obj):
        return await b(Key(key), obj)

    return a.map(inner, [])


@_builtin("rekey")
async def rekey(a: repomodule.Repository, b: Callable[[Key], Awaitable[Key]]) -> repomodule.Repository:
    async def inner(k: str) -> str:
        return str(await b(Key(k)))

    if isinstance(a, repomodule.MetadataRepository):
        return repomodule.RelatedItemMetadataRepository(a, repomodule.FunctionCallMetadataRepository(inner, a, []))
    else:
        return repomodule.RelatedItemRepository(a, repomodule.FunctionCallMetadataRepository(inner, a, []))


@_builtin("filter")
async def filter_repo_keys(a: repomodule.Repository, b: Callable[[Key], Awaitable[bool]]) -> repomodule.Repository:
    async def inner(k: str) -> bool:
        return await b(Key(k))

    if isinstance(a, repomodule.MetadataRepository):

        async def inner_all(d: Dict[str, Any]) -> AsyncIterator[str]:
            for k in d.keys():
                if await b(Key(k)):
                    yield k

        return repomodule.FilterMetadataRepository(a, filt=inner, filter_all=inner_all)
    elif isinstance(a, repomodule.FilesystemRepository):
        return repomodule.FilterFilesystemRepository(a, inner)
    elif isinstance(a, repomodule.BlobRepository):
        return repomodule.FilterBlobRepository(a, inner)
    else:
        return repomodule.FilterRepository(a, inner)


@_builtin("filter")
async def filter_repo_keyvals(
    a: repomodule.Repository, b: Callable[[Key, object], Awaitable[bool]]
) -> repomodule.Repository:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Only MetadataRepository can be used with filter() with key-data callback")

    async def inner_all(d: Dict[str, Any]) -> AsyncIterator[str]:
        for k, v in d.items():
            if await b(Key(k), v):
                yield k

    async def inner(k: str) -> bool:
        if not await a.contains(k):
            return False
        return await b(Key(k), await a.info(k))

    return repomodule.FilterMetadataRepository(a, filt=inner, filter_all=inner_all)


@_builtin("filter")
async def filter_repo_vals(a: repomodule.Repository, b: Callable[[object], Awaitable[bool]]) -> repomodule.Repository:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Only MetadataRepository can be used with filter() with data callback")

    async def inner_all(d: Dict[str, Any]) -> AsyncIterator[str]:
        for k, v in d.items():
            if await b(v):
                yield k

    async def inner(k: str) -> bool:
        if not await a.contains(k):
            return False
        return await b(await a.info(k))

    return repomodule.FilterMetadataRepository(a, filt=inner, filter_all=inner_all)


@_builtin("any")
async def repo_any(a: repomodule.Repository) -> bool:
    async for _ in a:
        return True
    else:
        return False


@_builtin("__index__")
async def list_index(a: List, b: int) -> object:
    return a[b]


@_builtin("__index__")
async def repo_index(a: repomodule.Repository, b: Key) -> object:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Can only index MetadataRepositories")
    return await a.info(str(b))


@_builtin("sort")
async def sort_list(a: List) -> List:
    return sorted(a)


@_builtin("sort")
async def sort_list_keyed(a: List, key: Callable[[object], Awaitable[int]]) -> List:
    keys = [(await key(x), x) for x in a]
    keys.sort()
    for i, (_, x) in enumerate(keys):
        keys[i] = x  # type: ignore
    return keys


@_builtin("values")
async def repo_values(a: repomodule.Repository) -> List:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Can only values MetadataRepositories")
    return list((await a.info_all()).values())


@_builtin("items")
async def repo_items(a: repomodule.Repository) -> List:
    if not isinstance(a, repomodule.MetadataRepository):
        raise TypeError("Can only values MetadataRepositories")
    return [[k, v] for k, v in (await a.info_all()).items()]


@_builtin("keys")
async def repo_keys(a: repomodule.Repository) -> List:
    return [Key(x) async for x in a]


@_builtin("len")
async def repo_len(a: repomodule.Repository) -> int:
    result = 0
    async for _ in a:
        result += 1
    return result


@_builtin("len")
async def list_len(a: List) -> int:
    return len(a)


@_builtin("sum")
async def list_sum(a: List) -> int:
    result = 0
    try:
        for x in a:
            result += x
    except TypeError as e:
        raise TypeError("Can only sum lists of ints") from e
    return result


@_builtin("concat")
async def list_concat(a: List) -> List:
    result = []
    try:
        for x in a:
            result += x
    except TypeError as e:
        raise TypeError("Can only concat lists of lists") from e
    return result


@_builtin("index")
async def list_index_str(a: List, b: str) -> int:
    if b in a:
        return a.index(b)
    else:
        return -1


@_builtin("index")
async def list_index_int(a: List, b: int) -> int:
    if b in a:
        return a.index(b)
    else:
        return -1


@_builtin("get")
async def list_get(a: List, b: int, c: object) -> object:
    if 0 <= b < len(a):
        return a[b]
    else:
        return c


@_builtin("contains")
async def list_contains(a: List, b: object) -> bool:
    return b in a


@_builtin("contains")
async def dict_contains_key(a: Dict, b: object) -> bool:
    return b in a


@_builtin("contains")
async def repo_contains_key(a: repomodule.Repository, b: Key) -> bool:
    return await a.contains(b)


# HACKS BELOW THIS POINT
@_builtin("asData")
async def list_as_data(a: List) -> object:
    return a


@_builtin("asList")
async def data_as_list(a: object) -> List:
    return cast(List, a)
