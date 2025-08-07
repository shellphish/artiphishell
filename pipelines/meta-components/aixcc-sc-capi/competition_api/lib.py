import itertools
from typing import Iterator, TypeVar

T = TypeVar("T")


def peek(iterator: Iterator[T]) -> Iterator[T] | None:
    try:
        first = next(iterator)
    except StopIteration:
        return None
    return itertools.chain([first], iterator)
