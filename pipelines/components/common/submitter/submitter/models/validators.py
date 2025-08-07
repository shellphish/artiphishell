from typing import Any, Callable


def max_size(size: int) -> Callable[[Any], Any]:
    def func(field: Any) -> Any:
        assert len(field) <= size, f"Field must be shorter than {size}"
        return field

    return func
