"""A session is a tool for managing multiple live ephemeral resources. Async ephemeral manager routines can be
registered, and in their place will be left a callable which will return the live ephemeral resource while the
session is opened.

For example:

.. code:: python

    session = pydatatask.Session()

    @session.ephemeral
    async def my_file_dst():
        with open('/tmp/my_file_dst', 'wb') as fp:
            yield fp

    @session.ephemeral
    async def my_file_src():
        with open('/tmp/my_file_src', 'rb') as fp:
            yield fp

    async with session:
        my_file_dst().write(my_file_src().read())

The advantage over using normal contextlib context managers is that this produces a function reference which can be
passed into other locations in sync contexts with the promise that it will not be called until the session is opened.

If a session is passed to a pipeline, it will be opened and closed when the pipeline is opened and closed.

Sessions cannot be opened more than once. But this doesn't have to be the way! If you have a use case, complain in a
GitHub issue, and I'll see what can be done.
"""

from typing import AsyncIterable, Callable, Optional, Protocol, TypeVar

__all__ = ("Session", "Ephemeral")

T_co = TypeVar("T_co", covariant=True)


class Ephemeral(Protocol[T_co]):
    """An accessor for a session object.

    Will throw an error if the session is not open.
    """

    def __call__(self) -> T_co: ...

    _session: "Session"


class SessionClosedError(Exception):
    """An error indicating attempted access to an ephemeral while its session is closed."""


class SessionOpenFailedError(Exception):
    """An error indicating attempted access to an optional ephemeral that failed creation."""


class Session:
    """The session class.

    See module docs for usage information.
    """

    def __init__(self):
        self._ephemeral_defs = {}
        self._ephemeral_errors = {}
        self._optionals = set()
        self.ephemerals = {}

    def ephemeral(
        self, manager: Callable[[], AsyncIterable[T_co]], name: Optional[str] = None, optional: bool = False
    ) -> Ephemeral[T_co]:
        """Decorator for ephemeral resource managers.

        Should be called with an async function that will yield exactly one object, the live constructed resource, and
        then tear that resource down on completion.
        """
        name = name or manager.__name__
        self._ephemeral_defs[name] = manager()
        if optional:
            self._optionals.add(name)

        def inner():
            if name not in self.ephemerals:
                if optional and name in self._ephemeral_errors:
                    raise SessionOpenFailedError(f"{name} failed to open") from self._ephemeral_errors[name]
                raise SessionClosedError("Session is not open")
            return self.ephemerals[name]

        inner._session = self  # type: ignore
        return inner  # type: ignore

    async def __aenter__(self):
        await self.open()

    async def open(self):
        """Open the session, initializing all the ephemerals.

        This is automatically called when entering an ``async with session:`` block.
        """
        for name, manager in self._ephemeral_defs.items():
            try:
                self.ephemerals[name] = await manager.__anext__()
            except Exception as e:  # pylint: disable=broad-exception-caught
                if name in self._optionals:
                    self._ephemeral_errors[name] = e
                else:
                    raise

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Close the session, tearing down all the resources.

        This is automatically called when exiting an ``async with session:`` block.
        """
        for name, manager in reversed(self._ephemeral_defs.items()):
            try:
                await manager.__anext__()
            except StopAsyncIteration:
                pass
            else:
                print("Warning: ephemeral has more than one yield")
            self.ephemerals.pop(name, None)
            self._ephemeral_errors.pop(name, None)
