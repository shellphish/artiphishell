"""Various utility classes and functions that are used throughout the codebase but don't belong anywhere in
particular."""

from typing import (
    Any,
    AsyncContextManager,
    AsyncIterator,
    Awaitable,
    Callable,
    Coroutine,
    Generic,
    List,
    Optional,
    Protocol,
    TypeVar,
    Union,
)
from hashlib import md5
import asyncio
import codecs
import io
import json
import pickle
import struct
import time

from typing_extensions import Buffer, ParamSpec
import yaml

_T = TypeVar("_T")

# pylint: disable=unnecessary-ellipsis
# pyright doesn't work right without them


class ReadStream(Protocol):
    """A protocol for reading data from a stream."""

    def read(self, n: int = -1, /) -> bytes:
        """Read and return up to ``n`` bytes, or if unspecified, the rest of the stream."""
        ...

    def close(self) -> Any:
        """Close and release the stream."""
        ...


class WriteStream(Protocol):
    """A protocol for writing data to an stream."""

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Write ``data`` to the stream."""
        ...

    def close(self) -> Awaitable[Any]:
        """Close and release the stream."""
        ...


class AReadStreamBase(Protocol):
    """A protocol for reading data from an asynchronous stream (bass boosted)."""

    async def read(self, n: int = -1, /) -> bytes:
        """Read and return up to ``n`` bytes, or if unspecified, the rest of the stream."""
        ...


class AReadStream(Protocol):
    """A protocol for reading data from an asynchronous stream."""

    async def read(self, n: int = -1, /) -> bytes:
        """Read and return up to ``n`` bytes, or if unspecified, the rest of the stream."""
        ...

    def close(self) -> Awaitable[Any]:
        """Close and release the stream."""
        ...


class AReadTextProto(Protocol):
    """A protocol for reading data from an asynchronous stream."""

    async def read(self, n: int = -1, /) -> str:
        """Read and return up to ``n`` chars, or if unspecified, the rest of the stream."""
        ...

    def close(self) -> Awaitable[Any]:
        """Close and release the stream."""
        ...


class AWriteStreamBase(Protocol):
    """A protocol for writing data to an asynchronous stream (bass boosted)."""

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Write ``data`` to the stream."""
        ...


class AWriteStreamWrapper:
    """A wrapper that turns an AWriteStreamBase into an AWriteStream by stubbing its close method."""

    def __init__(self, inner: AWriteStreamBase):
        self.inner = inner

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Write ``dat`` to the stream."""
        return await self.inner.write(data)

    async def close(self):
        """Do nothing.

        Bye!
        """


class _AWriteStreamBad(Protocol):
    """This class exists because you so sucks."""

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> None:
        """Write ``data`` to the stream."""
        ...


class AWriteStreamBaseIntWrapper:
    """A wrapper that turns a bad writestream (returns None instead of int) into a good writestream."""

    def __init__(self, inner: _AWriteStreamBad):
        self.inner = inner

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Write ``data`` to the stream."""
        await self.inner.write(data)
        return len(data)


class AWriteStream(Protocol):
    """A protocol for writing data to an asynchronous stream."""

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Write ``data`` to the stream."""
        ...

    def close(self) -> Awaitable[Any]:
        """Close and release the stream."""
        ...


class AWriteTextProto(Protocol):
    """A protocol for writing text data to an asynchronous stream."""

    async def write(self, data: str, /) -> int:
        """Write ``data`` to the stream."""
        ...

    def close(self) -> Awaitable[Any]:
        """Close and release the stream."""
        ...


class AReadStreamManager(AReadStream, AsyncContextManager, Protocol):
    """A protocol for reading data from an asynchronous stream with context management."""


class AWriteStreamManager(AWriteStream, AsyncContextManager, Protocol):
    """A protocol for writing data to an asynchronous stream with context management."""


class AWriteStreamDrainer:
    """A class that wraps an asyncio streamwriter and turns the synchronous write into an asynchronous write by
    calling drain().

    Keep in mind this is a step in the right direction but is not perfect, as per
    https://vorpus.org/blog/some-thoughts-on-asynchronous-api-design-in-a-post-asyncawait-world/
    """

    def __init__(self, inner: asyncio.StreamWriter):
        self.inner = inner

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Write ``data`` to the stream."""
        self.inner.write(data)
        await self.inner.drain()
        return len(data)

    async def close(self) -> None:
        """Close the stream."""
        self.inner.close()
        # um.
        # await self.inner.wait_closed()

    async def __aenter__(self) -> "AWriteStreamDrainer":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


async def async_copyfile(copyfrom: AReadStreamBase, copyto: AWriteStreamBase, blocksize=1024 * 1024):
    """Stream data from ``copyfrom`` to ``copyto``."""
    while True:
        data = await copyfrom.read(blocksize)
        if not data:
            break
        await copyto.write(data)


async def async_copyfile_close(copyfrom: AReadStreamBase, copyto: AWriteStream, blocksize=1024 * 1024):
    """Stream data from ``copyfrom`` to ``copyto``, closing the sink stream on completion."""
    await async_copyfile(copyfrom, copyto, blocksize)
    await copyto.close()


class AReadText:
    """An async version of :external:class:`io.TextIOWrapper` which can only handle reading."""

    def __init__(
        self,
        base: AReadStream,
        encoding: str = "utf-8",
        errors="strict",
        chunksize=4096,
    ):
        self.base = base
        self.decoder = codecs.lookup(encoding).incrementaldecoder(errors)
        self.buffer = ""
        self.chunksize = chunksize

    async def read(self, n: Optional[int] = None) -> str:
        """Read up to ``n`` chars from the string, or the rest of the stream if not provided."""
        while n is None or len(self.buffer) < n:
            data = await self.base.read(self.chunksize)
            self.buffer += self.decoder.decode(data, final=not bool(data))
            if not data:
                break

        if n is not None:
            result, self.buffer = self.buffer[:n], self.buffer[:n]
        else:
            result, self.buffer = self.buffer, ""
        return result

    async def close(self) -> None:
        """Close and release the stream."""
        await self.base.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class AWriteText:
    """An async version of ``io.TextIOWrapper`` which can only handle writing."""

    def __init__(self, base: AWriteStream, encoding="utf-8", errors="strict"):
        self.base = base
        self.encoding = encoding
        self.errors = errors

    async def write(self, data: str):
        """Write ``data`` to the stream."""
        return await self.base.write(data.encode(self.encoding, self.errors))

    async def close(self) -> None:
        """Close and release the stream."""
        await self.base.close()

    async def __aenter__(self):
        aenter = getattr(self.base, "__aenter__", None)
        if aenter is not None:
            await aenter()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


async def async_copyfile_str(copyfrom: AReadText, copyto: AWriteText, blocksize=1024 * 1024):
    """Stream text from ``copyfrom`` to ``copyto``."""
    while True:
        data = await copyfrom.read(blocksize)
        if not data:
            break
        await copyto.write(data)


async def roundrobin(iterables: List):
    """An async version of the itertools roundrobin recipe.

    roundrobin('ABC', 'D', 'EF') --> A D E B F C
    """
    i = 0
    while iterables:
        i %= len(iterables)
        try:
            yield await iterables[i].__anext__()
        except StopAsyncIteration:
            iterables.pop(i)
        else:
            i += 1


class _AACM(Generic[_T]):
    def __init__(self, live: AsyncIterator[_T]):
        self.live = live

    async def __aenter__(self) -> _T:
        assert self.live is not None
        return await self.live.__anext__()

    async def __aexit__(self, exc_type, exc_value, exc_tb):
        try:
            await self.live.__anext__()
        except StopAsyncIteration:
            pass
        else:
            raise Exception("Programming error: async generator yields more than once")


P = ParamSpec("P")


def asyncasynccontextmanager(
    f: Callable[P, AsyncIterator[_T]]
) -> Callable[P, Coroutine[Any, Any, AsyncContextManager[_T]]]:
    """Like asynccontextmanager but needs to be awaited first."""

    async def inner(*args: P.args, **kwargs: P.kwargs):
        return _AACM(f(*args, **kwargs))

    return inner


def supergetattr(item: Any, key: str) -> Any:
    """Like getattr but also tries getitem."""
    try:
        return getattr(item, key)
    except AttributeError:
        return item[key]


def supergetattr_path(item: Any, keys: List[str]) -> Any:
    """Calls supergetattr repeatedly for each key in a list."""
    for key in keys:
        item = supergetattr(item, key)
    return item


class AsyncReaderQueueStream:
    """A stream queue whose writer is synchronous-nonblocking and whose reader is asynchronous."""

    def __init__(self) -> None:
        self.buffer: List[Optional[bytes]] = []
        self.readptr = (0, 0)
        self.closed = False

    def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Add data to the queue."""
        self.buffer.append(bytes(data))
        return len(data)

    def close(self) -> Any:
        """Mark the queue as closed, so reads will terminate."""
        self.closed = True
        r: asyncio.Future[None] = asyncio.Future()
        r.set_result(None)
        return r

    async def read(self, size: int = -1, /) -> bytes:
        """Read up to size bytes from the queue, or until EOF.

        Negative sizes (the default) will read all bytes until EOF.
        """
        outbuf = bytearray()
        while size != 0:
            line, col = self.readptr
            if line >= len(self.buffer):
                if self.closed:
                    break
                await asyncio.sleep(0.0001)
                continue
            buf = self.buffer[line]
            assert buf is not None

            if size < 0 or size >= len(buf) - col:
                outbuf.extend(buf[col:])
                self.buffer[line] = None
                self.readptr = (line + 1, 0)
                size -= len(buf) - col
                continue

            outbuf.extend(buf[col : col + size])
            self.readptr = (line, col + size)
            size = 0

        return bytes(outbuf)

    def tell(self) -> int:
        """It's a secret to everybody!"""
        return 0


class AsyncWriterQueueStream:
    """A stream queue whose writer is asynchronous-blocking and whose reader is synchronous."""

    def __init__(self) -> None:
        self.buffer: List[Optional[bytes]] = []
        self.bufsize = 0
        self.max_bufsize = 1024 * 16 * 8
        self.readptr = (0, 0)
        self.closed = False

    async def write(self, data: Union[bytes, bytearray, memoryview], /) -> int:
        """Add data to the queue."""
        while self.bufsize >= self.max_bufsize:
            await asyncio.sleep(0.0001)
        self.bufsize += len(data)
        self.buffer.append(bytes(data))
        return len(data)

    def close(self) -> Any:
        """Mark the queue as closed, so reads will terminate."""
        self.closed = True
        r: asyncio.Future[None] = asyncio.Future()
        r.set_result(None)
        return r

    def read(self, size: int = -1, /) -> bytes:
        """Read up to size bytes from the queue, or until EOF.

        Negative sizes (the default) will read all bytes until EOF.
        """
        outbuf = bytearray()
        while size != 0:
            line, col = self.readptr
            if line >= len(self.buffer):
                if self.closed:
                    break
                time.sleep(0.0001)
                continue
            buf = self.buffer[line]
            assert buf is not None

            if size < 0 or size >= len(buf) - col:
                outbuf.extend(buf[col:])
                self.bufsize -= len(buf)
                self.buffer[line] = None
                self.readptr = (line + 1, 0)
                size -= len(buf) - col
                continue

            outbuf.extend(buf[col : col + size])
            self.readptr = (line, col + size)
            size = 0

        return bytes(outbuf)

    def tell(self) -> int:
        """It's a secret to everybody!"""
        return 0


class QueueStream:
    """A stream queue with synchronous-locking reader and synchronous-nonblocking writer."""

    def __init__(self) -> None:
        self.buffer: List[Optional[bytes]] = []
        self.readptr = (0, 0)
        self._closed = False

    def close(self) -> None:
        """Add data to the queue."""
        self._closed = True

    def write(self, data: Buffer, /) -> int:
        """Add data to the queue."""
        b = bytes(data)
        self.buffer.append(b)
        return len(b)

    def read(self, size: int = -1, /) -> bytes:
        """Read up to size bytes from the queue, or until EOF.

        Negative sizes (the default) will read all bytes until EOF.
        """
        outbuf = bytearray()
        while size != 0:
            line, col = self.readptr
            if line >= len(self.buffer):
                if self._closed:
                    break
                time.sleep(0.0001)
                continue
            buf = self.buffer[line]
            assert buf is not None

            if size < 0 or size >= len(buf) - col:
                outbuf.extend(buf[col:])
                self.buffer[line] = None
                self.readptr = (line + 1, 0)
                size -= len(buf) - col
                continue

            outbuf.extend(buf[col : col + size])
            self.readptr = (line, col + size)
            size = 0

        return bytes(outbuf)


class AsyncQueueStream:
    """A stream queue with asynchronous-blocking reader and asynchronous-blocking writer."""

    def __init__(self) -> None:
        self.buffer: List[Optional[bytes]] = []
        self.readptr = (0, 0)
        self._closed = False
        self.bufsize = 0
        self.max_bufsize = 1024 * 16 * 8

    def close(self) -> None:
        """Add data to the queue."""
        self._closed = True

    async def write(self, data: Buffer, /) -> int:
        """Add data to the queue."""
        b = bytes(data)
        while self.bufsize >= self.max_bufsize:
            await asyncio.sleep(0.0001)
        self.bufsize += len(b)
        self.buffer.append(b)
        return len(b)

    async def read(self, size: int = -1, /) -> bytes:
        """Read up to size bytes from the queue, or until EOF.

        Negative sizes (the default) will read all bytes until EOF.
        """
        outbuf = bytearray()
        while size != 0:
            line, col = self.readptr
            if line >= len(self.buffer):
                if self._closed:
                    break
                await asyncio.sleep(0.0001)
                continue
            buf = self.buffer[line]
            assert buf is not None

            if size < 0 or size >= len(buf) - col:
                outbuf.extend(buf[col:])
                self.bufsize -= len(buf)
                self.buffer[line] = None
                self.readptr = (line + 1, 0)
                size -= len(buf) - col
                continue

            outbuf.extend(buf[col : col + size])
            self.readptr = (line, col + size)
            size = 0

        return bytes(outbuf)


class _StderrIsStdout:
    pass


STDOUT = _StderrIsStdout()

_hash_unpacker = struct.Struct("<QQ")


def crypto_hash(x: Any) -> int:
    """Perform a 64 bit cryptographic hash of the given item.

    A dark woeful blight passes over the land. In its foreboding mists you begin to hear creatures laughing and dancing.
    "Did you miss us?" they say, gleeful with mischief.

    You pass a vial of holy declarative configuration over your eyes and shout, "Begone, foul demons! I have not
    summoned ye! Collision-resistent hashing is a valiant and unsullied tool, and its association with the misery of
    hash-consing shall not poison its well of wonders!"

    The demons laugh some more. "But dearly beloved, you shall never rid yourself of hash collisions that fall from
    misconfigurations, and misconfigurations there shall be!"

    You weep.
    """
    return _hash_unpacker.unpack(md5(pickle.dumps(x)).digest())[0]


def safe_load(x: Union[str, bytes, io.TextIOBase]) -> Any:
    """Work around bugs parsing large json documents as yaml."""
    # import ipdb; ipdb.set_trace()
    if not isinstance(x, (str, bytes, bytearray, memoryview)):
        x = x.read()
    try:
        return json.loads(x)
    except json.JSONDecodeError:
        return yaml.safe_load(x)
