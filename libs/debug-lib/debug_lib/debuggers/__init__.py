import logging

from .gdb import GDBDebugger as GDBDebugger
from .jdb import JavaDebugger as JDBDebugger
from .debugger import Debugger as Debugger
from rich.logging import RichHandler
from rich.console import Console

FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d | %(message)s"
logging.basicConfig(
    level="NOTSET",
    format=FORMAT,
    datefmt="[%X]",
    handlers=[RichHandler(console=Console(width=150), rich_tracebacks=True)],
)
logging.getLogger().setLevel(logging.INFO)
