from .gdb import GDBDebugger
from .jdb import JavaDebugger
from .debugger import Debugger
import logging
from rich.logging import RichHandler
from rich.console import Console

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler(console=Console(width=150), rich_tracebacks=True)]
)
logging.getLogger().setLevel(logging.INFO)
