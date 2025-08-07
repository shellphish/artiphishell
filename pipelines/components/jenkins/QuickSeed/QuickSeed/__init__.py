__version__ = "0.0.1"
import logging

logging.getLogger("QuickSeed").addHandler(logging.NullHandler())
from .logger import Loggers
loggers = Loggers()
del Loggers

_l = logging.getLogger(__name__)

