import traceback
import logging
import zlib

from enum import Enum, unique


_ansi_prefix = "\x1b["


#
# Ansi colors
#


clear: str = f"{_ansi_prefix}0m"


@unique
class Color(Enum):
    """
    The basic ansi colors
    """

    black = 30
    red = 31
    green = 32
    yellow = 33
    blue = 34
    magenta = 35
    cyan = 36
    white = 37


BackgroundColor = unique(Enum("BackgroundColor", {i.name: (i.value + 10) for i in Color}))


#
# Functions
#


def color(c: Color | BackgroundColor, bright: bool):
    """
    Return the ansi prefix using the given code
    Bright may not be used with a BackgroundColor
    """
    if bright and isinstance(c, BackgroundColor):
        raise ValueError("Backgrounds should not be bright")
    return f"{_ansi_prefix}{c.value};1m" if bright else f"{_ansi_prefix}{c.value}m"


#
# Actual Logger
#


class Loggers:
    """
    Implements a loggers manager for angr.
    """

    __slots__ = (
        "default_level",
        "_loggers",
        "profiling_enabled",
        "handler",
    )

    def __init__(self, default_level=logging.WARNING):
        self.default_level = default_level
        self._loggers = {}
        self.load_all_loggers()
        self.profiling_enabled = False

        self.handler = logging.StreamHandler()
        self.handler.setFormatter(CuteFormatter(True))

        if len(logging.root.handlers) == 0:
            self.enable_root_logger()
            logging.root.setLevel(self.default_level)

    IN_SCOPE = ("patchery",)

    def load_all_loggers(self):
        """
        A dumb and simple way to conveniently aggregate all loggers.

        Adds attributes to this instance of each registered logger, replacing '.' with '_'
        """
        for name, logger in logging.Logger.manager.loggerDict.items():
            if any(name.startswith(x + ".") or name == x for x in self.IN_SCOPE):
                self._loggers[name] = logger

    def __getattr__(self, k):
        real_k = k.replace("_", ".")
        if real_k in self._loggers:
            return self._loggers[real_k]
        else:
            raise AttributeError(k)

    def __dir__(self):
        return list(super().__dir__()) + list(self._loggers.keys())

    def enable_root_logger(self):
        """
        Enable angr's default logger
        """
        logging.root.addHandler(self.handler)

    def disable_root_logger(self):
        """
        Disable angr's default logger
        """
        logging.root.removeHandler(self.handler)

    @staticmethod
    def setall(level):
        for name in logging.Logger.manager.loggerDict:
            logging.getLogger(name).setLevel(level)


class CuteFormatter(logging.Formatter):
    """
    A log formatter that can print log messages with colors.
    """

    __slots__ = ("_should_color",)

    def __init__(self, should_color: bool):
        super().__init__()
        self._should_color: bool = should_color

    def format(self, record: logging.LogRecord):
        name: str = record.name
        level: str = record.levelname
        message: str = record.getMessage()
        name_len: int = len(name)
        lvl_len: int = len(level)
        if self._should_color:
            skip_color = False
            # Color level
            if record.levelno == logging.CRITICAL:
                level = color(Color.red, True) + level
                level = color(BackgroundColor.yellow, False) + level
            elif record.levelno == logging.ERROR:
                level = color(Color.red, True) + level
            elif record.levelno == logging.WARNING:
                level = color(Color.yellow, False) + level
            elif record.levelno == logging.INFO:
                level = color(Color.blue, False) + level
            else:
                skip_color = True

            # if not skip_color:
            #    # Color text
            #    c: int = zlib.adler32(record.name.encode()) % 7
            #    if c != 0:  # Do not color black or white, allow 'uncolored'
            #        col = Color(c + Color.black.value)
            #        message = color(col, False) + message + clear
            #        name = color(col, False) + name + clear
        # Finalize log message
        name = name.ljust(14 + len(name) - name_len)
        level = level.ljust(8 + len(level) - lvl_len)
        body: str = (
            f"{level} | {self.formatTime(record, self.datefmt) : <23} | {name} | {message}{clear if self._should_color else ''}"
        )
        if record.exc_info:
            body += "\n" + "".join(traceback.format_exception(*record.exc_info))[:-1]
        return body


def is_enabled_for(logger, level):
    if level == 1:
        from .. import loggers

        return loggers.profiling_enabled
    return originalIsEnabledFor(logger, level)


originalIsEnabledFor = logging.Logger.isEnabledFor

# Override isEnabledFor() for Logger class
logging.Logger.isEnabledFor = is_enabled_for
