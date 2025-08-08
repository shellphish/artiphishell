import os
import logging
import traceback

WARNING_TRACE = os.getenv('WARNING_TRACE', '0').lower() not in (
    '0', 'false', 'no', 'off', 'disable',
    'disabled', 'nope', 'nah', 'n', ''
)
ERROR_TRACE = os.getenv('ERROR_TRACE', '1').lower() not in (
    '0', 'false', 'no', 'off', 'disable',
    'disabled', 'nope', 'nah', 'n', ''
)

LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG').upper()

log = logging.getLogger(__name__)

def get_color_logger(cls):
    import colorlog
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s[%(levelname)s] [%(name)s] %(message)s'
    ))
    logger = colorlog.getLogger(cls.__name__)
    logger.addHandler(handler)
    logger.setLevel(LOG_LEVEL)
    return logger

def get_logger(cls):
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '[%(levelname)s] [%(name)s] %(message)s'
    ))
    logger = logging.getLogger(cls.__name__)
    logger.addHandler(handler)
    logger.setLevel(LOG_LEVEL)
    return logger

def print_log_static(cls=None, *args, level=logging.INFO, **kwargs):
    if not cls:
        return print(*args, **kwargs)
    if '__LOGGER__' not in cls.__dict__:

        try:
            l = get_color_logger(cls)
        except ImportError:
            l = get_logger(cls)
        #l.setLevel(logging.DEBUG) # TODO: make this configurable
        cls.__LOGGER__ = l
    args = ' '.join(map(str, args))
    cls.__LOGGER__.log(level, f'{args}', **kwargs)
    return


def print_log_self(self=None, *args, level=logging.INFO, **kwargs):
    print_log_static(
        self.__class__ if self else StaticLogger,
        *args, level=level, **kwargs
    )

class BaseLogger(object):
    __LOGGER__ = None

    def debug(self, *args, **kwargs):
        print_log_self(self, *args, **kwargs, level=logging.DEBUG)
    @classmethod
    def debug_static(cls, *args, **kwargs):
        print_log_static(cls, *args, **kwargs, level=logging.DEBUG)

    def info(self, *args, **kwargs):
        print_log_self(self, *args, **kwargs, level=logging.INFO)
    @classmethod
    def info_static(cls, *args, **kwargs):
        print_log_static(cls, *args, **kwargs, level=logging.INFO)

    def warn(self, *args, **kwargs):
        print_log_self(self, *args, **kwargs, level=logging.WARNING)
        if WARNING_TRACE:
            traceback.print_stack()

    @classmethod
    def warn_static(cls, *args, **kwargs):
        print_log_static(cls, *args, **kwargs, level=logging.WARNING)
        if WARNING_TRACE:
            traceback.print_stack()

    def log_error(self, *args, **kwargs):
        print_log_self(self, *args, **kwargs, level=logging.ERROR)
        if ERROR_TRACE:
            traceback.print_stack()
    @classmethod
    def log_error_static(cls, *args, **kwargs):
        print_log_static(cls, *args, **kwargs, level=logging.ERROR)
        if ERROR_TRACE:
            traceback.print_stack()

class StaticLogger(BaseLogger):
    pass