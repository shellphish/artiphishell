import logging
import logging.config
import tempfile
from datetime import datetime

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
_, tempfilename = tempfile.mkstemp(prefix=timestamp + '.QuickSeed.', suffix='.log')
string_format = "%(levelname)s | %(asctime)s | %(name)-8s | %(message)s"

default_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "console": {
            "format": string_format
        },
        "logfile": {
            "format": string_format
        },
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "console",
            "stream": "ext://sys.stdout"
        },

        "local_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "logfile",
            "filename": tempfilename,
            "maxBytes": 1000000,
            "backupCount": 20,
            "encoding": "utf8",
            "delay": True
        }
    },
    'loggers': {
        'QuickSeed': {
            'handlers': ["console", "local_file_handler"],
            'level': 'DEBUG',
            'propagate': False
        },
        'neo4j': {
            'handlers': ["console", "local_file_handler"],
            'level': 'WARNING',  # Set to WARNING to suppress INFO messages
            'propagate': False
        },
        'neo4j.notifications': {
            'handlers': ["console", "local_file_handler"],
            'level': 'ERROR',  # Set to ERROR to suppress all notifications
            'propagate': False
        },
        'neo4j.io': {
            'handlers': ["console", "local_file_handler"],
            'level': 'WARNING',
            'propagate': False
        },
        'neomodel': {
            'handlers': ["console", "local_file_handler"],
            'level': 'DEBUG',
            'propagate': False
        },
        'py2neo': {
            'handlers': ["console", "local_file_handler"],
            'level': 'WARNING',
            'propagate': False
        },
        'agentlib': {
            'handlers': ["console", "local_file_handler"],
            'level': 'DEBUG',  # Set to your desired level
            'propagate': False
        },
        'graphquery.graph_client': {  
            'handlers': ["console", "local_file_handler"],
            'level': 'WARNING',  # Only WARNING and above will be logged
            'propagate': False
        },
    }
}


class Loggers:
    """
    Logger Manager.
    """
    IN_SCOPE_LOGGERS = ('QuickSeed',)

    def __init__(self):
        self._loggers = {}
        self.load_all_loggers()
        self.profiling_enabled = False

        # disable filelock info logs
        logging.getLogger("filelock").setLevel(logging.WARNING)

        self.config_dict = None
        if default_config is not None:
            self.config_dict = default_config
        if self.config_dict is not None:
            logging.config.dictConfig(self.config_dict)
        self.handler = logging.StreamHandler()
        self.handler.setFormatter(logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))

    def load_all_loggers(self):
        for name, logger in logging.Logger.manager.loggerDict.items():
            if any(name.startswith(x + '.') or name == x for x in self.IN_SCOPE_LOGGERS):
                self._loggers[name] = logger

    def __getattr__(self, k):
        real_k = k.replace('_', '.')
        if real_k in self._loggers:
            return self._loggers[real_k]
        else:
            raise AttributeError(k)

    def __dir__(self):
        return list(super(Loggers, self).__dir__()) + list(self._loggers.keys())
