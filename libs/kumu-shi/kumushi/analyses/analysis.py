import logging
import time
import typing
import signal
from enum import IntEnum

from ..data import PoICluster, Program
from ..aixcc import AICCProgram

if typing.TYPE_CHECKING:
    from kumushi.root_cause_analyzer import RootCauseAnalyzer


class AnalysisWeight(IntEnum):
    WEIGHTLESS = 0
    LIGHT = 1
    HEAVY = 2


class AnalysisTimeoutError(Exception):
    """Raised when an analysis times out"""
    pass


_l = logging.getLogger(__name__)


class Analysis:
    NAME: str = None
    FAST_SLEEP = 0.05
    LONG_SLEEP = 60 * 2.5
    DEPENDS_ON = []
    ANALYSIS_WEIGHT = AnalysisWeight.LIGHT
    TIMEOUT = 5*60  # Default 5 minutes timeout
    REQUIRES_NEW_PROGRAM = False

    def __init__(self, program: AICCProgram, finished_callbacks: list[callable] | None = None, timeout: int = None, **kwargs):
        self.program = program
        self._finished_callbacks = finished_callbacks or []
        self.finished = False
        self.timeout = timeout or self.TIMEOUT

        # completed data
        self.poi_clusters = []

    def _analyze(self) -> list[PoICluster]:
        return []

    def _timeout_handler(self, signum, frame):
        """Signal handler for timeout"""
        raise AnalysisTimeoutError(f"Analysis {self.__class__.__name__} timed out after {self.timeout} seconds")

    def analyze(self):
        self.wait_until_ready()
        _l.info(f"Starting analysis {self.__class__.__name__} with timeout {self.timeout}s...")
        _l.info(f"Reinit function resolver for %s", self.__class__.__name__)
        self.program.code.reinit_or_get_function_resolver()
        
        # Set up timeout handling
        old_handler = signal.signal(signal.SIGALRM, self._timeout_handler)
        signal.alarm(self.timeout)
        
        try:
            self.poi_clusters = self._analyze()
            self.on_finished()
        except AnalysisTimeoutError:
            _l.error(f"Analysis {self.__class__.__name__} timed out after {self.timeout} seconds")
            raise
        finally:
            # Restore original signal handler and cancel alarm
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        self.program.reset_function_resolver()

    def ready(self) -> bool:
        # TODO: implement me if analyses start to depend on each other
        if not self.DEPENDS_ON:
            return True

    def wait_until_ready(self):
        while not self.ready():
            time.sleep(self.FAST_SLEEP)

    def on_finished(self):
        _l.info(f"Analysis {self.__class__.__name__} finished!")
        for callback in self._finished_callbacks:
            callback(self)
        self.finished = True
