from pathlib import Path
import json
import time

from .analysis import Analysis, AnalysisWeight


class ExternalAnalysis(Analysis):
    """
    Base class for all external analyses that are not part of the core Kumushi but instead will return files that
    can be used by the core Kumushi analyses.
    """
    ANALYSIS_WEIGHT = AnalysisWeight.HEAVY

    def __init__(self, *args, results_file=None):
        super().__init__(*args)
        self.results_file = Path(results_file) if isinstance(results_file, str) else results_file

    def _analyze(self):
        if self.results_file is None:
            return

        while True:
            if self.results_file and self.results_file.exists():
                try:
                    with open(self.results_file, "r") as f:
                        results = json.load(f)
                except json.JSONDecodeError:
                    results = None

                if results:
                    break

            time.sleep(self.LONG_SLEEP)
