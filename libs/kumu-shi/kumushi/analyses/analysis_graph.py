from .analysis import Analysis, AnalysisWeight

class AnalysisGraphCoverageAnalysis(Analysis):
    NAME = 'analysis_graph'
    ANALYSIS_WEIGHT = AnalysisWeight.LIGHT

    def _analyze(self):
        return []