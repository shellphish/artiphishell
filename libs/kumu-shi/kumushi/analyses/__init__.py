from .analysis import Analysis, AnalysisWeight, AnalysisTimeoutError
from .variable_dependencies import VariableDependenciesAnalysis
from .call_trace import CallTraceAnalysis
from .aurora import AuroraAnalysis
from .stack_trace import StackTraceAnalysis
from .git_diff_analysis import GitDiffAnalysis
from .analysis_graph import AnalysisGraphCoverageAnalysis
from .diffguy import DiffGuyAnalysis

# ORDER MATTERS
DEFAULT_ANALYSES = [
    # LIGHT
    (VariableDependenciesAnalysis, True),
    (CallTraceAnalysis, True),
    (AnalysisGraphCoverageAnalysis, False),
    # HEAVY
    (AuroraAnalysis, True),
]

# WEIGHTLESS_ANALYSES = [StackTraceAnalysis, DiffGuyAnalysis]
WEIGHTLESS_ANALYSES = [StackTraceAnalysis, GitDiffAnalysis, DiffGuyAnalysis]
