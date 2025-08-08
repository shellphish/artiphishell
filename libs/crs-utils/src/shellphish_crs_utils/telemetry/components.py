from .telemetry import Telemetry
from .enums import SUBMITTER_EVENTS


class ClangIndexerTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Clang Indexer"


class Antlr4IndexerTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Antlr4 Indexer"


class FunctionIndexerTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Function Indexer"


class TargetAnalyzerTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Target Analyzer"


class PoIGuyTelemetry(Telemetry):
    __COMPONENT_NAME__ = "PoI Guy"


class PatcherYTelemetry(Telemetry):
    __COMPONENT_NAME__ = "PatcherY"


class AFLPPTelemetry(Telemetry):
    __COMPONENT_NAME__ = "AFL++"


class ASAN2REPORTTelemetry(Telemetry):
    __COMPONENT_NAME__ = "ASAN Report"


class FFCCTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Find First Crash Report"


class GrammarGuyTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Grammar Guy"


class SubmitterTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Submitter"

    @classmethod
    def log_vds(cls, vds: str, succeeded: int):
        # Check if an event with the same message already exists
        cls.log_component_event(
            event=SUBMITTER_EVENTS.VDS, value=succeeded, message=str(vds)
        )

    @classmethod
    def log_patch(cls, vds: str, succeeded: int):
        # Check if an event with the same message already exists
        cls.log_component_event(
            event=SUBMITTER_EVENTS.PATCH, value=succeeded, message=str(vds)
        )


class PoVGuyTelemetry(Telemetry):
    __COMPONENT_NAME__ = "PoV Guy"


class CoverageQueryTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Coverage Query"


class CoverageTraceTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Coverage Trace"


class InvariantBuildTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Invariant Guy Build"


class InvariantGuyTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Invariant Guy"


class PatcherQTelemetry(Telemetry):
    __COMPONENT_NAME__ = "PatcherQ"


class ChallengeProject(Telemetry):
    __COMPONENT_NAME__ = "Challenge Project"


class DyvaAgentTelemetry(Telemetry):
    __COMPONENT_NAME__ = "Dyva Agent"
