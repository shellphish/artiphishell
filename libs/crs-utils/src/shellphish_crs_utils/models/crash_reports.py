
from enum import Enum
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import Field, model_validator
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models import JavaInfo
from shellphish_crs_utils.models.base import ShellphishBaseModel
from shellphish_crs_utils.models.symbols import BinaryLocation, SourceLocation
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error

log = logging.getLogger(__name__)

class BacktraceType(Enum):
    source = "source"
    binary = "binary"
    entrypoint = "entrypoint"
    instrumentation = "instrumentation"
    sanitizer_instrumentation = "sanitizer_instrumentation"
    unknown = "unknown"

class CallTraceEntry(ShellphishBaseModel):
    depth: int
    type: BacktraceType = Field(description="The type of the backtrace entry. Describes what this entry refers to (as best we can tell).")

    trace_line: Optional[str] = Field(description="Either the function signature or the error line (Not currently used)")

    source_location: Optional[SourceLocation] = None
    binary_location: Optional[BinaryLocation] = None

    def enhance_with_function_resolver(
        self,
        function_resolver: FunctionResolver,
    ):
        if function_resolver is None:
            log.warning("No function resolver provided, skipping enhancement")
            return
        try:
            source_location = None
            log.info("##### Enhancing call trace entry: %s", self)
            if self.source_location:
                source_location = self.source_location
            elif self.binary_location:
                func_name = self.binary_location.function_name
                source_location = SourceLocation(
                    function_name=func_name,
                    java_info = JavaInfo(
                        package=self.binary_location.package,
                    ) if self.binary_location.package else None,
                )
            else:
                log.warning("No source or binary location found for call trace entry: %s", self)
                return self

            try:
                results = function_resolver.resolve_source_location(source_location, num_top_matches=3, allow_build_generated=False)
            except Exception:
                log.error("Error resolving source location: %s", source_location, exc_info=True)
                if artiphishell_should_fail_on_error():
                    raise
                return

            if not results:
                return

            log.error("Results found for source location: loc=%s: results=%s", source_location, results)
            for key, ranking in results:
                log.info("Ranking: %s: %s", key, ranking)
            try:
                focus_repo_keys = [x[0] for x in results if function_resolver.get(x[0]).focus_repo_relative_path]
            except Exception:
                log.error("Error getting focus repo keys: %s", results, exc_info=True)
                if artiphishell_should_fail_on_error():
                    raise
                return

            if len(focus_repo_keys) > 1:
                # WARNING: multiple focus repo paths found for function name
                log.warning("Multiple focus repo paths found for function name: %s => %s", source_location.function_name, results)
                log.warning("Picking the best one, but this is sus")
                if artiphishell_should_fail_on_error():
                    raise ValueError("Multiple focus repo paths found for function name: %s => %s" % (source_location.function_name, results))
            key = None
            if focus_repo_keys:
                key = focus_repo_keys[0]

            if not key and len(results) >= 2:
                # WARNING: multiple results found for function name
                log.warning("Multiple results found for function name: %s => %s", source_location.function_name, results)
                log.warning("Picking the best one, but this is sus")
                if artiphishell_should_fail_on_error():
                    raise ValueError("Multiple results found for function name: %s => %s" % (source_location.function_name, results))

            if not key and len(results):
                key, rankings = results[0]
                log.info(f"Lookup result function index for {source_location=} {key=} {rankings=}")

            log.info(f"Lookup result function index for {source_location=} {key=}")
            func_index = function_resolver.get_with_default(key, default=None)

            if func_index is not None:
                log.info("Found function index: %s", func_index)

                line_no = source_location.line_number if (source_location.line_number is not None and (func_index.start_line <= source_location.line_number <= func_index.end_line)) else None
                line_map = {
                    func_index.start_line + i: code_line for i, code_line in enumerate(func_index.code.split('\n'))
                }
                source_location = SourceLocation(
                    focus_repo_relative_path=func_index.focus_repo_relative_path,
                    relative_path=func_index.focus_repo_relative_path,
                    full_file_path=func_index.target_container_path,
                    file_name=Path(func_index.target_container_path.name) if func_index.target_container_path else None,
                    function_name=func_index.funcname,
                    line_number=line_no,
                    line_text=line_map[line_no] if line_no in line_map else None,
                    symbol_offset=self.source_location.symbol_offset if self.source_location 
                        else (
                            self.binary_location.symbol_offset if self.binary_location else None
                        ),
                    symbol_size=self.source_location.symbol_size if self.source_location
                        else (
                            self.binary_location.symbol_size if self.binary_location else None
                        ),
                    raw_signature=func_index.signature,
                    function_index_signature=key,
                    function_index_key=key,
                    java_info=(self.source_location.java_info if self.source_location else None) or JavaInfo(
                        package=func_index.package,
                        class_name=func_index.class_name,
                    )
                )
                self.source_location = source_location
                if self.binary_location:
                    self.binary_location.function_index_key = key
                    self.binary_location.function_index_signature = key
        except Exception:
            log.error("Error enhancing call trace entry: %s", self, exc_info=True)
            if artiphishell_should_fail_on_error():
                raise


class CallTrace(ShellphishBaseModel):
    reason: Optional[str] = Field(description="The reason for the call trace, normally a description of the crash")
    dedup_token: Optional[str] = Field(default=None, description="A token that can be used to deduplicate call traces")
    call_locations: List[CallTraceEntry] = Field(description="The call locations of the crash", default_factory=list)

    def get_dedup_token(self):
        if self.dedup_token:
            return self.dedup_token

        return self.get_dedup_token_oss_fuzz()

    def get_dedup_token_full(self):
        dedup_vals = []
        for entry in self.call_locations:
            if entry.source_location:
                if entry.source_location.function_name:
                    dedup_vals.append(str(entry.source_location.function_name))
                elif entry.source_location.file_name:
                    dedup_vals.append(str(entry.source_location.file_name))
                else:
                    dedup_vals.append(f"UNKNOWN_{entry.type}")
            elif entry.binary_location:
                if entry.binary_location.function_name:
                    dedup_vals.append(str(entry.binary_location.function_name))
                elif entry.binary_location.file_name:
                    dedup_vals.append(str(entry.binary_location.file_name))
                else:
                    dedup_vals.append(f"UNKNOWN_{entry.type}")
            else:
                dedup_vals.append(f"UNKNOWN_{entry.type}")
        return '--'.join(dedup_vals)

    def get_dedup_token_oss_fuzz(self, num_entries=3):
        dedup_vals = []
        for entry in self.call_locations[:num_entries]:
            if entry.source_location and entry.source_location.function_name:
                dedup_vals.append(entry.source_location.function_name)
            elif entry.binary_location and entry.binary_location.function_name:
                dedup_vals.append(entry.binary_location.function_name)
            else:
                dedup_vals.append(f"UNKNOWN_LOCATION_{entry.type}_{entry.trace_line}")
        return '--'.join(dedup_vals)

    def get_dedup_token_shellphish(self, num_entries=3):
        dedup_vals = []
        i = 0
        while len(dedup_vals) < num_entries and i < len(self.call_locations):
            entry = self.call_locations[i]
            if entry.source_location and (entry.source_location.focus_repo_relative_path or entry.source_location.function_index_signature):
                dedup_vals.append(entry.source_location.function_name)
            i += 1
        return '--'.join(dedup_vals)


class LosanSanitizerEnum(str, Enum):
    OSCommandInjection = "OSCommandInjection"
    SQLInjection = "SQLInjection"
    FilePathTraversal = "FilePathTraversal"
    ScriptEngineInjection = "ScriptEngineInjection"
    ServerSideRequestForgery = "ServerSideRequestForgery"
    ServerSideTemplateInjection = "ServerSideTemplateInjection"
    DeserializationVulnerability = "DeserializationVulnerability"
    ExpressionLanguageInjection = "ExpressionLanguageInjection" 

class LoSanMetaData(ShellphishBaseModel):
    sanitizer_type: LosanSanitizerEnum = Field(description="The type of losan sanitizer crash that was triggered", required=True)
    found_string: Optional[bytes] = None
    expected_string: Optional[bytes] = None

    def clean_invalid_utf8(self):
        if self.found_string is not None and isinstance(self.found_string, bytes):
            self.found_string = self.found_string.decode('utf-8', errors='ignore').encode('utf-8')
        if self.expected_string is not None and isinstance(self.expected_string, bytes):
            self.expected_string = self.expected_string.decode('utf-8', errors='ignore').encode('utf-8')

    def description(self) -> str:
        return f"The {self.sanitizer_type} sanitizer expected to find `{self.expected_string!r}` but found `{self.found_string!r}`"

class SanitizerReport(ShellphishBaseModel):
    raw_report: bytes
    summary: str
    crash_type: str
    sanitizer: str
    internal_crash_type: Optional[str] = None
    stack_traces: Dict[str, CallTrace]
    crash_info: Dict[str, Any]
    extra_context: Optional[str] = None
    losan: bool = False
    losan_metadata: Optional[LoSanMetaData] = None

    def clean_invalid_utf8(self):
        if self.raw_report is not None and isinstance(self.raw_report, bytes):
            self.raw_report = self.raw_report.decode('utf-8', errors='ignore').encode('utf-8')
        if self.losan_metadata is not None:
            self.losan_metadata.clean_invalid_utf8()

    @model_validator(mode='after')
    def sanity_check_model(self) -> "SourceLocation":
        # print(self)
        # import ipdb; ipdb.set_trace()
        assert self.losan == (self.losan_metadata is not None), "If losan is set, losan_metadata must be set"
        assert self.losan == (b'[LOSAN]' in self.raw_report), "losan should be set if and only if the report contains [LOSAN]"
        if self.losan:
            # if there's a losan report, we should *always* have a stack trace
            assert self.stack_traces, "If losan is set, we should have stack traces"
            assert '[LOSAN]' in self.summary, "If losan is set, we should have [LOSAN] in the summary"

        return self

    @property
    def final_crash_type(self):
        if self.internal_crash_type == None:
            return self.crash_type
        return self.internal_crash_type

    @property
    def final_sanitizer_type(self):
        return self.sanitizer + ": " + self.crash_type

    @classmethod
    def from_asan_report(cls, report: bytes):
        return cls(
            raw_report=report,
            summary='',
            crash_type="UNKNOWN",
            sanitizer="asan",
            stack_traces={},
            crash_info={}
        )
    
    
    def enhance_with_function_resolver(self, function_resolver: FunctionResolver):
        if not function_resolver:
            log.warning("No function resolver provided, skipping enhancement")
            return
        assert function_resolver is not None, "Function resolver is required to enhance sanitizer report"
        log.info("Enhancing sanitizer report: %s", self)
        for stack_trace_name, stack_trace in self.stack_traces.items():
            for cte in stack_trace.call_locations:
                try:
                    cte.enhance_with_function_resolver(function_resolver)
                except Exception as e:
                    log.error("Error enhancing call trace entry: %s", cte, exc_info=True)
                    log.error("Error: %s", e)
                    if artiphishell_should_fail_on_error():
                        raise


def clean_java_report_str(report: str):
    report_start = report.split('\n')[0]
    report_start = report_start.split(':')[:3]
    report_start = ':'.join(report_start)
    report = report_start + '\n' + '\n'.join(report.split('\n', 1)[1:])
    report = re.sub(r'collections took \d+m?s', 'collections took <REDACTED>', report)
    report = re.sub(r'\(use .* to reproduce\)', '', report).strip()
    report = re.sub(r'File path traversal: .*', 'File path traversal', report)
    report = re.sub(r'FOUND:\s+"(.*?)"\s+and\s+EXPECTED:\s+"(.*?)"', 'FOUND: <REDACTED> and EXPECTED: <REDACTED>', report)
    report = re.sub(r'-Xmx\d+[mMgGkK]', '-Xmx<REDACTED>', report)
    report = re.sub(r'java.io.IOException: Cannot run program ".*', 'java.io.IOException: Cannot run program', report)
    report = re.sub(r'PS Scavenge: \d+ collections took', 'PS Scavenge: <REDACTED> collections took', report)
    report = re.sub(r'Attempted connection to: .*', 'Attempted connection to: <REDACTED>', report)
    report = re.sub(r'Index \d+ out of bounds for length \d+', 'Index <REDACTED> out of bounds for length <REDACTED>', report)
    report = re.sub(r' \d+ seconds', ' <REDACTED> seconds', report)
    return report

def clean_report(report: bytes):
    # first, find the line starting with "SUMMARY: " and remove every line after that
    if b'SUMMARY:' in report:
        report, rest = report.split(b'SUMMARY:', 1)
        report += b'SUMMARY:' + rest.split(b'\n', 1)[0]

    # if 'libFuzzer: timeout' is in the report, replace the entire report since the stack-trace is non-deterministically ordered in the report.
    if b'libFuzzer: timeout' in report:
        return b'<ARTIPHISHELL: Timeout occurred during fuzzing, report not available>\nSUMMARY: libFuzzer: timeout'

    report = report.decode('utf-8', errors='ignore')
    report = re.sub(r'\+0x[0-9a-fA-F]*', '+0x<REDACTED>', report)
    report = re.sub(r'==\d+==', '==MARKER==', report)
    report = re.sub(r'of size \d+', 'of size <REDACTED>', report)
    report = re.sub(r'is located \d+ bytes', 'is located <REDACTED> bytes', report)
    report = re.sub(r'inside of \d+-byte', 'inside of <REDACTED>-byte', report)
    report = re.sub(r'after \d+-byte region', 'after <REDACTED>-byte region', report)
    report = re.sub(r'SCARINESS: \d+', 'SCARINESS: <REDACTED>', report)
    report = re.sub(r'\d+-byte-write', '<REDACTED>-byte-write', report)
    report = re.sub(r'\d+-byte-read', '<REDACTED>-byte-read', report)
    report = re.sub(r'multi-byte-write', 'multi-byte-write', report)
    report = re.sub(r'multi-byte-read', 'multi-byte-read', report)
    report = re.sub(r'0x[0-9a-fA-F]{8,}', '0x<REDACTED>', report)
    report = re.sub(r' is ascii string \'[^\']+\'', '', report)
    report = re.sub(r'0x[0-9a-fA-F]{8,}', '0x<REDACTED>', report)

    report = re.sub(r'SHELLPHISH_FOUND_LOSAN: \"(.*?)\"', 'SHELLPHISH_FOUND_LOSAN: "<REDACTED>"', report)
    report = re.sub(r'SHELLPHISH_EXPECTED_LOSAN: \"(.*?)\"', 'SHELLPHISH_EXPECTED_LOSAN: "<REDACTED>"', report)

    return clean_java_report_str(report)

class DedupSanitizerReport(ShellphishBaseModel):
    cleaned_report: str
    dedup_tokens_shellphish: Dict[str, str]
    dedup_tokens_full: Dict[str, str]
    dedup_tokens: Dict[str, str]
    crash_type: str
    sanitizer: str
    internal_crash_type: Optional[str] = None
    stack_traces: Dict[str, CallTrace]
    losan: bool

    @classmethod
    def from_sanitizer_report(cls, report: SanitizerReport):
        dedup_tokens = {k: v.get_dedup_token() for k, v in report.stack_traces.items()}
        dedup_tokens_full = {k: v.get_dedup_token_full() for k, v in report.stack_traces.items()}
        dedup_tokens_shellphish = {k: v.get_dedup_token_shellphish() for k, v in report.stack_traces.items()}
        stack_traces = {}
        for k, v in report.stack_traces.items():
            call_locations = []
            for entry in v.call_locations:
                ent = CallTraceEntry(**entry.model_dump())
                ent.trace_line = clean_report(ent.trace_line.encode('utf-8'))
                call_locations.append(ent)
            stack_traces[k] = CallTrace(reason=v.reason, dedup_token=v.dedup_token, call_locations=call_locations)
        return cls(
            cleaned_report=clean_report(report.raw_report),
            dedup_tokens_full=dedup_tokens_full,
            dedup_tokens=dedup_tokens,
            dedup_tokens_shellphish=dedup_tokens_shellphish,
            crash_type=report.crash_type,
            sanitizer=report.sanitizer,
            internal_crash_type=report.internal_crash_type,
            stack_traces=stack_traces,
            losan=report.losan
        )

    @property
    def final_crash_type(self):
        if self.internal_crash_type == None:
            return self.crash_type
        return self.internal_crash_type

    @property
    def final_sanitizer_type(self):
        return self.sanitizer + ": " + self.crash_type