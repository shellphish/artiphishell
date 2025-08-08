
"""
{
  "sanitizer": "OS Command Injection",
  "backtrace": "== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command InjectionExecuting OS commands with attacker-controlled data can lead to remote code execution.Found in argument 0\tat com.code_intelligence.jazzer.sanitizers.OsCommandInjection.ProcessImplStartHook(OsCommandInjection.java:31)\tat java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1109)\tat java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1073)\tat io.jenkins.plugins.UtilPlug.UtilMain.createUtils(UtilMain.java:194)\tat io.jenkins.plugins.UtilPlug.UtilMain.doexecCommandUtils(UtilMain.java:157)\tat PipelineCommandUtilFuzzer.fuzzerTestOneInput(PipelineCommandUtilFuzzer.java:66)"
}
"""

import json
import os
import re
import argparse
import hashlib
import shutil
import logging
from pathlib import Path
import traceback
from typing import Dict, List
import ast

from shellphish_crs_utils.models.crash_reports import BacktraceType, CallTrace, CallTraceEntry, SanitizerReport, LoSanMetaData, LosanSanitizerEnum, clean_java_report_str
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation, BinaryLocation
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error, safe_decode_string

log = logging.getLogger(__name__)

def extract_found_expected_losan_meta(reason, report: str) -> LoSanMetaData:
    found_string = None
    expected_string = None
    pattern = r'SHELLPHISH_FOUND_LOSAN:\s+"(.*?)"\s+and\s+SHELLPHISH_EXPECTED_LOSAN:\s+"(.*?)"'
    match = re.search(pattern, report)
    if match:
        found_string = match.group(1)
        expected_string = match.group(2)
    else:
        if artiphishell_should_fail_on_error():
                assert False, f"Failed to parse losan report as we failed to parse the metadata using regex: {report}\n"
        else:
            return None

    found_string = ast.literal_eval('b"' + found_string + '"')
    expected_string = ast.literal_eval('b"' + expected_string + '"')
    return LoSanMetaData(
        sanitizer_type = get_losan_sanitizer_type_from_reason(reason),
        found_string=found_string,
        expected_string=expected_string,
    )

def get_losan_sanitizer_type_from_reason(reason: str) -> LosanSanitizerEnum:
    if '[LOSAN] OS Command Injection' in reason:
        return LosanSanitizerEnum.OSCommandInjection
    if '[LOSAN] File path traversal' in reason:
        return LosanSanitizerEnum.FilePathTraversal
    if 'Script Engine Injection: Insecure user input was used in script engine invocation.' in reason:
        return LosanSanitizerEnum.ScriptEngineInjection
    if '[LOSAN] Expression Language Injection' in reason:
        return LosanSanitizerEnum.ExpressionLanguageInjection
    if '[LOSAN] : SQL Injection' in reason:
        return LosanSanitizerEnum.SQLInjection
    if '[LOSAN] Deserialization Sanitizer' in reason:
        return LosanSanitizerEnum.DeserializationVulnerability
    # Speculative, not sure how these look yet

    # if 'SQL Injection: Insecure user input was used in SQL query.' in reason:
        # return LosanSanitizerEnum.SQLInjection

    raise ValueError(f"Unknown LoSan sanitizer type: {reason}")


def parse_java_backtrace_line(depth, line: str) -> CallTraceEntry:
    if '/java.lang.invoke.LambdaForm$' in line:
        log.warning(f"Skipping line: {line} as it's a lambda form")
        return None
    if '/com.code_intelligence.jazzer.driver.FuzzTargetRunner.dumpAllStackTraces' in line:
        log.warning(f"Skipping line: {line} as it's a FuzzTargetRunner dump")
        return None
    line = line.strip()

    try:
        assert line.startswith("at ")
        line = line[3:]
        method_path, file_name_and_line = line.split('(', 1)
        assert file_name_and_line.endswith(")")
        file_name_and_line = file_name_and_line[:-1]

        prefix = None
        if '/' in method_path:
            prefix, method_path = method_path.rsplit('/', 1)
            module_version = None
            if '@' in prefix:
                prefix, module_version = prefix.rsplit('@', 1)
            if prefix not in ("java.xml", "java.base", 'app/'):
                log.warning(f"{line} has an unknown prefix: {prefix}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        class_path, method = method_path.rsplit(".", 1)
        if file_name_and_line == 'Native Method':
            file_name = None
            line_no = None
        elif file_name_and_line.startswith("LambdaForm$") and ':' not in file_name_and_line:
            file_name = None
            line_no = None
        else:
            file_name, line_no = file_name_and_line.rsplit(":", 1)
        if '.' in class_path:
            package, class_name = class_path.rsplit(".", 1)
        else:
            package, class_name = None, class_path

        trace_entry = CallTraceEntry(
            depth=depth,
            trace_line=line,
            type=BacktraceType.source,
            source_location=SourceLocation(

                full_file_path=None,
                file_name=file_name,
                function_name=method,
                line_number=int(line_no) if line_no is not None else None,
                raw_signature=method_path,
                java_info=JavaInfo(
                    is_native_method = file_name_and_line == 'Native Method',
                    full_method_path=method_path,
                    method_name=method,
                    package=package,
                    class_path=class_path,
                    class_name=class_name,
                    package_prefix=prefix,
                )
            )
        )

    except Exception as e:
        trace_entry = CallTraceEntry(
            depth=depth,
            trace_line=line,
            type=BacktraceType.unknown,
        )
        print(f"[CRITICAL]: Failed to parse line: {line} with error: {e}")
        import traceback
        print('\n'.join(traceback.format_exception(e)))

        if artiphishell_should_fail_on_error():
            exception = '\n'.join(traceback.format_exception(e))
            assert False, f"Failed to parse line: {line} with error: \n{exception}"
            raise e

    return trace_entry

def parse_jazzer_timeout_reports(stderr: bytes) -> List[SanitizerReport]:
    if not stderr:
        return None

    raw_report = stderr.rsplit(b"ALARM: working on the last Unit for ", 1)[1].split(b"== ERROR: ", 1)[1]
    assert raw_report.startswith(b"libFuzzer: timeout after ")
    lines = [l for l in safe_decode_string(raw_report).split("\n")][1:]
    reason = 'libFuzzer: timeout'

    stack_traces = {}
    cur_stack_trace = None
    cur_stack_trace_name = None
    parsing_stack_traces = False
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if line.startswith("SUMMARY: "):
            break
        if line.startswith("Stack traces of all JVM threads:"):
            parsing_stack_traces = True
            continue
        if not parsing_stack_traces:
            continue
        if line.startswith("Thread["):
            assert line.endswith("]")
            thread_name = line.split("[", 1)[1].split("]", 1)[0].split(",")[0]
            cur_stack_trace = []
            stack_traces[thread_name] = cur_stack_trace
            continue
        if line.startswith("at "):
            line = line.strip()
            if (trace_entry := parse_java_backtrace_line(len(cur_stack_trace), line)) is None:
                log.warning(f"Skipping line: {line} as it's unknown")
                continue
            cur_stack_trace.append(trace_entry)
        if not line.strip():
            cur_stack_trace = None
            cur_stack_trace_name = None
            continue

    sanitizer_report = SanitizerReport(
        raw_report=raw_report,
        sanitizer="libFuzzer",
        crash_type="timeout",
        summary="libFuzzer: timeout",
        crash_info={},
        stack_traces={
            key: CallTrace(
                reason=key,
                dedup_token=None,
                call_locations=value,
            ) for key, value in stack_traces.items()
        },
        losan=False,
    )
    return [sanitizer_report] if sanitizer_report else None


def parse_jazzer_sanitizer_reports(stderr: bytes) -> List[SanitizerReport]:
    if not stderr:
        return None

    raw_report = stderr
    print(f"Searching for reports in {len(stderr)} bytes")
    all_lines = stderr.split(b'\n')
    report_search = ((idx, x) for idx, x in enumerate(all_lines) if x.strip().startswith(b"== Java Exception:"))
    raw_reports = []

    dedup_tokens = [line for line in all_lines if line.startswith(b"DEDUP_TOKEN:")]
    while current_report := next(report_search, None):
        line_no, line = current_report
        lib_fuzzer_equal_line = next((idx for idx, x in enumerate(all_lines[line_no:]) if x.strip().startswith(b"== libFuzzer crashing input ==")), None)
        report_end = next((idx for idx, x in enumerate(all_lines[line_no:]) if x.strip().startswith(b'reproducer_path=')), None)
        if lib_fuzzer_equal_line is not None:
            report_end = lib_fuzzer_equal_line
        if report_end is None:
            raw_reports.append(all_lines[line_no:])
            break
        print(line_no, report_end)
        raw_reports.append(all_lines[line_no:line_no+report_end]) # we don't want the reproducer_path line here, so it's not +1 on the end

    reports = []
    for i, raw_report in enumerate(raw_reports):
        is_losan_report = False
        losan_meta_str = None
        losan_meta = None
        report = {}
        bytes_report = b'\n'.join(raw_report)
        report = safe_decode_string(bytes_report)
        error_line = safe_decode_string(raw_report[0])
        if "[LOSAN]" in error_line:
            is_losan_report = True
        error_line = clean_java_report_str(error_line)
        reason = error_line.split("Java Exception: ")[1]
        if ': ' not in reason:
            exception_kind = reason
            message = 'unspecified'
        else:
            exception_kind, message = reason.split(": ")[:2]

        if is_losan_report:
            losan_meta_str = safe_decode_string(raw_report[1])
            if "SHELLPHISH_FOUND_LOSAN" in losan_meta_str:
                losan_meta = extract_found_expected_losan_meta(reason, losan_meta_str)
        stack_trace = []
        crash_info = {}
        for line in raw_report:
            line = line.strip().decode("utf-8", "ignore")
            if line.startswith("Found in argument"):
                crash_info['argument'] = line[len("Found in argument "):]
            if not line.startswith("at"):
                continue

            trace_entry = parse_java_backtrace_line(len(stack_trace), line)
            if trace_entry is None:
                log.warning(f"Skipping line: {line} as it's unknown")
                continue
            stack_trace.append(trace_entry)

        # this is super stupid, but somehow in java the DEDUP_TOKEN gets printed to stdout ...
        # so it's out-of-order with the rest of the report on stderr, and we need to match it like this
        if i < len(dedup_tokens):
            dedup_token = dedup_tokens[i].split(b"DEDUP_TOKEN: ")[1].strip().decode("utf-8", "ignore")
        else:
            dedup_token = None # this is fine, we regenerate an equivalent one if need be
        ct = CallTrace(reason=reason, dedup_token=dedup_token, call_locations=stack_trace)
        if is_losan_report and (losan_meta is None):
            if artiphishell_should_fail_on_error():
                assert False, f"Failed to parse losan report as we didn't find the metadata: {report}\n"
            else:
                losan_meta = LoSanMetaData.model_validate(dict(
                    sanitizer_type=get_losan_sanitizer_type_from_reason(reason),
                    found_string=None,
                    expected_string=None,
                ))
        result = SanitizerReport(
            raw_report=bytes_report,
            sanitizer = exception_kind,
            crash_type=message,
            summary=error_line,
            crash_info=crash_info,
            stack_traces={'main': ct},
            losan=is_losan_report,
            losan_metadata=losan_meta,
        )
        reports.append(result)
    return reports
