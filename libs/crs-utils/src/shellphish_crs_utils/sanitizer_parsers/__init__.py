from datetime import datetime
import logging
import traceback
from typing import Union

from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.models import Optional, SanitizerEnum
from shellphish_crs_utils.models.crash_reports import CallTraceEntry, DedupSanitizerReport, SanitizerReport
from shellphish_crs_utils.models.crs_reports import RawPoVReport, RunPoVResult
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.models.symbols import JavaInfo, SourceLocation
from shellphish_crs_utils.sanitizer_parsers.jazzer import parse_jazzer_sanitizer_reports, parse_jazzer_timeout_reports
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.organizers import organizer_evaluate_crash

log = logging.getLogger(__name__)

def parse_run_output(project_language: Union[str, LanguageEnum], sanitizer: Union[str, SanitizerEnum], exit_code: int, stdout: bytes, stderr: bytes, target_source_root=None, function_resolver=None, crash_time: Optional[datetime] = None, expect_crash=True) -> RawPoVReport:
    # changing stderr to stderr + stdout, since some targets may put the error to stdout, like the tipc target
    if isinstance(project_language, str):
        project_language = LanguageEnum(project_language)
    if isinstance(sanitizer, str):
        sanitizer = SanitizerEnum(sanitizer)

    stderr_bytes: bytes = stderr
    stdout_bytes: bytes = stdout
    stdall_bytes = stdout_bytes + b'\n' + stderr_bytes


    organizer_crash_eval = organizer_evaluate_crash(
        sanitizer=sanitizer,
        return_code=exit_code,
        stdout_bytes=stdout_bytes,
        stderr_bytes=stderr_bytes,
        stdall_bytes=stdall_bytes,
        unexpected_crash=not expect_crash,  # we assume that the run_pov_result is unexpected
    )

    try:
        if project_language == LanguageEnum.jvm and b"ALARM: working on the last Unit for " in stdall_bytes:
            jazzer_timeout_sanitizer_reports = parse_jazzer_timeout_reports(stdall_bytes)
            triggered_sanitizers = list(sorted(set(r.final_sanitizer_type for r in jazzer_timeout_sanitizer_reports)))
            if artiphishell_should_fail_on_error():
                assert len(jazzer_timeout_sanitizer_reports) <= 1, "Multiple Jazzer timeout reports in a single run_pov_result"
            report = jazzer_timeout_sanitizer_reports[-1]
            if function_resolver:
                report.enhance_with_function_resolver(function_resolver)
            return RawPoVReport(
                parser="jazzer",
                organizer_crash_eval=organizer_crash_eval,
                crash_report=report,
                extra_context=report.extra_context,
                dedup_crash_report=DedupSanitizerReport.from_sanitizer_report(report),
                triggered_sanitizers=triggered_sanitizers,
            )
        if project_language == LanguageEnum.jvm and b"== Java Exception:" in stdall_bytes:
            # return RawPoVReport(parser="jazzer",
            #                     report=parse_jazzer(stdall_bytes, sanitizers),
            #                     triggered_sanitizers=triggered_sanitizers)

            jazzer_sanitizer_reports = parse_jazzer_sanitizer_reports(stdall_bytes)
            triggered_sanitizers = list(sorted(set(r.final_sanitizer_type for r in jazzer_sanitizer_reports)))

            if artiphishell_should_fail_on_error():
                assert len(jazzer_sanitizer_reports) <= 1, "Multiple Jazzer reports in a single run_pov_result"

            report = jazzer_sanitizer_reports[-1]
            if function_resolver:
                report.enhance_with_function_resolver(function_resolver)

            return RawPoVReport(
                parser="jazzer",
                organizer_crash_eval=organizer_crash_eval,
                crash_report=report,
                extra_context=report.extra_context,
                dedup_crash_report=DedupSanitizerReport.from_sanitizer_report(report),
                triggered_sanitizers=triggered_sanitizers,
            )

        elif project_language in (LanguageEnum.c, LanguageEnum.cpp, LanguageEnum.go, LanguageEnum.rust) and any(v in stdall_bytes for v in [b"AddressSanitizer", b'MemorySanitizer', b'UndefinedBehaviorSanitizer', b'LeakSanitizer', b'SUMMARY: libFuzzer:', b'ERROR: libFuzzer']):
            asan_reports = parse_asan_reports_from_stderr(stdall_bytes, target_source_root=target_source_root)
            triggered_sanitizers = list(sorted(set(r.final_sanitizer_type for r in asan_reports)))
            # assert len(asan_reports) <= 1, "Multiple ASAN reports in a single run_pov_result"
            assert len(asan_reports) > 0, "No ASAN reports in the run_pov_result"
            extra_report_context = ''
            for extra_report in asan_reports[:-1]: # the last report was fatal, everything before it gets given as extra context
                extra_report_data = extra_report.raw_report.decode()
                extra_report_context += f'{extra_report_data}\n\n\n'
            extra_report_context += asan_reports[-1].extra_context if asan_reports[-1].extra_context else ''
            sanitizer_report = asan_reports[-1]
            if function_resolver:
                sanitizer_report.enhance_with_function_resolver(function_resolver)
            return RawPoVReport(
                parser="asan",
                organizer_crash_eval=organizer_crash_eval,
                extra_context=extra_report_context if extra_report_context else None,
                crash_report=sanitizer_report,
                dedup_crash_report=DedupSanitizerReport.from_sanitizer_report(sanitizer_report),
                triggered_sanitizers=triggered_sanitizers
            )

        else:
            return RawPoVReport(
                parser="failed",
                organizer_crash_eval=organizer_crash_eval,
                unparsed=stdall_bytes,
                triggered_sanitizers=[]
            )
    except Exception as e:
        raise NotImplementedError(f"{stderr!r}. Sanitizer report parsing error: {e}") from e
        # return RawPoVReport(parser="failed",
        #            exception=str(e),
        #            traceback=traceback.format_exc(),
        #            crash_report=None,
        #            unparsed=stdall_bytes,
        #            triggered_sanitizers=[])


def parse_run_pov_result(project_language: Union[str, LanguageEnum], sanitizer: Union[str, SanitizerEnum], run_pov_result: RunPoVResult, target_source_root=None, function_resolver=None) -> RawPoVReport:
    # changing stderr to stderr + stdout, since some targets may put the error to stdout, like the tipc target

    return parse_run_output(
        project_language,
        sanitizer=sanitizer,
        exit_code=run_pov_result.run_exit_code,
        stdout=run_pov_result.stdout,
        stderr=run_pov_result.stderr,
        target_source_root=target_source_root,
        function_resolver=function_resolver
    )


from .jazzer import parse_jazzer_sanitizer_reports
from .asan import parse_asan_reports_from_stderr