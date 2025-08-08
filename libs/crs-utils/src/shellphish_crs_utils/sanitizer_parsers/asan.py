import argparse
import os
import re
import json
import logging
from io import StringIO
from pathlib import Path
import string
from typing import Any, Dict, List, Optional, Union

from shellphish_crs_utils.models.crash_reports import BacktraceType, CallTraceEntry, CallTrace, SanitizerReport
from shellphish_crs_utils.models.symbols import BinaryLocation, RelativePathKind, SourceLocation
from shellphish_crs_utils.utils import artiphishell_should_fail_on_error
from shellphish_crs_utils.models.target import VALID_SOURCE_FILE_SUFFIXES, VALID_SOURCE_FILE_SUFFIXES_C
import yaml


log = logging.getLogger("Asan2Report")
#log.propagate = False

SEPARATOR = b'=================================================================\n'


def extract_raw_asan_report_from_stderr(stderr):
    errs = stderr
    if type(errs) is str:
        errs = errs.encode()

    # print(outs.decode('latin-1'))
    # print(errs.decode('latin-1'))
    # idx = errs.find(SEPARATOR)
    if match := re.match(rb'==\d+==', errs):
        # find the next index of this occuring to get the end of the report
        idx = errs.find(match.group(0), 1)
        idx = errs.find(b"\n", idx)
        report = errs[:idx].decode().strip()

    if (idx := errs.find(b'==WARNING: ')) >= 0:
        report = errs[idx:].decode().strip()
    elif (idx := errs.find(b'==ERROR: ')) >= 0:
        report = errs[idx:].decode().strip()
    elif (idx := errs.find(b'== ERROR: ')) >= 0:
        #
        report = errs[idx:].decode().strip()
    elif (idx := errs.find(SEPARATOR)) >= 0:
        report = errs[idx+len(SEPARATOR):].decode().strip()
    elif (idx := errs.find(b'UndefinedBehaviorSanitizer:DEADLYSIGNAL')) >= 0:
        report = errs[idx+len(b'UndefinedBehaviorSanitizer:DEADLYSIGNAL'):].decode().strip()
    elif (idx := errs.find(b'MemorySanitizer:DEADLYSIGNAL')) >= 0:
        report = errs[idx+len(b'MemorySanitizer:DEADLYSIGNAL'):].decode().strip()

    elif (idx := errs.find(b'MemorySanitizer: CHECK failed')) >= 0:
        report = errs[idx:].decode().strip()

    elif match := re.search(b'.*: runtime error: .*', errs):
        report = errs[errs.find(b'runtime error: '):].decode().strip()

    else:
        log.warning("Fail to find the separator in the stderr")
        return None

    return report

def get_project_relative_file_path(file_path: Union[Path, str], target_source_root) -> Optional[Path]:
    if isinstance(file_path, str):
        file_path = Path(file_path)

    assert Path(target_source_root).is_relative_to('/src/')
    if not str(file_path).startswith('/src'):
        return None

    if target_source_root:
        try:
            return file_path.relative_to(target_source_root)
        except ValueError:
            pass
    return None

def extract_function_name_from_start(str):
    open_paren_count = 0
    open_bracket_count = 0
    start_index = 0
    if str.startswith('operator '):
        start_index = len('operator ')
    for i, c in list(enumerate(str))[start_index:]:
        if c in string.whitespace and open_bracket_count == 0 and open_paren_count == 0:
            if str[i:].startswith(' const '):
                i += len(' const')
            return str[:i]

        if c == '<':
            open_bracket_count += 1
        elif c == '>':
            open_bracket_count -= 1

        if c == '(':
            open_paren_count += 1
        elif c == ')':
            open_paren_count -= 1

    return str

def parse_raw_asan_report(report, target_source_root=None) -> SanitizerReport:
    """
    crash_type: memory-leak, null-ptr-deref, wild-ptr-deref
    """
    io = StringIO(report)

    result = {}
    result['raw_report'] = report

    # extract sanitizer type and crash type
    line = io.readline()
    if '==ERROR: ' in line:
        line = line.split('==ERROR: ')[1]
    elif '== ERROR: ' in line:
        line = line.split('== ERROR: ')[1]
    elif '==WARNING: ' in line:
        line = line.split('==WARNING: ')[1]
    elif '== WARNING: ' in line:
        line = line.split('== WARNING: ')[1]
    result['sanitizer'] = line.split(':')[0].strip()
    if result['sanitizer'] != 'runtime error':
        result['sanitizer'] = result['sanitizer'].split()[0]
    match result['sanitizer']:
        case 'LeakSanitizer':
            crash_type  = line.split(':')[-1].strip()
            assert crash_type == 'detected memory leaks'
            result['crash_type'] = 'memory-leak'
        case 'AddressSanitizer':
            if ': attempting double-free' in line:
                crash_type = 'double-free'
            elif ': attempting free on address which was not malloc()-ed' in line:
                crash_type = 'bad-free'
            elif ': bad parameters to __sanitizer_' in line:
                crash_type = 'bad-sanitizer-parameters'
            elif 'AddressSanitizer failed to allocate' in line or 'out of memory: allocator is trying to allocate' in line:
                crash_type = 'out-of-memory'
            else:
                crash_type  = line.split('AddressSanitizer: ')[1].split(':')[0].strip().split()[0]
            result['crash_type'] = crash_type
        case 'MemorySanitizer':
            crash_type  = line.split("MemorySanitizer: ")[1].split(':')[0].strip()
            if crash_type != 'CHECK failed':
                crash_type = crash_type.split()[0]
            result['crash_type'] = crash_type
        case 'UndefinedBehaviorSanitizer':
            crash_type = line.split("UndefinedBehaviorSanitizer: ")[1].split()[0].strip()
            result['crash_type'] = crash_type
        case 'runtime error':
            assert 'UndefinedBehaviorSanitizer' in report
            result['sanitizer'] = 'UndefinedBehaviorSanitizer'
            if match := re.search(r'SUMMARY: UndefinedBehaviorSanitizer: ([0-9a-zA-Z-]+) ', report):
                result['crash_type'] = match.group(1)
            else:
                raise NotImplementedError(f"Unknown sanitizer {result['sanitizer']}")
        case 'libFuzzer':
            result['sanitizer'] = 'libFuzzer'
            result['crash_type'] = line.split('libFuzzer:')[1].strip().split('(')[0].strip()
        case _:
            print(line)

            raise NotImplementedError(f"Unknown sanitizer {result['sanitizer']}")


    # self.sanitizer = self.sanitizer + ": " + self.crash_type
    if result['crash_type'] == 'SEGV':
        assert 'unknown address' in line
        address = line[line.index('unknown address')+len('unknown address'):].strip().split()[0]
        if 'unknown address (pc' not in line:
            addr = int(address, 16)
            if addr == 0:
                crash_type = 'null-ptr-deref'
            else:
                crash_type = 'wild-ptr-deref'
        else:
            crash_type = 'wild-ptr-deref'
        result['internal_crash_type'] = crash_type
    if result['crash_type'].startswith('timeout after'):\
        result['crash_type'] = 'timeout'

    #print(line, [self.sanitizer], [self.crash_type])

    # extract the stack traces and summary
    traces = []
    trace = ''
    summary = None
    for line in io:
        if line.startswith('SUMMARY:'):
            summary = line
            break
        line = line.lstrip(' ')
        trace += line
        if line.strip().startswith('DEDUP_TOKEN:'):
            traces.append(trace.strip())
            trace = ''

    if trace:
        traces.append(trace.strip())
    if summary:
        summary = summary.split("(")[0].strip()
    if not summary:
        summary = f'SUMMARY: {result["sanitizer"]}: {result["crash_type"]}'
    result['summary'] = summary

    def add_key_to_dict(d, key, value):
        if key not in d:
            d[key] = value
            return
        for i in range(1, 20):
            new_key = key + '--' + str(i)
            if new_key not in d:
                d[new_key] = value
                return
        log.error(f"Failed to add key {key!r}:{value!r} to dict??? {d!r}")
        if artiphishell_should_fail_on_error():
            raise ValueError(f"Failed to add key {key!r}:{value!r} to dict??? {d!r}")
        else:
            return # just ignore the trace
    # categorize stack traces
    stack_traces = {}
    traces = [x for x in traces if x.strip() and '#0' in x]
    stack_traces['main'] = traces[0] if len(traces) >= 1 else ''
    match result['crash_type']:
        case 'memory-leak' | 'null-ptr-deref' | 'wild-ptr-deref' | 'global-buffer-overflow' | 'stack-overflow' | \
                'SEGV' | 'ABRT' | 'CHECK failed' | 'undefined-behavior' | 'unknown-crash' | 'out-of-memory' | \
                'fuzz target overwrites its const input' | 'fuzz target exited' | 'bad-sanitizer-parameters':
            pass
        case 'heap-buffer-overflow' | 'container-overflow' | 'use-after-poison' | 'memcpy-param-overlap' | 'negative-size-param':
            for trace in traces[1:]:
                if '\nfreed by ' in trace:
                    add_key_to_dict(stack_traces, 'buffer-previously-freed', trace)
                elif '\npreviously allocated by ' in trace:
                    add_key_to_dict(stack_traces, 'allocate', trace)
                elif 'allocated by' in trace:
                    add_key_to_dict(stack_traces, 'allocate', trace)
                else:
                    log.warning(f"Failed to parse trace {trace!r} for crash type {result['crash_type']}")
                    if artiphishell_should_fail_on_error():
                        raise ValueError(f"Failed to parse trace {trace!r} for crash type {result['crash_type']}")
        case 'heap-use-after-free' | 'double-free':
            stack_traces['free'] = traces[1] if len(traces) >= 2 else ''
            stack_traces['allocate'] = traces[2] if len(traces) >= 3 else ''
            assert len(traces) >= 3 and 'freed by' in traces[1] and 'allocated by' in traces[2]
        case 'stack-buffer-overflow' | 'bad-free' | 'stack-use-after-scope' | 'stack-buffer-underflow':
            stack_traces['crashing-address-frame'] = traces[1] if len(traces) >= 2 else ''
            stack_traces['frame-info'] = traces[2] if len(traces) >= 3 else ''
            assert len(traces) >= 2 and 'is located in stack' in traces[1]
            assert len(traces) <= 2 or 'This frame has ' in traces[2]
        case 'stack-use-after-return':
            stack_traces['crashing-address-frame'] = traces[1] if len(traces) >= 2 else ''
            assert len(traces) >= 2 and 'is located in stack' in traces[1]
        case 'dynamic-stack-buffer-overflow':
            if len(traces) > 1:
                stack_traces['crashing-address-frame'] = traces[1] if len(traces) >= 2 else ''
                assert len(traces) >= 2 and 'is located in stack' in traces[1]
        case 'use-of-uninitialized-value':
            for trace in traces[1:]:
                if 'Uninitialized value was stored to memory at' in trace:
                    add_key_to_dict(stack_traces, 'uninitialized-value-stored', trace)
                elif 'Uninitialized value was created by' in trace:
                    add_key_to_dict(stack_traces, 'uninitialized-value-creation', trace)

        case 'unknown-crash' | 'deadly signal' | 'timeout':
            stack_traces['main'] = traces[0] if len(traces) >= 1 else ''

        case _:

            print(result['crash_type'])
            print(traces)
            raise NotImplementedError(f"Unknown crash_type {result['crash_type']}")

    # extract crash action
    line = stack_traces['main']
    result['crash_info'] = {}
    if line:
        elems = line.split()
        match result['sanitizer']:
            case 'LeakSanitizer':
                result['crash_info']["access"] = elems[1].lower()
                result['crash_info']["size"] = int(elems[elems.index('of')+1])
            case 'libFuzzer':
                if result['crash_type'] == 'fuzz target overwrites its const input':
                    result['crash_info']["access"] = 'WRITE'
                    result['crash_info']["size"] = 'unknown'
                elif result['crash_type'] in ['deadly signal', 'out-of-memory', 'fuzz target exited', 'timeout']:
                    result['crash_info']['access'] = 'unknown'
                    result['crash_info']['size'] = 'unknown'
                else:

                    raise NotImplementedError(f"Unknown sanitizer {result['sanitizer']}")
            case 'AddressSanitizer':
                if result['crash_type'] in ['null-ptr-deref', 'wild-ptr-deref', 'SEGV']:
                    result['crash_info']["access"] = elems[elems.index('a')+1]
                    result['crash_info']["size"] = 'unknown'
                elif result['crash_type'] in ['stack-overflow', 'double-free', 'bad-free', 'out-of-memory',
                                            'memcpy-param-overlap', 'negative-size-param', 'bad-sanitizer-parameters']:
                    result['crash_info']["access"] = 'unknown'
                    result['crash_info']["size"] = 'unknown'
                elif result['crash_type'] in [
                    'heap-buffer-overflow', 'stack-buffer-overflow', 'heap-use-after-free', 'stack-use-after-return',
                    'use-after-poison', 'global-buffer-overflow', 'container-overflow', 'unknown-crash',
                    'stack-use-after-scope', 'dynamic-stack-buffer-overflow', 'stack-buffer-underflow'
                    ]:
                    result['crash_info']["access"] = elems[0].lower()
                    result['crash_info']["size"] = int(elems[elems.index('size')+1])
                elif result['crash_type'] in ['SEGV', 'ABRT', 'CHECK failed']:
                    result['crash_info']["access"] = 'unknown'
                    result['crash_info']["size"] = 'unknown'
                else:
                    #
                    raise NotImplementedError(f"Unknown crash type {result['crash_type']} for sanitizer {result['sanitizer']}")
            case 'UndefinedBehaviorSanitizer':
                if result['crash_type'] in ['SEGV']:
                    result['crash_info']["access"] = elems[elems.index('a')+1]
                    result['crash_info']["size"] = 'unknown'
                elif result['crash_type'] in ['undefined-behavior']:
                    result['crash_info']["access"] = 'unknown'
                    result['crash_info']["size"] = 'unknown'
                elif result['crash_type'] in ['stack-overflow']:
                    result['crash_info']["access"] = 'unknown'
                    result['crash_info']["size"] = 'unknown'
                else:
                    raise NotImplementedError(f"Unknown UBSAN crash_type {result['sanitizer']}")

            case "MemorySanitizer":
                if result['crash_type'] in ['CHECK failed', 'use-of-uninitialized-value']:
                    result['crash_info']['access'] = 'unknown'
                    result['crash_info']['size'] = 'unknown'
                elif result['crash_type'] in ['SEGV']:
                    result['crash_info']["access"] = elems[elems.index('a')+1]
                    result['crash_info']["size"] = 'unknown'
                else:

                    raise NotImplementedError(f"Unknown MSAN crash_type {result['sanitizer']}")

            case _:
                print(line)
                raise NotImplementedError(f"Unknown sanitizer {result['sanitizer']}")

        #print(self.crash_action)

    # further parse stack_trace
    result['stack_traces'] = {}
    for k, v in stack_traces.items():
        if not v:
            continue

        dedup_token = None
        if 'DEDUP_TOKEN' in v:
            dedup_token = v.split('DEDUP_TOKEN: ')[1].split('\n')[0]
        bt = parsed_stack_trace(v, target_source_root=target_source_root)
        result['stack_traces'][k] = CallTrace(reason=k, dedup_token=dedup_token, call_locations=bt)

    return SanitizerReport.model_validate(result)

def parse_asan_reports_from_stderr(stderr_bytes, target_source_root=None) -> List[SanitizerReport]:
    all_report_options = stderr_bytes.split(SEPARATOR)
    reports = []
    for option in all_report_options:
        if not option:
            continue
        report = extract_raw_asan_report_from_stderr(option)
        if report:
            reports.append(parse_raw_asan_report(report, target_source_root=target_source_root))
    return reports

def get_func_name(signature):
    res = re.search(r'\(.*\)$', signature)
    if not res:
        return signature
    return signature[:-len(res.group(0))]

def parsed_stack_trace(stack_trace, target_source_root=None):
    if not stack_trace:
        return []
    trace: List[CallTraceEntry] = []
    for line in stack_trace.splitlines():
        line = line.strip()
        full_line = line
        res = re.search(r'#(\d+)\s+(0x[0-9a-fA-F]+) ', line)
        if not res:
            continue
        depth = int(res.group(1))
        addr = int(res.group(2), 16)
        line = line[len(res.group(0)):]
        if line.startswith('in '):
            line = line[3:]
            signature = extract_function_name_from_start(line)
            func_name = get_func_name(signature)
            line = line[len(signature):].lstrip()
        else:
            line = line.lstrip()
            signature = '' # if this is the case, there is no signature
            func_name = ''

        # determine whether this is a source code info
        if res := re.search(r'([^\s]*):(\d+):\d+$', line) or re.search(r'([^\s]*):(\d+)$', line):
            full_file_path = Path(res.group(1)).resolve()
            line_num = int(res.group(2))
            #print(depth, hex(addr), signature, file, line_num)
            trace.append(
                CallTraceEntry(
                    depth=depth,
                    type=BacktraceType.source,
                    trace_line=full_line,
                    source_location=SourceLocation(
                        file_name=Path(full_file_path.name),
                        full_file_path=full_file_path,
                        focus_repo_relative_path=get_project_relative_file_path(full_file_path, target_source_root=target_source_root),
                        line_number=line_num,
                        function_name=func_name,
                        raw_signature=signature,
                    )
                )
            )

        elif any(line.strip().endswith(suffix) for suffix in VALID_SOURCE_FILE_SUFFIXES_C):
            full_file_path = Path(line).resolve()
            trace.append(
                CallTraceEntry(
                    depth=depth,
                    type=BacktraceType.source,
                    trace_line=full_line,
                    source_location=SourceLocation(
                        file_name=Path(full_file_path.name),
                        full_file_path=full_file_path,
                        focus_repo_relative_path=get_project_relative_file_path(full_file_path, target_source_root=target_source_root),
                        function_name=func_name,
                        raw_signature=signature,
                    )
                )
            )

        elif line.startswith('/src/'):
            full_file_path = Path(line.strip()).resolve()
            trace.append(
                CallTraceEntry(
                    depth=depth,
                    type=BacktraceType.source,
                    trace_line=full_line,
                    source_location=SourceLocation(
                        file_name=Path(full_file_path.name),
                        full_file_path=full_file_path,
                        focus_repo_relative_path=get_project_relative_file_path(full_file_path, target_source_root=target_source_root),
                        function_name=func_name,
                        raw_signature=signature,
                    )
                )
            )

        # determine whether this is a binary info
        elif res := re.search(r'\(BuildId:\s+([0-9a-fA-F]+)\)$', line):
            build_id = res.group(1)
            line = line[:-len(res.group(0))]
            res = re.search(r'([^(]+)\+0x([0-9a-fA-F]+)', line)
            assert res
            full_binary_path = Path(res.group(1)).resolve()
            offset = int(res.group(2), 16)
            trace.append(
                CallTraceEntry(
                    depth=depth,
                    type=BacktraceType.binary,
                    trace_line=full_line,
                    binary_location=BinaryLocation.create(
                        full_binary_path=full_binary_path,
                        offset=offset,
                        build_id=build_id,
                        function_name=func_name,
                        raw_signature=signature,
                    )
                )
            )

        # asan interceptors?
        # Example:
        #   printf_common(void*, char const*, __va_list_tag*) asan_interceptors.cpp.o
        elif '_start' == func_name:
            line: str
            binary = line
            full_binary_path = binary.split("+")[0].replace("(", "")
            try:
                offset = int(binary.split("+")[1].replace(")", ""), 0)
            except:
                offset = None
            trace.append(
                CallTraceEntry(
                    depth=depth,
                    type=BacktraceType.entrypoint,
                    trace_line=full_line,
                    binary_location=BinaryLocation.create(
                        full_binary_path=full_binary_path,
                        offset=offset,
                        function_name=func_name,
                        raw_signature=signature,
                    )
                )
            )
        elif 'aflpp_driver.c' in line:
            full_source_path = Path(line.split()[-1])
            assert full_source_path.name.endswith('aflpp_driver.c')
            assert line.split()[0] == 'LLVMFuzzerRunDriver'
            trace.append(
                CallTraceEntry(
                    depth=depth,
                    type=BacktraceType.instrumentation,
                    trace_line=full_line,
                    source_location=SourceLocation(
                        file_name=Path(full_source_path.name),
                        full_file_path=full_source_path,
                        focus_repo_relative_path=get_project_relative_file_path(full_source_path, target_source_root=target_source_root),
                        function_name=func_name,
                        raw_signature=signature,
                    )
                )
            )
        elif line.startswith("(<unknown module>)"):
            trace.append(
                CallTraceEntry(
                    depth=depth,
                    type=BacktraceType.unknown,
                    trace_line=full_line,
                )
            )
        elif res := re.search(r'([^\s]*)$', line):
            full_path = res.group(1)
            if full_path.startswith('(') and full_path.endswith(')'):
                full_path = full_path[1:-1]
            relative_path = get_project_relative_file_path(Path(full_path.split("+")[0]), target_source_root=target_source_root)

            if 'sanitizer_common_interceptors.inc' in line:
                trace.append(
                    CallTraceEntry(
                        depth=depth,
                        type=BacktraceType.sanitizer_instrumentation,
                        trace_line=full_line,
                        binary_location=BinaryLocation.create(
                            full_binary_path=full_path,
                            function_name=func_name,
                            raw_signature=signature,
                        )
                    )
                )
            elif any(full_path.endswith(ext) for ext in VALID_SOURCE_FILE_SUFFIXES):
                trace.append(
                    CallTraceEntry(
                        depth=depth,
                        type=BacktraceType.source,
                        trace_line=full_line,
                        source_location=SourceLocation(
                            file_name=Path(Path(full_path).name),
                            full_file_path=Path(full_path),
                            focus_repo_relative_path=relative_path,
                            function_name=func_name,
                            raw_signature=signature,
                        )
                    )
                )
            else:
                offset = 0
                try:
                    if '+' in full_path:
                        full_path, offset = full_path.split('+')
                        offset = int(offset, 0)
                except:
                    offset = 0

                trace.append(
                    CallTraceEntry(
                        depth=depth,
                        type=BacktraceType.binary,
                        trace_line=full_line,
                        binary_location=BinaryLocation.create(
                            full_binary_path=full_path,
                            offset=offset,
                            function_name=func_name,
                            raw_signature=signature,
                        )
                    )
                )
        else:
            if artiphishell_should_fail_on_error():
                raise RuntimeError(f"Fail to parse stack_trace: {stack_trace}")
            else:
                log.error(f"Failed to really parse the line: {line}")

                trace.append(
                    CallTraceEntry(
                        depth=depth,
                        type=BacktraceType.unknown,
                        trace_line=full_line,
                        source_location=None,
                        binary_location=None,
                    )
                )

    for x in trace:
        # check that the source signature and binary signature match if present
        if x.source_location and x.binary_location:
            assert x.source_location.raw_signature == x.binary_location.raw_signature

    return trace

def main():
    parser = argparse.ArgumentParser(description='Parse ASAN reports from the cli')
    parser.add_argument('stderr', type=Path, help='The path to the stderr containing the report')
    parser.add_argument('--target-source-root', type=str, help='The root of the source code')
    args = parser.parse_args()
    stderr = args.stderr.read_bytes()
    reports = parse_asan_reports_from_stderr(stderr, target_source_root=args.target_source_root)
    for i, report in enumerate(reports):
        print(report.model_dump_json())

if __name__ == '__main__':
    main()