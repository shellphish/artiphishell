
import os
import re
from typing import Dict

import yaml

SEPARATOR = b'=================================================================\n'

# def parsed_stack_traces(stack_trace):
#     if not stack_trace:
#         return stack_trace
#     trace = []
#     if 'MemorySanitizer: use-of-uninitialized-value' in stack_trace:
#         import ipdb; ipdb.set_trace()
#     for line in stack_trace.splitlines():
#         line = line.strip()
#         res = re.search(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+', line)
#         if not res:
#             continue
#         depth = int(res.group(1))
#         addr = int(res.group(2), 16)
#         line = line[len(res.group(0)):]

#         # determine whether this is a source code info
#         if res := re.search(r'([^\s]*):(\d+):\d+$', line):
#             file = res.group(1)
#             file = os.path.relpath(file, '/src') # source code is in /src when building
#             line_num = int(res.group(2))
#             signature = line[:-len(res.group(0))].strip()
#             #print(depth, hex(addr), signature, file, line_num)
#             trace.append({'depth': depth, 'type': 'source', 'src_loc': f"{file}:{line_num}", 'src_file': file, 'line': line_num, 'signature': signature})

#         # determine whether this is a binary info
#         elif res := re.search(r'\s+\(BuildId:\s+([0-9a-fA-F]+)\)$', line):
#             build_id = res.group(1)
#             line = line[:-len(res.group(0))]
#             res = re.search(r'([^(]+)\+0x([0-9a-fA-F]+)', line)
#             assert res
#             binary = res.group(1)
#             binary = os.path.relpath(binary, os.getcwd() + '/src')
#             offset = int(res.group(2), 16)
#             # signature is anything before binary with trialing ) removed
#             signature = line[:line.index(res.group(1))][:-1].strip()
#             trace.append({'depth': depth, 'type': 'binary', 'binary': binary, 'offset': offset, 'build_id': build_id, 'signature': signature})

#         # asan interceptors?
#         # Example:
#         #   printf_common(void*, char const*, __va_list_tag*) asan_interceptors.cpp.o
#         elif res := re.search(r'\s+([^\s]*)$', line):
#             binary = res.group(1)
#             binary = os.path.relpath(binary, os.getcwd() + '/src')
#             signature = line[:-len(res.group(0))].strip()
#             trace.append({'depth': depth, 'type': 'maybe_asan_interceptor', 'binary': binary, 'signature': signature})
#         else:
#             raise RuntimeError(f"Fail to parse stack_trace: {stack_trace}")

#     # derive function name from the function signature
#     for x in trace:
#         signature = x['signature']
#         res = re.search(r'\(.*\)$', signature)
#         if not res:
#             x['func_name'] = signature
#         else:
#             x['func_name'] = signature[:-len(res.group(0))]

#     return trace

def triggered_sanitizers(stderr: bytes, sanitizers: Dict[str, str]):
    triggered_sanitizers = []
    for key, value in sanitizers.items():
        if value.encode() in stderr:
            triggered_sanitizers.append(key)
    return triggered_sanitizers

def clean_report(report: bytes):
    report = re.sub('of size \d+', 'of size <REDACTED>', report)
    report = re.sub('is located \d+ bytes', 'is located <REDACTED> bytes', report)
    report = re.sub('0x[0-9a-fA-F]{8,}', '0x<REDACTED>', report)
    report = re.sub(' is ascii string \'[^\']+\'', '', report)
    return report

def extract_asan_report(stderr: bytes, sanitizers: Dict[str, str]):
    if not stderr:
        return None
    
    raw_reports = []
    start_pos = 0
    # print(f"Searching for reports in {len(stderr)} bytes")
    
    # if b'MemorySanitizer: CHECK failed' in stderr:
    #     import ipdb; ipdb.set_trace()

    while start_pos != len(stderr) and (
        ((match := re.search(b'==\d+==', stderr[start_pos:])) is not None) or \
        ((match := re.search(b'==\d+:\d+==', stderr[start_pos:])) is not None) or \
        ((match := re.search(b'[a-zA-Z0-9./-]+:\d+:\d+: runtime error: ', stderr[start_pos:])) is not None) or \
        ((match := re.search(b'MemorySanitizer: CHECK failed', stderr[start_pos:])) is not None)
    ):
        marker_start = start_pos + match.start()
        marker_end = start_pos + match.end()
        marker = stderr[marker_start:marker_end]
        if not marker.startswith(b'=='):
            marker = None
            marker_end = marker_start

        start_pos = marker_end

        error_line_end = stderr.find(b'\n', marker_end)
        if error_line_end == -1:
            error_line_end = len(stderr)
        error_line = stderr[marker_end:error_line_end]
        # assert error_line.startswith(b'ERROR: ') or \
        #     error_line.startswith(b'WARNING: ') or \
        #     re.match('index -?\d+ out of bounds'), f"Failed to find error line: {cur!r}, {marker!r}"

        result = {}
        # result['start_pos'] = start_pos
        # result['marker'] = marker.decode('utf-8', errors='ignore')
        result['error_line'] = error_line.strip().decode('utf-8', errors='ignore')
        result['error_line'] = re.sub('0x[0-9a-fA-F]{8,}', '0x<REDACTED>', result['error_line'])

        # now find the last occurence of the marker and extract until there is a newline after
        end_pos = -1
        if marker is not None:
            end_pos = stderr.rfind(marker)
        if end_pos == -1:
            end_pos = stderr.find(b'SUMMARY: ', marker_end)
        if end_pos == -1:
            end_pos = stderr.find(b'Return Code', marker_end)
        assert end_pos != -1, f"Failed to find end marker: {stderr!r}, {marker!r}"
        end_pos_end_line = stderr.find(b'\n', end_pos)
        if end_pos_end_line == -1:
            end_pos_end_line = len(stderr)
        
        # result['end_pos'] = start_pos + end_pos_end_line
        result['triggered_sanitizers'] = triggered_sanitizers(stderr, sanitizers)
        result['report'] = stderr[marker_start:end_pos_end_line+start_pos].decode('utf-8', errors='ignore')
        # result['stacktraces'] = parsed_stack_traces(result['report'])
        result['report'] = clean_report(result['report'])
        if marker is not None:
            result['report'] = result['report'].replace(marker.decode('utf-8', errors='ignore'), '==<MARKER>==')

        # print(result)
        if result not in raw_reports:
            # print(result)
            raw_reports.append(result)

        # print(f"Found report: {result['error_line']}, updating start_pos to {start_pos=} + {end_pos_end_line=} = {start_pos + end_pos_end_line}")
        start_pos = start_pos + end_pos_end_line

    return raw_reports



def parse(stderr, sanitizers: Dict[str, str]):
    reports = extract_asan_report(stderr, sanitizers)
    if not reports:
        return None

    triggered_sanitizers = []
    for key, value in sanitizers.items():
        if value.encode() in stderr:
            triggered_sanitizers.append(key)

    crash_data = {
        "triggered_sanitizers": triggered_sanitizers,
        "reports": reports
    }
    return crash_data

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--pov-report', type=str, help='Path to pov report')
    parser.add_argument('--sanitizers', type=str, help='Sanitizers to search for')
    args = parser.parse_args()
    sanitizers = {f'id_{i}': sanitizer for i, sanitizer in enumerate(args.sanitizers.split(','))}

    with open(args.pov_report, 'rb') as f:
        data = yaml.safe_load(f)
        stderr = data['run_pov_result']['stderr']
        print(yaml.dump(parse(stderr, sanitizers)))