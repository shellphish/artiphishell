import logging
import os
import re
from ast import literal_eval

# Configure logging
logger = logging.getLogger(__name__)


######################################################################################################################
#######                                              LINUX                                                    ########
######################################################################################################################

def _poi_split(traces):
    # List to hold parsed information from each trace
    parsed_traces = []
    error_pattern_strip_out_kasan = re.compile('^(BUG :|BUG:|INFO:|ERROR:|PANIC:|ASSERT:|FATAL:|CRITICAL:)\s*KASAN:\s*',
                                               re.MULTILINE)

    for trace in traces:
        # Initialize the dictionary with default values set to None
        record = {
            'poi': trace,
            'function': None,
            'file_path': None,
            'line_number': None,
            'symbol_offset': None,
            'symbol_size': None
        }

        trace = re.sub('(discriminator [0-9]+)', '', trace)

        # Only proceed if 'at' is present in the trace string
        # Previously, 'in' was used to extract the function name, but now it 'at' is used
        if ' at ' in trace:
            parts_after_at = trace.split(' at ', 1)[-1].strip()
            words = parts_after_at.split()

            # Ensure there are at least two words following 'at' for further processing
            if len(words) >= 2:
                function_with_offset, file_with_line = words[-2], words[-1]
                file_with_line = file_with_line.lstrip('(').rstrip(')')

                # Split function from offset and then offset into symbol offset and size
                if '+' in function_with_offset and '/' in function_with_offset:
                    function, offset = function_with_offset.split('+')
                    if '/' in offset:
                        symbol_offset, symbol_size = offset.split('/')

                        # Try converting hex values to integers
                        try:
                            record['symbol_offset'] = int(symbol_offset, 16)
                        except ValueError:
                            record['symbol_offset'] = 0
                        try:
                            record['symbol_size'] = int(symbol_size, 16)
                        except ValueError:
                            record['symbol_size'] = 0

                    record['function'] = function
                else:
                    record['function'] = function_with_offset

                # Split file path from line number
                if ':' in file_with_line:
                    file_path, line_number = file_with_line.split(':')
                    record['file_path'] = file_path
                    try:
                        record['line_number'] = int(line_number)
                    except ValueError:
                        record['line_number'] = 0
                else:
                    logger.warning("No colon in file path and line number segment")

            else:
                logger.warning("Not enough information after 'at' keyword: %s", words)
        if ' in ' in trace:
            parts_after_at = trace.split(' in ', 1)[-1].strip()
            words = parts_after_at.split()

            # Ensure there are at least two words following 'at' for further processing
            if len(words) >= 2:
                function_with_offset, file_with_line = words[-2], words[-1]
                file_with_line = file_with_line.lstrip('(').rstrip(')')

                # Split function from offset and then offset into symbol offset and size
                if '+' in function_with_offset and '/' in function_with_offset:
                    function, offset = function_with_offset.split('+')
                    if '/' in offset:
                        symbol_offset, symbol_size = offset.split('/')

                        # Try converting hex values to integers
                        try:
                            record['symbol_offset'] = int(symbol_offset, 16)
                        except ValueError:
                            record['symbol_offset'] = 0
                        try:
                            record['symbol_size'] = int(symbol_size, 16)
                        except ValueError:
                            record['symbol_size'] = 0

                    record['function'] = function
                else:
                    record['function'] = function_with_offset

                # Split file path from line number
                if ':' in file_with_line:
                    file_path, line_number = file_with_line.split(':')
                    record['file_path'] = file_path
                    try:
                        record['line_number'] = int(line_number)
                    except ValueError:
                        record['line_number'] = 0
                else:
                    logger.warning("No colon in file path and line number segment")

            else:
                logger.warning("Not enough information after 'at' keyword: %s", words)

        elif 'KASAN' in trace:
            # \nBUG: KASAN: slab-out-of-bounds in tipc_crypto_msg_rcv (net/tipc/crypto.c:2314\
            filtered_trace = re.sub(error_pattern_strip_out_kasan, r'', trace)
            words = filtered_trace.split()
            words = list(filter(lambda x: 'inline' not in x, words))

            # Ensure there are at least two words following 'at' for further processing
            if len(words) >= 2:
                function_with_offset, file_with_line = words[-3], words[-1].strip('(').strip(')')  # WHY? ASK HONGWEI

                # Split function from offset and then offset into symbol offset and size
                if '+' in function_with_offset and '/' in function_with_offset:
                    function, offset = function_with_offset.split('+')
                    if '/' in offset:
                        symbol_offset, symbol_size = offset.split('/')

                        # Try converting hex values to integers
                        try:
                            record['symbol_offset'] = int(symbol_offset, 16)
                        except ValueError:
                            record['symbol_offset'] = 0
                        try:
                            record['symbol_size'] = int(symbol_size, 16)
                        except ValueError:
                            record['symbol_size'] = 0

                    record['function'] = function
                else:
                    record['function'] = function_with_offset

                # Split file path from line number
                if ':' in file_with_line:
                    file_path, line_number = file_with_line.split(':')
                    file_path = file_path.strip('(')
                    line_number = line_number.strip(')')
                    record['file_path'] = file_path
                    record['line_number'] = int(line_number)
                else:
                    logger.warning("No colon in file path and line number segment")

            else:
                logger.warning("Not enough information after 'at' keyword: %s", words)
        elif "RIP" in trace:
            try:
                # RIP: 0010:__kmem_cache_alloc_node (mm/slab.h:771 mm/slub.c:3452 mm/slub.c:3491)
                _temp = trace.split('RIP:')[1]
                function_with_offset = _temp.split(':')[1].split()[0].stip()
                file_with_line = _temp.split()[-1].strip('(').strip(')')
                words = [function_with_offset, file_with_line]

                # Ensure there are at least two words following 'at' for further processing
                if len(words) >= 2:
                    function_with_offset, file_with_line = words  # WHY? ASK HONGWEI

                    # Split function from offset and then offset into symbol offset and size
                    if '+' in function_with_offset and '/' in function_with_offset:
                        function, offset = function_with_offset.split('+')
                        if '/' in offset:
                            symbol_offset, symbol_size = offset.split('/')

                            # Try converting hex values to integers
                            try:
                                record['symbol_offset'] = int(symbol_offset, 16)
                            except ValueError:
                                record['symbol_offset'] = 0
                            try:
                                record['symbol_size'] = int(symbol_size, 16)
                            except ValueError:
                                record['symbol_size'] = 0

                        record['function'] = function
                    else:
                        record['function'] = function_with_offset

                    # Split file path from line number
                    if ':' in file_with_line:
                        file_path, line_number = file_with_line.split(':')
                        file_path = file_path.strip('(')
                        line_number = line_number.strip(')')
                        record['file_path'] = file_path
                        try:
                            record['line_number'] = int(line_number)
                        except:
                            record['line_number'] = 0
                    else:
                        logger.warning("No colon in file path and line number segment")

                else:
                    logger.warning("Not enough information after 'at' keyword: %s", words)

                pass
            except:
                print("🤡+🤡=RIP")
        else:
            logger.warning("Missing 'at' keyword in trace")

        # Append the record regardless of missing parts to include None values
        parsed_traces.append(record)

    return parsed_traces


def kasan_report_parser(report):
    # Regex patterns to extract information
    report = re.sub('\s*\(discriminator [0-9a-zA-Z]+\)', '', report)
    FLAGS = ["RIP", "RSP", "RAX", 'RDX", "RBP", "R10", "R13', "Code", "<TASK>", "</TASK>", "<IRQ>", "</IRQ>", ""]
    error_pattern = re.compile(re.compile(
        r'^(?=.*(?:KASAN:|WARNING:|BUG:|INFO:|ERROR:|PANIC:|ASSERT:|FATAL:|CRITICAL:|RIP:)).*$',
        re.MULTILINE
    ))
    error_pattern_strip_out = re.compile(
        r"^(WARNING:|BUG:|INFO:|ERROR:|PANIC:|ASSERT:|FATAL:|CRITICAL:)\sCPU:\s\d+\sPID:\s\d+\s(.*)$",
        re.MULTILINE)
    error_pattern_kasan = re.compile(re.compile(
        r'^.*KASAN:.*',
        re.MULTILINE
    ))
    error_pattern_strip_out_kasan = re.compile('^(BUG:|INFO:|ERROR:|PANIC:|ASSERT:|FATAL:|CRITICAL:)\s*KASAN:\s*',
                                               re.MULTILINE)
    # TODO: run on more test cases
    # call_trace_pattern = re.compile(r'^Call Trace:\n( +.*(?:\n +.*)*)', re.MULTILINE) # Tahoe Regex
    # call_trace_pattern = re.compile(r"(?<=Call Trace:\n)(.*\n)+?(?=(</IRQ>\n)|($))", re.MULTILINE) # LA last regex - i
    # call_trace_pattern = re.compile(r"Call Trace:\n(.*?)========\n", re.DOTALL) # LA last regex - ii
    # call_trace_pattern = re.compile(r"<TASK>(.*?)<TASK>", re.DOTALL)  # LA last regex - iii
    call_trace_pattern = re.compile(r"Call Trace:\n'<TASK>\n(.*?)RIP:", re.DOTALL)  # LA last regex - iv

    # KASAN specific patterns, TODO: must be updated for a better pattern
    kasan_marker_pattern = '=================================================================='

    # Parsing the report
    if 'KASAN' in report and kasan_marker_pattern in report:
        error_match = re.findall(error_pattern_kasan, report)
        error_match_filtered = [re.sub(error_pattern_strip_out_kasan, r'', match)
                                for match in error_match]
    else:
        error_match = re.findall(error_pattern, report)
        error_match_filtered = [re.sub(error_pattern_strip_out, r'\2', match)
                                for match in error_match]
    _temp = set()
    error_match_filtered_final = []
    for item in zip(error_match, error_match_filtered):
        if item[1] not in _temp:
            _temp.add(item[1])
            error_match_filtered_final.append(item[0])

    # call_trace_match = re.findall(call_trace_pattern, report)
    if '</TASK>' in report:
        call_trace_match = report.split('Call Trace:\n')[-1].split('</TASK>')[0].split('\n')  # WHY? ASK HONGWEI
    else:
        call_trace_match = report.split('Call Trace:\n')[-1].split('RIP')[0].split('\n')  # WHY? ASK HONGWEI
    call_trace_match_filtered = [
        list(filter(lambda x: x.strip() not in FLAGS, item.split("\n")))
        for item in call_trace_match
    ]

    return {
        'pois': _poi_split(error_match_filtered_final),
        'call_traces': call_trace_match_filtered
    }


def kasan_call_trace_function_parser(function_call):
    record = {
        'trace_line': function_call,
        'function': None,
        'file_path': None,
        'line_number': None,
        'symbol_offset': None,
        'symbol_size': None,
        'is_inline': False
    }
    words = function_call.split()
    words = list(filter(lambda x: x != '?', words))
    record['is_inline'] = '[inline]' in words
    words = list(filter(lambda x: '[inline]' not in x, words))
    if len(words) >= 2:
        function_with_offset, file_with_line = words[0], words[-1].strip('(').strip(')')  # WHY? ASK HONGWEI
        # Split function from offset and then offset into symbol offset and size
        if '+' in function_with_offset and '/' in function_with_offset:
            function, offset = function_with_offset.split('+')
            if '/' in offset:
                symbol_offset, symbol_size = offset.split('/')
                # Try converting hex values to integers
                try:
                    record['symbol_offset'] = int(symbol_offset, 16)
                except ValueError:
                    record['symbol_offset'] = 0
                try:
                    record['symbol_size'] = int(symbol_size, 16)
                except ValueError:
                    record['symbol_size'] = 0

                record['function'] = function
        else:
            record['function'] = function_with_offset

        # Split file path from line number
        if ':' in file_with_line:
            file_path, line_number = file_with_line.split(':')
            record['file_path'] = file_path
            try:
                record['line_number'] = int(line_number.strip(')').strip('('))
            except ValueError:
                record['line_number'] = 0
        else:
            logger.warning("No colon in file path and line number segment")
    elif len(words) == 1:
        function_with_offset = words[0]
        file_with_line = ""

        # Split function from offset and then offset into symbol offset and size
        if '+' in function_with_offset and '/' in function_with_offset:
            function, offset = function_with_offset.split('+')
            if '/' in offset:
                symbol_offset, symbol_size = offset.split('/')

                # Try converting hex values to integers
                try:
                    record['symbol_offset'] = int(symbol_offset, 16)
                except ValueError:
                    record['symbol_offset'] = 0
                try:
                    record['symbol_size'] = int(symbol_size, 16)
                except ValueError:
                    record['symbol_size'] = 0

                record['function'] = function
        else:
            record['function'] = function_with_offset

        # Split file path from line number
        if ':' in file_with_line:
            file_path, line_number = file_with_line.split(':')
            record['file_path'] = file_path
            try:
                record['line_number'] = int(line_number)
            except ValueError:
                record['line_number'] = 0
        else:
            logger.warning("No colon in file path and line number segment")
    return record


######################################################################################################################
#######                                              AFL                                                      ########
######################################################################################################################

def asan_report_parser(report):
    harness_binary_pattern = report['cp_harness_binary_path']
    harness_source_pattern = report['cp_harness_source_path']
    stack_trace = report['stack_traces']['main']
    _poi = []
    _call_trace = []
    for trace in stack_trace:
        _poi.append(trace)
        # if trace['type'] == 'binary':
        #     if trace['binary'] not in harness_binary_pattern:

        # if trace['type'] == 'source':
        #     if trace['src_file'] not in harness_source_pattern:
        #         _poi.append(trace)
    for trace in stack_trace:
        _call_trace.append(trace)
        # if trace['type'] == 'binary':
        #     if harness_binary_pattern not in trace['binary']:
        #         _call_trace.append(trace)
        # if trace['type'] == 'source':
        #     if harness_source_pattern not in trace['src_file']:
        #         _call_trace.append(trace)

    return {
        'poi': _poi,
        'call_trace': _call_trace
    }


######################################################################################################################
#######                                              JAZZER                                                   ########
######################################################################################################################

def jazzer_report_parser(report):
    cp_harness_name = report.get('cp_harness_name')  # Done
    harness_info_id = report.get('harness_info_id')  # Done
    consistent_sanitizers = report.get('consistent_sanitizers')  # Done
    _triggered_sanitizers = report.get('triggered_sanitizers')  # Done
    parsed_backtraces = []
    pois = []
    reports = report.get('run_pov_result').get('pov').get('jazzer').get('reports')
    for _report in reports:
        pois.append({
            'error_line': _report.get('error_line'),
            'report': _report.get('report'),
        })
    for _report in reports:
        if any(cs in _report.get('triggered_sanitizers') for cs in consistent_sanitizers):
            parsed_backtraces.append(_report.get('stack_trace'))
            break

    return {
        'cp_harness_name': cp_harness_name,
        'harness_info_id': harness_info_id,
        'consistent_sanitizers': consistent_sanitizers,
        'pois': pois,
        'parsed_backtraces': parsed_backtraces
    }


def jazzer_extract_components(log_string, src_paths, harnesses_path, indexDF):
    log_lines = log_string.split('\n')
    harness_names = {os.path.basename(harness) for harness in harnesses_path}
    for log_line in log_lines:
        if any(src_path in log_line for src_path in src_paths):
            if not any(harness_name in log_line for harness_name in harness_names):
                filename_match = re.search(r'\(([^:]+):\d+\)', log_line)
                if filename_match:
                    filename = filename_match.group(1)
                    pkg_path = log_line.split('(')[0].split()[-1]
                    function_name = pkg_path.split('.')[-1]
                    pkg = '.'.join(pkg_path.split('.')[:-1])
                    filtered_df = indexDF.loc[
                        (indexDF.filename == filename) &
                        (indexDF.func_name == function_name) &
                        (indexDF.function_signature.str.contains(pkg))
                        ]
                    if filtered_df.shape[0] == 1:
                        _temp = filtered_df.iloc[0].to_dict()
                        line = int(log_line.split(':')[-1].split(')')[0])
                        _temp['line_number'] = line
                        line_map = literal_eval(_temp['line_map'])
                        try:
                            crash_line = list(filter(lambda x: x[0] == line, line_map))[0][1]
                        except IndexError:
                            print(f"Error: {line} not found in {line_map}")
                            crash_line = "Error"
                        _temp['line_text'] = crash_line
                        yield _temp
