# taken from https://github.com/shellphish-support-syndicate/poiguy/blob/main/poiguy_utils/pareser.py

import re
import logging as logger


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

        # Only proceed if 'at' is present in the trace string
        if 'at' in trace:
            parts_after_at = trace.split('at', 1)[-1].strip()
            words = parts_after_at.split()

            # Ensure there are at least two words following 'at' for further processing
            if len(words) >= 2:
                function_with_offset, file_with_line = words[-2], words[-1]

                # Split function from offset and then offset into symbol offset and size
                if '+' in function_with_offset and '/' in function_with_offset:
                    function, offset = function_with_offset.split('+')
                    if '/' in offset:
                        symbol_offset, symbol_size = offset.split('/')

                        # Try converting hex values to integers
                        try:
                            record['symbol_offset'] = int(symbol_offset, 16)
                            record['symbol_size'] = int(symbol_size, 16)
                        except ValueError:
                            logger.error("Invalid hex value: %s", offset)

                    record['function'] = function
                else:
                    record['function'] = function_with_offset

                # Split file path from line number
                if ':' in file_with_line:
                    file_path, line_number = file_with_line.split(':')
                    record['file_path'] = file_path
                    record['line_number'] = int(line_number)
                else:
                    logger.warning("No colon in file path and line number segment")

            else:
                logger.warning("Not enough information after 'at' keyword: %s", words)
        elif 'KASAN' in trace:
            filtered_trace = re.sub(error_pattern_strip_out_kasan, r'', trace)
            words = filtered_trace.split()
            words = list(filter(lambda x: 'inline' not in x, words))

            # Ensure there are at least two words following 'at' for further processing
            if len(words) >= 2:
                function_with_offset, file_with_line = words[-2], words[-1]

                # Split function from offset and then offset into symbol offset and size
                if '+' in function_with_offset and '/' in function_with_offset:
                    function, offset = function_with_offset.split('+')
                    if '/' in offset:
                        symbol_offset, symbol_size = offset.split('/')

                        # Try converting hex values to integers
                        try:
                            record['symbol_offset'] = int(symbol_offset, 16)
                            record['symbol_size'] = int(symbol_size, 16)
                        except ValueError:
                            logger.error("Invalid hex value: %s", offset)

                    record['function'] = function
                else:
                    record['function'] = function_with_offset

                # Split file path from line number
                if ':' in file_with_line:
                    file_path, line_number = file_with_line.split(':')
                    record['file_path'] = file_path
                    record['line_number'] = int(line_number)
                else:
                    logger.warning("No colon in file path and line number segment")

            else:
                logger.warning("Not enough information after 'at' keyword: %s", words)

        else:
            logger.warning("Missing 'at' keyword in trace")

        # Append the record regardless of missing parts to include None values
        parsed_traces.append(record)

    return parsed_traces

def kasan_report_parser(report):
    # Regex patterns to extract information
    FLAGS = ["RIP", "RSP", "RAX", 'RDX", "RBP", "R10", "R13', "Code", "<TASK>", "</TASK>", "<IRQ>", "</IRQ>"]
    error_pattern = re.compile(re.compile(
        r'^(?=.*(?:KASAN:|WARNING:|BUG:|INFO:|ERROR:|PANIC:|ASSERT:|FATAL:|CRITICAL:)).*$',
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
    call_trace_pattern = re.compile(r'^Call [a-zA-Z]race:\n( +.*(?:\n +.*)*)', re.MULTILINE)

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

    call_trace_match = re.findall(call_trace_pattern, report)
    call_trace_match_filtered = [
        list(filter(lambda x: x.strip() not in FLAGS, item.split("\n")))
        for item in call_trace_match
    ]

    return {
        'pois': _poi_split(error_match_filtered_final),
        'call_traces': call_trace_match_filtered
    }
