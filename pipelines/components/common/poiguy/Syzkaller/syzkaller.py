import logging
import time

import jsonschema
import pandas as pd
import yaml

from poiguy_utils import kasan_report_parser, search, kasan_call_trace_function_parser, compile_json_with_schema, \
    Scanner, \
    DetectionStrategy

#######################################
#              Syzkaller              #
#######################################

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def dump_syzkaller_poi(target_id, crash_report, crash_report_id, clang_index_csv, poi_reports_dir,
                       include_external_pois=True, include_external_callstacks=True):
    logging.info("Starting dump_syzkaller_poi function")

    logging.info("Loaded CSV data into DataFrame")
    FLAG = False
    logging.info(f"Reading index CSV file from {clang_index_csv}")
    try:
        data_frame = pd.read_csv(clang_index_csv)
    except Exception as e:
        logging.error(f"Error reading index CSV file: {e}")
        FLAG = True
        data_frame = pd.DataFrame(
            columns=['func_name', 'function_signature', 'filename', 'filepath', 'start_line', 'end_line',
                     'start_column', 'end_column', 'start_offset', 'end_offset', 'line_map'])

    # Read the crash report file
    with open(crash_report, 'r', encoding='utf-8', errors='replace') as file:
        kasan_report_content = yaml.safe_load(file)
    logging.info("Read crash report file")

    out_object = {
        'detection_strategy': DetectionStrategy.FUZZING.value,
        'scanner': Scanner.SYZKALLER.value,
        'target_id': str(target_id),
        'fuzzer': kasan_report_content.get('fuzzer'),
        "cp_harness_id": kasan_report_content.get('cp_harness_id'),
        'cp_harness_name': kasan_report_content.get('cp_harness_name'),
        'cp_harness_binary_path': kasan_report_content.get('cp_harness_binary_path'),
        'cp_harness_source_path': kasan_report_content.get('cp_harness_source_path'),
        'harness_info_id': kasan_report_content.get('harness_info_id'),
        'consistent_sanitizers': kasan_report_content.get('consistent_sanitizers'),
        'inconsistent_sanitizers': kasan_report_content.get('inconsistent_sanitizers'),
        'sanitizer_history': kasan_report_content.get('sanitizer_history'),
        'harness_id': kasan_report_content.get('cp_harness_id'),
        'crash_report_id': kasan_report_content.get('crash_report_id'),
        'crash_reason': kasan_report_content.get('crash_type', ''),
    }

    # Parse the KASAN report
    parsed_report = kasan_report_parser(
        kasan_report_content.get('run_pov_result').get('pov').get('kasan').get('reports')[0].get('report'))
    logging.info("Parsed KASAN report")

    # pprint(parsed_report)  # Debugging TODO: Remove
    # assert False # Debugging TODO: Remove

    points_of_interest = parsed_report['pois']
    call_traces = parsed_report['call_traces']

    processed_pois = []
    for poi in points_of_interest:
        file_path = poi.get('file_path', '')
        filename = file_path.split('/')[-1] if file_path else ''
        function_name = poi.get('function', '')
        line_number = poi.get('line_number', 0)
        reason = poi.get('poi', '')
        symbol_offset = poi.get('symbol_offset', 0)
        symbol_size = poi.get('symbol_size', 0)


        search_result = search(data_frame=data_frame,
                               func_name=function_name,
                               filename=filename,
                               filepath=file_path,
                               clash_line_number=line_number)

        function_signature = search_result.get('function_signature', '')
        key_index = search_result.get('key', '')
        crash_line_text = search_result.get('crash_line', '')

        processed_pois.append({
            "reason": reason,
            "source_location": {
                "relative_file_path": search_result.get('filepath') if search_result.get('filepath') else file_path,
                "function_signature": function_signature if function_signature else function_name,
                "line_text": crash_line_text if crash_line_text else None,  # TODO: Check this
                "line_number": line_number if line_number else 0,
                "symbol_offset": symbol_offset if symbol_offset else 0,
                "symbol_size": symbol_size if symbol_size else 0,
                "key_index": key_index if key_index else None
            }
        })
    logging.info("Processed points of interest")

    # pprint(processed_pois)  # Debugging TODO: Remove
    # assert False  # Debugging TODO: Remove

    processed_call_traces = []

    for trace in call_traces:
        call_trace_obj = dict()
        call_trace_obj['reason'] = "bla bla bla"  # Todo: Extract reason from the call trace
        call_locations = []
        for trace_function in list(filter(lambda x: x != '', trace)):
            parsed_function = kasan_call_trace_function_parser(function_call=trace_function)
            trace_line = parsed_function.get('trace_line', '')
            file_path = (parsed_function.get('file_path', '') or '').strip()
            filename = file_path.split('/')[-1].strip() if file_path else ''
            function_name = (parsed_function.get('function', '') or '').strip()
            line_number = parsed_function.get('line_number', 0)
            symbol_offset = parsed_function.get('symbol_offset', 0)
            symbol_size = parsed_function.get('symbol_size', 0)
            print('------------------NEW------------------')
            print("Trace Function: ", trace_function)
            print("Parsed Function: ", parsed_function)

            search_result = search(data_frame=data_frame,
                                   func_name=function_name,
                                   filename=filename,
                                   filepath=file_path,
                                   clash_line_number=line_number)
            function_signature = search_result.get('function_signature', function_signature)
            key_index = search_result.get('key', None)
            crash_line_text = search_result.get('crash_line', None)

            call_locations.append({
                'trace_line': trace_line.strip() if trace_line.strip() else None,
                "relative_file_path": search_result.get('filepath') if search_result.get('filepath') else file_path,
                "function": function_signature if function_signature else function_name,
                "line_text": crash_line_text if crash_line_text else None,
                "line_number": line_number if line_number else 0,
                "symbol_offset": symbol_offset if symbol_offset else 0,
                "symbol_size": symbol_size if symbol_size else 0,
                "key_index": key_index if key_index else None
            })
            processed_pois.append({
                "reason": "stacktrace",
                "source_location": {
                    "relative_file_path": search_result.get('filepath') if search_result.get('filepath') else file_path,
                    "function_signature": function_signature if function_signature else function_name,
                    "line_text": crash_line_text if crash_line_text else None,  # TODO: Check this
                    "line_number": line_number if line_number else 0,
                    "symbol_offset": symbol_offset if symbol_offset else 0,
                    "symbol_size": symbol_size if symbol_size else 0,
                    "key_index": key_index if key_index else None
                }
            })
        call_trace_obj['call_locations'] = call_locations
        processed_call_traces.append(call_trace_obj)
    logging.info("Processed call traces")

    signal, poi = compile_json_with_schema(**out_object,
                                           pois=processed_pois,
                                           stack_traces=processed_call_traces,
                                           additional_information={})
    logging.info("Compiled JSON with schema")

    with open(f'{poi_reports_dir}/poi-report-syzkaller-{target_id}-{crash_report_id}-{time.time()}.yaml',
              'w') as poi_file:
        yaml.safe_dump(poi, poi_file)
    logging.info("Dumped POI to YAML file")
    if signal:
        raise jsonschema.exceptions.ValidationError('JSON data is invalid')
    if FLAG:
        raise Exception('Error in reading clang index CSV file')
