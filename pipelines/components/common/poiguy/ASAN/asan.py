import logging
import time

import jsonschema
import pandas as pd
import yaml

from poiguy_utils import search, compile_json_with_schema, Scanner, DetectionStrategy
from poiguy_utils.parser import asan_report_parser


# Setup logging


#######################################
#                asan                 #
#######################################

def dump_asn_poi(target_id, asan_crash_report, clang_index_csv, poi_reports_dir, include_external_pois=True,
                 include_external_callstacks=True):
    logging.info("Starting dump_asn_poi function")

    # import ipdb; ipdb.set_trace()

    with open(asan_crash_report, 'r') as crash_report_file:
        asan_report_data = yaml.safe_load(crash_report_file)
        logging.info("Loaded ASAN crash report")

    parsed_report = asan_report_parser(asan_report_data)
    pois = parsed_report.get('poi', [])
    call_traces = parsed_report.get('call_trace', [])

    # import ipdb; ipdb.set_trace()
    out_object = {
        'detection_strategy': DetectionStrategy.FUZZING.value,
        'scanner': Scanner.ASAN.value,
        'target_id': str(target_id),
        'fuzzer': asan_report_data.get('fuzzer'),
        "cp_harness_id": asan_report_data.get('cp_harness_id'),
        'cp_harness_name': asan_report_data.get('cp_harness_name'),
        'cp_harness_binary_path': asan_report_data.get('cp_harness_binary_path'),
        'cp_harness_source_path': asan_report_data.get('cp_harness_source_path'),
        'harness_info_id': asan_report_data.get('harness_info_id'),
        'consistent_sanitizers': asan_report_data.get('consistent_sanitizers'),
        'inconsistent_sanitizers': asan_report_data.get('inconsistent_sanitizers'),
        'sanitizer_history': asan_report_data.get('sanitizer_history'),
        'harness_id': asan_report_data.get('cp_harness_id'),
        'crash_report_id': asan_report_data.get('crash_report_id'),
        'crash_reason': asan_report_data.get('crash_type', ''),
    }

    # Load clang index CSV
    FLAG = False
    logging.info(f"Reading index CSV file from {clang_index_csv}")
    try:
        data_frame = pd.read_csv(clang_index_csv)
    except Exception as e:
        logging.error(f"Error in reading clang index CSV file: {e}")
        FLAG = True
        data_frame = pd.DataFrame(
            columns=['func_name', 'function_signature', 'filename', 'filepath', 'start_line', 'end_line',
                     'start_column', 'end_column', 'start_offset', 'end_offset', 'line_map'])
    logging.info("Loaded clang index CSV")

    processed_pois = []

    for poi in pois:
        file_path = poi.get('binary') or poi.get('src_file', '')
        filename = file_path.split('/')[-1] if file_path else ''
        function_name = poi.get('func_name', '')
        _function_signature = poi.get('signature', '')
        _function_signature = _function_signature = poi.get('signature', '')
        line_number = poi.get('line', 0)
        symbol_offset = poi.get('offset', 0)
        symbol_size = poi.get('symbol_size', 0)  # Placeholder, to be replaced

        search_result = search(data_frame=data_frame,
                               func_name=function_name,
                               filename=filename,
                               filepath=file_path,
                               clash_line_number=line_number)
        function_signature = search_result.get('function_signature', _function_signature)
        key_index = search_result.get('key', None)
        crash_line_text = search_result.get('crash_line', None)

        processed_pois.append({
            "reason": asan_report_data.get('crash_type', ''),
            "source_location": {
                "relative_file_path": search_result.get('filepath') if search_result.get('filepath') else file_path,
                "function_name": function_name,
                "function_signature": function_signature if function_signature else _function_signature,
                "line_text": crash_line_text if crash_line_text else None,
                "line_number": line_number,
                "symbol_offset": symbol_offset,
                "symbol_size": symbol_size,
                "key_index": key_index if key_index else None,
            }
        })
        logging.info(f"Processed POI: {poi}")


    processed_call_traces = []
    call_trace_obj = {"reason": "Not specified", "call_locations": []}  # Placeholder for reason

    for trace in call_traces:
        file_path = trace.get('binary') or trace.get('src_file', '')
        filename = file_path.split('/')[-1] if file_path else ''
        function_name = trace.get('func_name', '')
        _function_signature = trace.get('signature', '')
        line_number = trace.get('line', 0)  # Placeholder, to be replaced
        symbol_offset = trace.get('offset', 0)
        symbol_size = trace.get('symbol_size', 0)  # Placeholder, to be replaced

        search_result = search(data_frame=data_frame,
                               func_name=function_name,
                               filename=filename,
                               filepath=file_path,
                               clash_line_number=line_number)
        function_signature = search_result.get('function_signature', _function_signature)
        key_index = search_result.get('key', None)
        crash_line_text = search_result.get('crash_line', None)

        if include_external_callstacks or key_index:
            call_trace_obj['call_locations'].append({
                "relative_file_path": search_result.get('filepath') if search_result.get('filepath') else file_path,
                "function": function_signature if function_signature else _function_signature,
                "function_name": function_name,
                "line_text": crash_line_text if crash_line_text else None,
                "line_number": line_number,
                "symbol_offset": symbol_offset,
                "symbol_size": symbol_size,
                "trace_line": trace.get('signature', '').strip() if trace.get('signature', '').strip() else None,
                "key_index": key_index if key_index else None
            })
        logging.info(f"Processed call trace: {trace}")

    processed_call_traces.append(call_trace_obj)

    signal, poi_asan = compile_json_with_schema(
        **out_object,
        pois=processed_pois,
        stack_traces=processed_call_traces,
        additional_information={
            "asan_report_data": asan_report_data,
            "sanitizer": asan_report_data.get('sanitizer', ''),
        }
    )
    logging.info("Compiled JSON with schema")

    if poi_reports_dir:
        output_path = f'{poi_reports_dir}/poi-report-{target_id}-{time.time()}.yaml'
        with open(output_path, 'w') as poi_file:
            yaml.safe_dump(poi_asan, poi_file)
        logging.info(f"POI report saved to {output_path}")
    if signal:
        raise jsonschema.exceptions.ValidationError('JSON data is invalid')
    if FLAG:
        raise Exception('Error in reading clang index CSV file')
