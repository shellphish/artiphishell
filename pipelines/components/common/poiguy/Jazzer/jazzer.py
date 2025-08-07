import logging
from ast import literal_eval

import jsonschema
import pandas as pd
import yaml

from poiguy_utils import jazzer_report_parser, jazzer_extract_components, DetectionStrategy, Scanner, \
    compile_json_with_schema


#######################################
#               Jazzer               #
#######################################

def dump_jazzer_poi(target_id, jazzer_crash_report, crash_report_id, antler4_index_csv,
                    poi_reports_dir, harness_id, target_metadata=None):
    if target_metadata:
        with open(target_metadata, 'r') as metadata_file:
            target_metadata = yaml.safe_load(metadata_file)
        harnesses_path = [target_metadata.get('harnesses')[i]['source'] for i in target_metadata.get('harnesses')]

    logging.info("Starting POI dump process")

    # Read the index CSV file
    flag = False
    logging.info(f"Reading index CSV file from {antler4_index_csv}")
    try:
        data_frame = pd.read_csv(antler4_index_csv)
    except Exception as e:
        logging.error(f"Error reading index CSV file: {e}")
        flag = True
        data_frame = pd.DataFrame(
            columns=['func_name', 'function_signature', 'filename', 'filepath', 'start_line', 'end_line',
                     'start_column', 'end_column', 'start_offset', 'end_offset', 'line_map'])

    # Load the Jazzer crash report
    logging.info(f"Loading Jazzer crash report from {jazzer_crash_report}")
    with open(jazzer_crash_report, 'r') as crash_report_file:
        jazzer_report_data = yaml.safe_load(crash_report_file)

    # Parse the Jazzer report
    logging.info("Parsing Jazzer report")
    parsed_report = jazzer_report_parser(jazzer_report_data)

    out_object = {
        'detection_strategy': DetectionStrategy.FUZZING.value,
        'scanner': Scanner.JAZZER.value,
        'target_id': str(target_id),
        'fuzzer': jazzer_report_data.get('fuzzer'),
        'cp_harness_id': jazzer_report_data.get('cp_harness_id'),
        'cp_harness_name': jazzer_report_data.get('cp_harness_name'),
        'cp_harness_binary_path': jazzer_report_data.get('cp_harness_binary_path'),
        'cp_harness_source_path': jazzer_report_data.get('cp_harness_source_path'),
        'harness_info_id': jazzer_report_data.get('harness_info_id'),
        'consistent_sanitizers': jazzer_report_data.get('consistent_sanitizers'),
        'inconsistent_sanitizers': jazzer_report_data.get('inconsistent_sanitizers'),
        'sanitizer_history': jazzer_report_data.get('sanitizer_history'),
        'harness_id': jazzer_report_data.get('cp_harness_id'),
        'crash_report_id': jazzer_report_data.get('crash_report_id'),
        'crash_reason': "Jazzer",
    }
    pois = parsed_report.get('pois')
    parsed_backtrace = parsed_report.get('parsed_backtraces')

    poi_array = []
    for poi in pois:
        logging.info(f"Processing POI: {poi}")
        components = list(filter(lambda x: x != None, jazzer_extract_components(poi.get('report'), list(
            target_metadata.get('cp_sources').keys()), harnesses_path, data_frame)))
        for _data in components:
            poi_array.append({
                "reason": poi.get('error_line'),
                "source_location": {
                    "relative_file_path": _data['filepath'] if _data['filepath'] else None,
                    "function_signature": _data['function_signature'].split('::')[-1],
                    "function_name": '.'.join(
                        _data['function_signature'].split('::')[-1].split()[0].split('.')[:-1]) + ':' + _data[
                                         'func_name'],
                    "line_text": _data['line_text'],
                    "line_number": _data['line_number'],
                    "symbol_offset": 0,
                    "symbol_size": 0,
                    "key_index": _data['function_signature']
                }
            })

    logging.info("Finished processing POIs")

    processed_call_traces = []
    call_trace_obj = {"reason": "triggered sanitizer match", "call_locations": []}
    zero_back_trace_flag = False
    try:
        for trace in parsed_backtrace[0]:
            logging.info(f"Processing call trace: {trace}")
            _class = trace.get('class')
            _function = trace.get('function')
            _file = trace.get('file')
            try:
                _line_number = int(trace.get('text').split(":")[-1].split(')')[0].strip())
            except ValueError:
                continue
            _package = trace.get('package')
            _crash_line_text = trace.get('text')

            stack_frame = data_frame.loc[
                (data_frame['func_name'] == _function) & (data_frame['filename'] == _file) & data_frame[
                    'function_signature'].str.contains(_class)]
            crash_line = None
            if not stack_frame.empty:
                line_map = literal_eval(stack_frame['line_map'].values[0] if not stack_frame['line_map'].empty else "[]")
                try:
                    crash_line = list(filter(lambda x: x[0] == _line_number, line_map))[0][1]
                except IndexError:
                    print(f"Error: {_line_number} not found in {line_map}")
                    crash_line = "Error"

            call_trace_obj['call_locations'].append({
                "relative_file_path": stack_frame['filepath'].values[0] if not stack_frame[
                    'filepath'].empty else _file,
                "function": stack_frame['function_signature'].values[0].split("::")[-1] if not stack_frame[
                    'function_signature'].empty else _function,
                "function_name": '.'.join(
                    stack_frame['function_signature'].values[0].split("::")[-1].split()[0].split('.')[:-1]) + ':' +
                                 stack_frame[
                                     'func_name'].values[0] if not stack_frame[
                    'function_signature'].empty else _function,
                "line_text": crash_line,
                "line_number": _line_number if _line_number else 0,
                "symbol_offset": 0,
                "symbol_size": 0,
                "key_index": stack_frame['function_signature'].values[0] if not stack_frame[
                    'function_signature'].empty else None,
                "trace_line": _crash_line_text if _crash_line_text else None
            })
    except IndexError:
        zero_back_trace_flag = True

    processed_call_traces.append(call_trace_obj)
    logging.info("Finished processing call traces")

    signal, poi = compile_json_with_schema(
        **out_object,
        pois=poi_array,
        stack_traces=processed_call_traces,
        additional_information={}
    )

    logging.info("Generated POI JSON with schema")

    if poi_reports_dir:
        output_file_path = f'{poi_reports_dir}/poi-report-jazzer-{target_id}-{crash_report_id}.yaml'
        logging.info(f"Writing POI to YAML file at {output_file_path}")
        with open(output_file_path, 'w+') as poi_file:
            yaml.safe_dump(poi, poi_file)
        logging.info("Dumped POI to YAML file successfully")

    if signal:
        raise jsonschema.exceptions.ValidationError('JSON data is invalid')
    if flag:
        raise Exception('Error in reading clang index CSV file')
    if zero_back_trace_flag:
        raise Exception('Error in processing backtrace, POV guy may not returned proper triggered_sanitizers and consistent_sanitizers')
