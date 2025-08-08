import json
from pathlib import Path
import sys
from shellphish_crs_utils.models import SanitizerEnum
from shellphish_crs_utils.models.oss_fuzz import LanguageEnum
from shellphish_crs_utils.sanitizer_parsers import parse_run_output
import yaml

def run_regression_test(meta, stdout_bytes, stderr_bytes):
    language = LanguageEnum(meta["language"])
    result = parse_run_output(
        project_language=language,
        sanitizer=SanitizerEnum(meta['sanitizer']),
        exit_code=meta['exit_code'],
        stdout=stdout_bytes,
        stderr=stderr_bytes,
        target_source_root=Path(meta['focus_repo_path']),
    )
    print(yaml.safe_dump(json.loads(result.model_dump_json()), sort_keys=False))
    if language == LanguageEnum.jvm:
        # should always have one stack trace
        assert len(result.crash_report.stack_traces) == 1

    if expected := meta.get('expected_parser', None):
        assert result.parser == expected, f"Expected {result.parser!r} to match {expected!r}"
    if expected := meta.get('expected_summary', None):
        assert result.crash_report.summary == expected, f"{regression_test}: Expected {result.crash_report.summary!r} to match {expected!r}"
    if expected := meta.get('expected_sanitizer', None):
        assert result.crash_report.sanitizer == expected, f"{regression_test}: Expected {result.crash_report.sanitizer!r} to match {expected!r}"
    if expected := meta.get('expected_crash_type', None):
        assert result.crash_report.crash_type == expected, f"{regression_test}: Expected {result.crash_report.crash_type!r} to match {expected!r}"
    if expected := meta.get('expected_organizer_significance', None):
        assert result.organizer_crash_eval.significance.value == expected, f"{regression_test}: Expected {result.organizer_crash_eval.significance.value!r} to match {expected!r}"
    if expected := meta.get('expected_organizer_crash_description', None):
        assert result.organizer_crash_eval.code_label == expected, f"{regression_test}: Expected {result.organizer_crash_eval.code_label!r} to match {expected!r}"

    if 'expected_stack_trace_file_names' in meta:
        # check that the stack trace file names match
        for stack_trace_name, stack_trace in result.crash_report.stack_traces.items():
            file_names = [
                dict(source=str(ent.source_location.file_name)) if ent.source_location else (dict(binary=str(ent.binary_location.file_name)) if ent.binary_location else None)
                for ent in stack_trace.call_locations
                if ent.source_location or ent.binary_location
            ]
            assert len(file_names) == len(meta['expected_stack_trace_file_names'].get(stack_trace_name, [])), f"{regression_test}: Expected {len(file_names)} to match {len(meta['expected_stack_trace_file_names'].get(stack_trace_name, []))} for {stack_trace_name}"
            for i, (file_name, expected_file_name) in enumerate(zip(file_names, meta['expected_stack_trace_file_names'][stack_trace_name])):
                assert file_name == expected_file_name, f"{regression_test}: Expected {file_name!r} to match {expected_file_name!r} at index {i}"
            assert file_names == meta['expected_stack_trace_file_names'][stack_trace_name], f"{regression_test}: Expected {file_names!r} to match {meta['expected_stack_trace_file_names']!r}"

    if 'expected_stack_trace_function_names' in meta:
        expected_names = meta['expected_stack_trace_function_names']
        # check that the stack trace function names match
        for stack_trace_name, stack_trace in result.crash_report.stack_traces.items():
            assert len(stack_trace.call_locations) == len(expected_names[stack_trace_name]), f"{regression_test}: Expected {len(stack_trace.call_locations)} to match {len(expected_names[stack_trace_name])} for {stack_trace_name}"
            expected_func_names = expected_names[stack_trace_name]
            for i, ent in enumerate(stack_trace.call_locations):
                if 'source' in expected_func_names[i]:
                    assert ent.source_location, f"{regression_test}: Expected source location for {stack_trace_name} at index {i}"
                    assert ent.source_location.function_name == expected_func_names[i]['source'], f"{regression_test}: Expected {ent.source_location.function_name!r} to match {expected_func_names[i]['source']!r} at index {i}"
                
                if 'binary' in expected_func_names[i]:
                    assert ent.binary_location, f"{regression_test}: Expected binary location for {stack_trace_name} at index {i}"
                    assert ent.binary_location.function_name == expected_func_names[i]['binary'], f"{regression_test}: Expected {ent.binary_location.function_name!r} to match {expected_func_names[i]['binary']!r} at index {i}"


    if 'expected_stack_trace_function_signatures' in meta:
        expected_names = meta['expected_stack_trace_function_signatures']
        # check that the stack trace function names match
        for stack_trace_name, stack_trace in result.crash_report.stack_traces.items():
            assert len(stack_trace.call_locations) == len(expected_names[stack_trace_name]), f"{regression_test}: Expected {len(stack_trace.call_locations)} to match {len(expected_names[stack_trace_name])} for {stack_trace_name}"
            expected_func_names = expected_names[stack_trace_name]
            for i, ent in enumerate(stack_trace.call_locations):
                if 'source' in expected_func_names[i]:
                    assert ent.source_location, f"{regression_test}: Expected source location for {stack_trace_name} at index {i}"
                    assert ent.source_location.raw_signature == expected_func_names[i]['source'], f"{regression_test}: Expected {ent.source_location.function_name!r} to match {expected_func_names[i]['source']!r} at index {i}"
                
                if 'binary' in expected_func_names[i]:
                    assert ent.binary_location, f"{regression_test}: Expected binary location for {stack_trace_name} at index {i}"
                    assert ent.binary_location.raw_signature == expected_func_names[i]['binary'], f"{regression_test}: Expected {ent.binary_location.function_name!r} to match {expected_func_names[i]['binary']!r} at index {i}"


regressions_dir = Path(__file__).parent / "regressions"
regressions = [Path(v) for v in sys.argv[1:]] if len(sys.argv) > 1 else regressions_dir.glob("*.yaml")
for regression_test in regressions:
    # find the stdout and stderr files if they exist
    stdout_bytes = b''
    stderr_bytes = b''
    id = regression_test.stem
    meta = yaml.safe_load(regression_test.read_text())
    if (regressions_dir / f"{id}.stdout").exists():
        stdout_bytes = (regressions_dir / f"{id}.stdout").read_bytes()
    if (regressions_dir / f"{id}.stderr").exists():
        stderr_bytes = (regressions_dir / f"{id}.stderr").read_bytes()

    try:
        run_regression_test(meta, stdout_bytes, stderr_bytes)
    except Exception as e:
        print(f"stdout: {stdout_bytes.decode(errors='replace')}")
        print(f"stderr: {stderr_bytes.decode(errors='replace')}")
        print(f"Regression test {regression_test} failed: {e}")
        raise
