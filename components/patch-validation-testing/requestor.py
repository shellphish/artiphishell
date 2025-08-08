import argparse
from pathlib import Path
import time
from typing import List

from shellphish_crs_utils.models import CrashingCommitReport, PatchVerificationRequest, RepresentativeCrashingInputMetadata
import yaml

def ready_files(dir: Path):
    assert isinstance(dir, Path), f'{dir} is not a Path, {type(dir)}'
    for file in dir.iterdir():
        assert file.is_file(), f'{file} is not a file'
        mtime = file.stat().st_mtime
        # if the file was modified in the last 30 seconds, ignore it
        if time.time() - mtime < 30:
            continue
        yield file

def filter_cokeyed(*args):
    key, arg0 = args[0]
    present_in_all = set([key(v) for v in arg0])
    for new_key, arg in args[1:]:
        present_in_all &= set([new_key(v) for v in arg])
    return [[v for v in arg if cur_key(v) in present_in_all] for cur_key, arg in args]

def load_meta(file: Path):
    assert isinstance(file, Path), f'{file} is not a Path, {type(file)}'
    assert file.is_file(), f'{file} is not a file'

    with file.open() as f:
        return yaml.safe_load(f)
    
def load_crashing_commit_report(file: Path):
    return CrashingCommitReport.model_validate(load_meta(file))

def load_representative_crashing_input_metadata(file: Path):
    return RepresentativeCrashingInputMetadata.model_validate(load_meta(file))
    
def ready_crashing_commit_reports(args):
    for file in ready_files(args.crashing_commit_reports):
        meta = load_meta(file)
        if meta['crashing_commit'] == args.crashing_commit_sha:
            yield meta
            
def step(args):
    patch_metadata = load_meta(args.patch_metadata)
    print(f'Loaded patch metadata: {patch_metadata}')

    ready_crashing_commit_reports = list(ready_files(args.crashing_commit_reports))
    print(f'Found {len(ready_crashing_commit_reports)} ready crashing commit reports')
    if len(ready_crashing_commit_reports) == 0:
        return
    
    ready_crashing_commit_reports = [
        (file, load_crashing_commit_report(file)) for file in ready_crashing_commit_reports
    ]
    print(f'Loaded {len(ready_crashing_commit_reports)} crashing commit reports (total)')
    for file, report in ready_crashing_commit_reports:
        print(f'{file.name}: {type(report.crashing_commit)} {report.crashing_commit} {type(args.crashing_commit_sha)} {args.crashing_commit_sha} {report.crashing_commit == args.crashing_commit_sha} {report.crashing_commit == args.crashing_commit_sha}')
    ready_crashing_commit_reports = [
        (file, report) for (file, report) in ready_crashing_commit_reports if report.crashing_commit == args.crashing_commit_sha
    ]
    print(f'Found {len(ready_crashing_commit_reports)} crashing commit reports for {args.crashing_commit_sha}')

    commit_report_ids = [report.crash_report_id for _, report in ready_crashing_commit_reports]
    print(f'Crashing commit report IDs: {commit_report_ids}')
    ready_representative_crashing_inputs_metadata = list(ready_files(args.crashing_representative_inputs_metadata))
    print(f'Found {len(ready_representative_crashing_inputs_metadata)} ready representative crashing inputs metadata')
    ready_representative_crashing_inputs_metadata = [
        (file, load_representative_crashing_input_metadata(file)) for file in ready_representative_crashing_inputs_metadata
    ]
    print(f'Loaded {len(ready_representative_crashing_inputs_metadata)} representative crashing inputs metadata (total)')
    
    for file, meta in ready_representative_crashing_inputs_metadata:
        print(f'\t{file.name} in {commit_report_ids}')
        print(f'\t and {meta.harness_info_id} == {patch_metadata["pdt_harness_info_id"]}')
        print(f'\t and {args.sanitizer_id} in {meta.consistent_sanitizers}')
    ready_representative_crashing_inputs_metadata = [
        (file, meta) for (file, meta) in ready_representative_crashing_inputs_metadata 
            if (
                file.name in commit_report_ids and \
                meta.harness_info_id == patch_metadata['pdt_harness_info_id'] and \
                args.sanitizer_id in meta.consistent_sanitizers
            )
    ]
    print(f'Found {len(ready_representative_crashing_inputs_metadata)} representative crashing inputs metadata for {args.crashing_commit_sha} and {args.sanitizer_id}')

    for file, meta in ready_representative_crashing_inputs_metadata:
        request = PatchVerificationRequest(
            project_id=meta.project_id,
            harness_id=meta.harness_info_id,
            patch_id=args.patch_id,
            crashing_commit_sha=str(args.crashing_commit_sha).lower(),
            crashing_commit_report_id=file.name,
            crash_report_representative_crashing_input_id=file.name,
            sanitizer_id=args.sanitizer_id,
        )
        with (args.output_verification_requests / f'{args.patch_id}_{file.name}').open('w') as f:
            yaml.safe_dump(request.model_dump(), f)

def main(args):
    while True:
        print('Running step...')
        step(args)
        print('Sleeping for 20 seconds...')
        time.sleep(20)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Patch Verification Requester')
    parser.add_argument('--patch-id', type=str, required=True, help='Patch ID')
    parser.add_argument('--sanitizer-id', type=str, required=True, help='Sanitizer ID')
    parser.add_argument('--crashing-commit-sha', type=lambda s: s.upper(), required=True, help='Crashing Commit SHA')
    parser.add_argument('--patch-metadata', type=Path, required=True, help='Patch Metadata')
    parser.add_argument('--crashing-commit-reports', type=Path, required=True, help='Path to crashing commit reports')
    parser.add_argument('--crashing-representative-inputs-metadata', type=Path, required=True, help='Path to crashing representative inputs')
    parser.add_argument('--output-verification-requests', type=Path, required=True, help='Output Verification Requests')

    args = parser.parse_args()
    print(args)
    main(args)