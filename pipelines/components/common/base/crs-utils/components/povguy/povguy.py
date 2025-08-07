import hashlib
import shutil
import sys
from shellphish_crs_utils.models import RepresentativeCrashingInputMetadata
import yaml
import time
import argparse
import subprocess
import tempfile
import os
import stat
import shlex

from pathlib import Path
from typing import Optional


from shellphish_crs_utils.challenge_project import ChallengeProject

def find_vmlinux_with_configs(target_dir):
    target_path = Path(target_dir)
    for root, dirs, files in os.walk(target_path):
        root_path = Path(root)
        files_set = set(files)
        if 'Kconfig' in files_set and 'Kbuild' in files_set:
            if 'vmlinux' in files_set:
                vmlinux_path = root_path / 'vmlinux'
                return vmlinux_path.resolve()
    return None

def find_vmlinux(target_dir):
    vmlinux_path = find_vmlinux_with_configs(target_dir)
    if vmlinux_path:
        return vmlinux_path
    else:
        for root, dirs, files in os.walk(target_dir):
            root_path = Path(root)
            if 'vmlinux' in files:
                vmlinux_path = root_path / 'vmlinux'
                return vmlinux_path.resolve()
    return None



def decode_stacktrace(vmlinux_path, orig_kasan_content: str) -> Optional[str]:
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_input:
        temp_input.write(orig_kasan_content)
        temp_input_path = temp_input.name
    temp_output = tempfile.NamedTemporaryFile(mode='w', delete=False)
    temp_output_path = temp_output.name
    temp_output.close()
    try:
        current_file_path = os.path.abspath(__file__)
        current_dir = os.path.dirname(current_file_path)

        decode_stacktrace_sh = os.path.join(current_dir, 'kernel_scripts', 'decode_stacktrace.sh')
        decodecode = os.path.join(current_dir, 'kernel_scripts', 'decodecode')

        os.chmod(decode_stacktrace_sh, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(decodecode, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)
        stacktrace_sh = shlex.quote(decode_stacktrace_sh)
        vmlinux_path = shlex.quote(str(vmlinux_path))
        temp_input_path = shlex.quote(temp_input_path)
        temp_output_path = shlex.quote(temp_output_path)

        command = f"{stacktrace_sh} {vmlinux_path} < {temp_input_path} > {temp_output_path}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f'running decode_stacktrace.sh, stderr: {result.stderr}')
        
        if result.returncode == 0:
            path = Path(temp_output_path)
            with path.open('r') as file:
                file_content = file.read()
            return file_content
        else:
            print(f"Failed to decode stacktrace: {result.stderr}")
            return None
    except Exception as e:
        print(f"Failed to decode stacktrace with exception: {e}")
        return None
    finally:
        os.remove(temp_input_path)
        os.remove(temp_output_path)

def kasan_add_lineno(raw_report, target_dir):
    vmlinux_path = find_vmlinux(target_dir)
    if not vmlinux_path:
        return raw_report
    else:
        try:
            report_with_lineno = decode_stacktrace(vmlinux_path, raw_report)
            if report_with_lineno:
                return report_with_lineno
            else:
                print(f"Failed to decode stacktrace for {raw_report}")
                return raw_report
        except Exception as e:
            print(f"Failed to decode stacktrace for {raw_report}: {e}")
            return raw_report

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        return "File not found."


def run_pov(
        base_meta_path, output_run_pov_results_path,
        output_crash_report_path, out_representative_crash, out_representative_crash_metadata,
        target_dir, harness_name, pov_path, crash_id, expect_crashing=True, timeout=None, retry_count=5):
    
    print(f"Running pov {pov_path} with harness {harness_name}")
    with open(base_meta_path, 'r') as f:
        base_meta = yaml.safe_load(f)
        
    cp = ChallengeProject(target_dir)
    for harness in cp.harnesses:
        if harness.name == harness_name:
            break
    else:
        raise Exception(f"Could not find harness {harness_name}")

    print(f"Running pov {pov_path} with harness {harness_name}")
    print(f"Source: {harness.source}")
    print(f"Binary: {harness.binary}")
    try:
        print(f"md5: {calculate_md5(pov_path)}")
    except Exception as e:
        print(f"Error getting md5: {e}")

    try:
        env_docker_path = os.path.join(cp.project_path, '.env.docker')

        # Set java memory limits to 80% of 1GB (The tasks max memory quota)
        try:
            os.system(f"sed -i '/JAVA_OPTS/d' '{env_docker_path}'")
        except Exception as e:
            print(f"Failed to remove JAVA_OPTS: {e}")

        with open(env_docker_path, 'a') as f:
            f.write("\nJAVA_OPTS=-Xmx820m\n")

    except Exception as e:
        print(f"Failed to set JAVA_OPTS: {e}")

    # Run the pov
    consistently_triggered_sanitizers = None
    triggered_sanitizer_history = []
    for idx in range(retry_count):
        start = time.time()
        run_pov_result = cp.run_pov(harness.name, data_file=pov_path, timeout=timeout)
        print(f"Run {idx} took {time.time() - start} seconds!")
        del run_pov_result['run_sh_stdout']
        del run_pov_result['run_sh_stderr']
        crash_report = run_pov_result['pov']
        if expect_crashing:
            # crash report is a dict, don't want to break the format
            if not crash_report or not any((crash_report or {}).get(v, {}).get('reports', []) for v in ['asan', 'kasan', 'jazzer']):
                print(f"#{idx}: POV {pov_path} did not crash!!!")
                print(f"#{idx}: POV {pov_path} stdout: {run_pov_result['stdout']}")
                print(f"#{idx}: POV {pov_path} stderr: {run_pov_result['stderr']}")
                triggered_sanitizer_history.append([])
                consistently_triggered_sanitizers = set()
                break
            # TODO: maybe a better way to handle this, since a timeout may lead to no crash
        else:
            if crash_report:
                print(f"#{idx}: POV {pov_path} crashed!!!")
                print(f"#{idx}: POV {pov_path} stdout: {run_pov_result['stdout']}")
                print(f"#{idx}: POV {pov_path} stderr: {run_pov_result['stderr']}")
        assert crash_report is not None, "No crash report found!!: " + str(run_pov_result)
        if idx == 0:
            consistently_triggered_sanitizers = set(crash_report["triggered_sanitizers"])
            triggered_sanitizer_history.append(list(sorted(consistently_triggered_sanitizers)))
            continue
        consistently_triggered_sanitizers &= set(crash_report["triggered_sanitizers"])
        triggered_sanitizer_history.append(list(sorted(set(crash_report["triggered_sanitizers"]))))

    print(f"CONSISTENTLY Triggered sanitizers: {consistently_triggered_sanitizers}")

    if find_vmlinux(target_dir): 
        raw_kasan_with_lineno = []
        for raw_kasan_with_sanitizers in crash_report['kasan']['reports']:
            raw_kasan = raw_kasan_with_sanitizers['report']
            raw_kasan_with_lineno.append(kasan_add_lineno(raw_kasan, target_dir))
        for idx, raw_kasan_with_sanitizers in enumerate(crash_report['kasan']['reports']):
            crash_report['kasan']['reports'][idx]['report'] = raw_kasan_with_lineno[idx]
    
    base_meta['run_pov_result'] = run_pov_result
    base_meta['original_crash_id'] = crash_id
    base_meta['sanitizer_history'] = triggered_sanitizer_history
    base_meta['consistent_sanitizers'] = crash_report['consistent_sanitizers'] = list(set(consistently_triggered_sanitizers))
    all_sanitizers = set([sanitizer for saniset in triggered_sanitizer_history for sanitizer in saniset])
    base_meta['inconsistent_sanitizers'] = crash_report['inconsistent_sanitizers'] = list(sorted(all_sanitizers - consistently_triggered_sanitizers))
    crash_report['cp_harness_binary_path'] = base_meta['cp_harness_binary_path']
    base_meta['cp_harness_name'] = crash_report['cp_harness_name'] = harness_name
    crash_report['harness_info_id'] = base_meta['harness_info_id']

    crash_report = yaml.dump(crash_report).encode()
    crash_report_md5 = hashlib.md5(crash_report).hexdigest()

    base_meta['crash_report_id'] = crash_report_md5

    # RepresentativeCrashingInputMetadata.model_validate(base_meta)

    # first, copy the pov to the output directory
    shutil.copy(pov_path, out_representative_crash)
    # then, copy the metadata to the output directory
    with open(out_representative_crash_metadata, 'w') as f:
        yaml.dump(base_meta, f)

    with open(output_run_pov_results_path, 'w') as f:
        yaml.dump(base_meta, f)

    with open(output_crash_report_path, 'wb') as f:
        f.write(crash_report)

def main():
    parser = argparse.ArgumentParser(description='Run a POV with a harness')
    parser.add_argument('--timeout', type=int, default=300, help='The timeout for the POV')
    parser.add_argument('--expect-crash', type=bool, help='Expect the POV to crash')
    parser.add_argument('base_meta_path', type=str, help='The base yaml path')
    parser.add_argument('output_run_pov_results_path', type=str, help='The output path')
    parser.add_argument('out_report_path', type=str, help='The output path')
    parser.add_argument('out_representative_crash', type=str, help='The output path')
    parser.add_argument('out_representative_crash_metadata', type=str, help='The output path')
    parser.add_argument('target_dir', type=str, help='The target directory')
    parser.add_argument('harness_name', type=str, help='The harness name')
    parser.add_argument('pov_path', type=str, help='The POV path')
    parser.add_argument("crash_id", type=str, help="The crash id")
    
    args = parser.parse_args()

    print(args)

    run_pov(
        args.base_meta_path,
        args.output_run_pov_results_path,
        args.out_report_path,
        args.out_representative_crash,
        args.out_representative_crash_metadata,
        args.target_dir,
        args.harness_name,
        args.pov_path,
        args.crash_id,
        timeout=args.timeout,
        retry_count=5
    )
    # retry_count is set to 5 because kernel run_pov may take a long time to run, for tipc, ~2 min for each run 
if __name__ == '__main__':
    main()
