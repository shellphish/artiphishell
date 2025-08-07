#!/usr/bin/env python3
import os
import sys
import shutil
from pathlib import Path
import yaml
import json
import random
import subprocess

print('\n\n\n============ Executing jazzer_wrapper.py ============\n\n\n')

JAZZER_BIN = "/classpath/jazzer/jazzer.bin"

INPUTS = Path("/inputs")

TRIAGE_FILE_ENV_VAR = "TRIAGE_FILE_ENV_VAR"

SRC_DIR = Path("/src")
OUT_DIR = Path("/out")
WORK_DIR = Path("/work")

def dump_cmd(args, filename):
    with open(filename, "w") as f:
        f.write(f"""#!/bin/bash
set -x
{" ".join(x for x in args)}\n""")


def update_cp_in_config(args_list, new_value, arg_to_update):
    for i, arg in enumerate(args_list):
        try:
            if arg.startswith(f"--{arg_to_update}"):
                if new_value:
                    args_list[i] = f'--{arg_to_update}"{new_value}"'
                else:
                    args_list.pop(i)
                break
        except Exception as e:
            print(f"Error in update config: {e}")
            continue
    return args_list


def fuzz_mode(cli_args, fuzz_with_new_args, FUZZ_SCRIPT, config_name):
    # print(f"func with new args: {fuzz_with_new_args}")
    new_args = [ JAZZER_BIN ] + fuzz_with_new_args
    collect_cps = []
    flag = False
    for x in cli_args[:-1]:
        if 'runs' in x:
            continue
        elif 'artifact_prefix' in x:
            flag = True
            new_args.append('-artifact_prefix=/crashes/')
            continue
        new_args.append(x)

    if cli_args[-1].startswith("-") is False:
        new_args.append(INPUTS.as_posix())
    else:
        new_args.extend([cli_args[-1], INPUTS.as_posix()])

    if flag is False:
        idx = 1 + len(fuzz_with_new_args)
        new_args = new_args[:idx] + ["-artifact_prefix=/crashes/"] + new_args[idx:]
    if INPUTS.is_dir() is False:
        INPUTS.mkdir(parents=True, exist_ok=True)

    fuzz_script = f'''
#!/bin/bash

set -x

nohup bash /work/auto_kill.sh > /work/tmpkill_{config_name}.log &

while true; do
  timeout -s 9 300 {" ".join(x for x in new_args)} || true;
  echo '======= Restarting To Incorporate New Seed Files ======='
  sleep 1
done
'''

    with open(FUZZ_SCRIPT, "w") as f:
        f.write(fuzz_script)

def triage_mode(cli_args, TRIAGE_SCRIPT):
    new_args = [ JAZZER_BIN ] + cli_args[:-1]
    if cli_args[-1].startswith("-") is False:
        new_args.append("${TRIAGE_FILE_ENV_VAR}")
    else:
        new_args.extend([cli_args[-1], "${TRIAGE_FILE_ENV_VAR}"])
    dump_cmd(new_args, TRIAGE_SCRIPT)


def fix_paths(cli_args):
    fix_args = []
    for x in cli_args:
        if x.startswith("-") is False:
            fix_args.append(x)
            continue
        idx = x.find("=")
        if idx < 0:
            fix_args.append(x)
            continue
        paths = x[idx+1:].split(":")
        if len(paths) == 0:
            fix_args.append(x)
            continue
        new_path = []
        for y in paths:
            thing = Path(y)
            if any(thing.resolve().is_relative_to(x) for x in [SRC_DIR, OUT_DIR, WORK_DIR]):
                new_path.append(thing)
                continue
            if thing.is_file():
                print(f"Copying {y} to {WORK_DIR}")
                shutil.copy(y, WORK_DIR)
                new_path.append(WORK_DIR / thing.name)
            elif thing.is_dir():
                for item in thing.iterdir():
                    if item.is_file():
                        print(f"Copying {y} to {WORK_DIR}")
                        shutil.copy(item, WORK_DIR)
            else:
                new_path.append(thing)
        fix_args.append(f"{x[:idx+1]}{':'.join(z.as_posix() for z in new_path)}")

    return fix_args

def load_configurations(file_path):
    """
    Loads the YAML configuration file and extracts the NEW_ARGS for each configuration.
    
    :param file_path: str - Path to the YAML configuration file.
    :return: dict - A dictionary with keys 'config1' to 'config8' and values being the list of args.
    """
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
        config_args = {}
        for key, config in data['jazzer_fuzzing_configs'].items():
            config_args[key] = config['NEW_ARGS']
    return config_args


def main(cli_args):

    jazzer_config_file = '/work/jazzer_fuzzing_configs.yaml'
    jazzer_configs = load_configurations(jazzer_config_file)
    
    in_scope_cls = {
                    'in_scope_packages_from_antlr': None,
                    'all_packages_from_reachability_report': None,
                    'sources_to_classes': None
                    }

    if os.path.exists("/work/packages_in_scope.json"):
        with open("/work/packages_in_scope.json", "r") as f:
            in_scope_cls = json.loads(f.read())

    in_scope_packages_from_antlr = in_scope_cls.get('in_scope_packages_from_antlr', None)
    all_packages_from_reachability_report = in_scope_cls.get('all_packages_from_reachability_report', None)
    sources_to_classes = in_scope_cls.get('sources_to_classes', None)
    
    if sources_to_classes: 
        all_source_keys = list(sources_to_classes.keys())
        random.shuffle(all_source_keys)
    else:
        all_source_keys = []
    
    for i, (key, fuzz_with_new_args) in enumerate(jazzer_configs.items(), 1):
        try:
            new_includes_value = None
            # config1 - codeql reachability report
            if key in ['config1', 'config5']:
                new_includes_value = all_packages_from_reachability_report
            # config2 - in scope in classes from antlr
            elif key in ['config2', 'config6']:
                new_includes_value = in_scope_packages_from_antlr
            # source + plugin + harness 
            elif key in ['config4', 'config7']:
                if len(all_source_keys) > 2:
                    all_source_keys = all_source_keys[:2]
                for sk in all_source_keys:
                    if 'harness' in sk.lower():
                        continue
                    new_includes_value = sources_to_classes[sk]
            
            fuzz_with_new_args = update_cp_in_config(fuzz_with_new_args, new_includes_value, 'instrumentation_includes=')
            fuzz_with_new_args = update_cp_in_config(fuzz_with_new_args, new_includes_value, 'custom_hook_includes=')

            FUZZ_SCRIPT = f"/work/fuzz_{i}.sh"
            TRIAGE_SCRIPT = f"/work/triage_{i}.sh"
            new_args = fix_paths(cli_args)
            fuzz_mode(new_args, fuzz_with_new_args, FUZZ_SCRIPT, key)
            triage_mode(new_args, TRIAGE_SCRIPT)

        except Exception as e:
            print(f"Error: {e}")
            continue


if __name__ == '__main__':
    fuzz_index = os.environ.get('FUZZ_INDEX')
    print(f"FUZZ_INDEX: {repr(fuzz_index)}")
    if fuzz_index:
        print(f"\n\n\n============ Executing fuzzing script {fuzz_index} ============\n\n\n")
        os.system(f'chmod +x /work/fuzz_{fuzz_index}.sh')
        sys.stdout.flush()
        os.system(f"/bin/bash /work/fuzz_{fuzz_index}.sh | tee /work/fuzz_{fuzz_index}_output.txt 2>&1")

    main(sys.argv[1:])
    print("\n\n\n============ Finished executing jazzer_wrapper.py ============\n\n\n")
