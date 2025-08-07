
import os
import argparse
import json
import subprocess
import yaml

from rich import print

from carrot.carrot import InvChecker
from carrot.carrot import ProgramPoint

from .jutils import *

def load_ppts(PPTs:dict, traces:str, crash_ppts=False):
    '''
    Loads all the program points from the result of the btrace.
    '''
    num_success = 0
    num_fail = 0
    
    print(f'There are {len(os.listdir(traces))} traces to load')

    for trace_file in os.listdir(traces):

        absolute_path = os.path.join(traces, trace_file)
        with open(absolute_path, "r") as f:
            data = json.load(f)

            for raw_ppt in data:
                try:
                    if raw_ppt['ppt_type'] != 'ENTRY' and raw_ppt['ppt_type'] != 'RETURN':
                        continue
                    if 'class' not in raw_ppt.keys():
                        continue
                    
                    if raw_ppt['callee'] == [None, None, None]:
                        # Corrupted ppt, safer to skip
                        continue
                
                    code_location_classpath, code_location_filename, code_location_loc = raw_ppt['callee']
                
                    # Assumption: the code_location_filename MUST be equal to the last element of the
                    # ppt['class'], otherwise something is weird.
                    if code_location_filename.replace(".java", "") != raw_ppt['class'].split('.')[-1]:
                        print(f"🤡 {code_location_filename.replace('.java', '')} != {raw_ppt['class'].split('.')[-1]}")
                        continue

                    # e.g., io.jenkins.plugins.UtilPlug.UtilMain:doexecCommandUtils:ENTRY:120
                    ppt_name = raw_ppt['class'] + ":" + raw_ppt['method'] + ":" + raw_ppt['ppt_type'] + ":" + code_location_loc
                    if ppt_name not in PPTs:
                        PPTs[ppt_name] = ProgramPoint(ppt_name)

                    ppt = PPTs[ppt_name]

                    if crash_ppts:
                        # This is a ppt in the crashing trace
                        ppt.in_crashing_trace = True
                    
                    ppt_args = []
                    if raw_ppt['ppt_type'] == 'ENTRY':
                        for arg_id, arg in enumerate(raw_ppt['arguments']):
                            arg_name = f'arg{arg_id}'
                            if arg['type'] == 'java.lang.Boolean':
                                ppt_args.append(("boolean", f'{arg_name}={arg["value"]}'))
                            elif arg['type'] == 'Java.lang.Integer':
                                ppt_args.append(("numerical", f'{arg_name}={arg["value"]}'))
                            else:
                                # Default to string
                                ppt_args.append(("string", f'{arg_name}={arg["value"]}'))
                    else:
                        for ret_id, ret in enumerate(raw_ppt['arguments']):
                            ret_name = f'ret{ret_id}'
                            if ret['type'] == 'java.lang.Boolean':
                                ppt_args.append(("boolean", f'{ret_name}={ret["value"]}'))
                            elif ret['type'] == 'Java.lang.Integer':
                                ppt_args.append(("numerical", f'{ret_name}={ret["value"]}'))
                            else:
                                # Default to string
                                ppt_args.append(("string", f'{ret_name}={ret["value"]}'))
                
                    ppt.add_observation_with_type(ppt_args)
                    num_success += 1
            
                except Exception as e:
                    num_fail += 1
                    print(f"Error loading raw_ppt {raw_ppt}: {e}")
                    continue

    return num_success, num_fail


def yolo_get_key_index(file, loc, func, functions_by_file_index_report):
    print(f'Fetching keyindex for {file}:{loc}')
    
    # get all the keys in the functions_by_file_index that contains the 
    filenames = functions_by_file_index_report.keys()
    
    print(f'Available filenames: {filenames}')

    for filename in filenames:
        # Our filename extracted from btrace is a substring 
        # of the filename in the functions_by_file_index
        if file in filename:
            # Found it!
            break
    else:
        return "?"

    # Now, to get the file index, we iterate over all the entries and get the right
    # function signature :) 
    for func_entry in functions_by_file_index_report[filename]:
        if func_entry['start_line'] <= int(loc) <= func_entry['end_line']:
            return func_entry['function_signature']
    else:
        return "?"

def tracepoint_to_file(tracepoint, functions_by_file_index):
    file = "?"
    loc = "?"
    func = "?"
    key_index= "?"
    try:
        tracepoint_name = tracepoint.split(":")[1]

        #file = probes_metadata[tracepoint_name].split(":")[0]
        #loc = probes_metadata[tracepoint_name].split(":")[1].split(" ")[0]
        file = tracepoint.split(":")[:-2][0].replace(".", "/") + ".java"
        loc = tracepoint.split(":")[-1]
        func = tracepoint.split(":")[-3]

        key_index = yolo_get_key_index(file, loc, func, functions_by_file_index)
        #func = tracepoints_to_func[f'{file}:{loc}']
        #return file, loc, func
        return file, loc, func, key_index
    except Exception as e:
        print(f'Exception during tracepoint_to_file: {e}')
        return file, loc, func, key_index

def jmine(target_dir, benign_traces_dir, crash_trace_dir, tracepoints_to_func, tracepoints_to_key_index, functions_by_file_index_report, invariant_report_out):
    print(f'🥕⛏️ Starting mining invariants!')
    PPTs = dict()
    VIOLATIONS_REPORT = dict()

    print(f' - Loading PPTs from benign traces')
    # for every trace in benign_traces, extract the ppts
    num_success, num_fail = load_ppts(PPTs, benign_traces_dir)

    # 🛡️: if we did not load any PPTs we have some problems.
    if num_success == 0:
        print(f' 🥶 Could not load any meaningful benign trace. Kamikaze!')
        raise KamikazeException()

    print(f' - Extracting PPTs vars')
    inv_checker = InvChecker(
                             numerical_invs = True, 
                             boolean_invs   = True, 
                             strings_invs   = True
                            )
    inv_checker.extract(PPTs)
    
    print(f' - Loading PPTs from crashing traces')
    # for every trace in crash_traces, extract the ppts
    num_success, num_fail = load_ppts(PPTs, crash_trace_dir, crash_ppts=True)
    
    # 🛡️: if we did not load the crashing trace properly, we gotta abort.
    if num_success == 0:
        print(f' 🫣 Could not load PPTs for the crashing trace. Kamikaze!')
        raise KamikazeException()

    print(f' - Checking violations!')
    violations, ppts_unique_to_crash = inv_checker.check_violations(PPTs)

    # open the yaml functions_by_file_index_report
    with open(functions_by_file_index_report, "r") as f:
        functions_by_file_index_report = yaml.safe_load(f)

    if len(violations) != 0:

        # print violations
        for violated_ppt, violation_diff in violations.items():
            #print(f"Program Point (violation): {violated_ppt}")
            file, loc, func, key_index = tracepoint_to_file(violated_ppt, functions_by_file_index_report)
            #print(f"  >>> Violations: {violation_diff}")

            assert(violated_ppt not in VIOLATIONS_REPORT)
            assert(violated_ppt not in ppts_unique_to_crash)
            VIOLATIONS_REPORT[violated_ppt] = dict()
            VIOLATIONS_REPORT[violated_ppt]['violations'] = violation_diff
            VIOLATIONS_REPORT[violated_ppt]['file'] = file
            VIOLATIONS_REPORT[violated_ppt]['line'] = loc
            VIOLATIONS_REPORT[violated_ppt]['func'] = func
            VIOLATIONS_REPORT[violated_ppt]['key_index'] = key_index
            VIOLATIONS_REPORT[violated_ppt]['unique_to_crash'] = False

    if len(ppts_unique_to_crash) != 0:
        for interesting_ppt in ppts_unique_to_crash:
            file, loc, func, key_index = tracepoint_to_file(interesting_ppt, functions_by_file_index_report)
            VIOLATIONS_REPORT[interesting_ppt] = dict()
            VIOLATIONS_REPORT[interesting_ppt]['violations'] = list()
            VIOLATIONS_REPORT[interesting_ppt]['file'] = file
            VIOLATIONS_REPORT[interesting_ppt]['line'] = loc
            VIOLATIONS_REPORT[interesting_ppt]['func'] = func
            VIOLATIONS_REPORT[interesting_ppt]['key_index'] = key_index
            VIOLATIONS_REPORT[interesting_ppt]['unique_to_crash'] = True

    print(VIOLATIONS_REPORT)

    if len(violations) == 0 and len(ppts_unique_to_crash) == 0:
        print(f'🤷🏻‍♂️ No invariants being broken')
        print(f' --> 💀🗡️ Kamikaze so we avoid triggering other stuff!')
        raise KamikazeException()

    # dump the dictionary violations as json on file
    with open(invariant_report_out, "w") as f:
        f.write(json.dumps(VIOLATIONS_REPORT))
