
import os
import json

from rich import print

from carrot.carrot import InvChecker
from carrot.carrot import ProgramPoint

from .cutils import *

def load_ppts(PPTs:dict, traces:str, crash_ppts=False):
    '''
    Loads all the program points from the perf traces
    and add them to the PPTs dictionary
    '''
    num_fail = 0
    num_success = 0
    for trace_file in os.listdir(traces):

        absolute_path = os.path.join(traces, trace_file)
        with open(absolute_path, "r") as f:
            data = f.readlines()
        
        # Getting all the program points in the trace
        for line in data:
            
            try:
                _l = line.split("probe_")[1]
                ppt_name = _l.split(" ")[0][:-1]

                if ppt_name not in PPTs:
                    PPTs[ppt_name] = ProgramPoint(ppt_name)
                ppt = PPTs[ppt_name]

                if crash_ppts:
                    ppt.in_crashing_trace = True

                # Add all observed variables to the program point
                vars = _l.split(")")[1].strip().split(" ")
                ppt.add_observation(vars)
                num_success += 1

            except Exception as e:
                print(f" 🥶 Error loading trace {trace_file}: {e}")
                num_fail += 1
                continue

    return num_success, num_fail


def tracepoint_to_file(probes_metadata, tracepoint, tracepoints_to_func, tracepoints_to_key_index):
    file = "?"
    loc = "?"
    func = "?"
    key_index= "?"
    try:
        # examples:
        #  'mock_vp:mock_vp_c_14'
        #  {'mock_vp_c_14': '/src/samples/mock_vp.c:14 buff i j'}
        #  '/src/samples/mock_vp.c:14 buff i j'
        #  TODO sanitize these names better
        tracepoint_name = tracepoint.split(":")[1]
        file = probes_metadata[tracepoint_name].split(":")[0]
        loc = probes_metadata[tracepoint_name].split(":")[1].split(" ")[0]

        func = tracepoints_to_func[f'{file}:{loc}']
        key_index = tracepoints_to_key_index[f'{file}:{loc}']
        return file, loc, func, key_index

    except Exception:
        return file, loc, func, key_index

def cmine(target_dir, benign_traces_dir, crash_trace_dir, probes_metadata, tracepoints_to_func, tracepoints_to_key_index, invariant_report_out):
    print(f'🥕⛏️ Starting mining invariants!')
    PPTs = {}
    VIOLATIONS_REPORT = dict()

    print(f' - Loading PPTs from benign traces')
    # for every trace in benign_traces, extract the ppts
    num_success, num_fail = load_ppts(PPTs, benign_traces_dir)

    # 🛡️: if we did not load any PPTs we have some problems.
    if len(PPTs.keys()) == 0:
        print(f' 🥶 Could not load any meaningful trace. Outputting empty report.')
        raise KamikazeException()

    print(f' - Extracting PPTs vars')
    inv_checker = InvChecker()
    inv_checker.extract(PPTs)

    print(f' - Loading PPTs from crashing traces')
    # for every trace in crash_traces, extract the ppts
    num_success, num_fail = load_ppts(PPTs, crash_trace_dir, crash_ppts=True)

    # 🛡️: if we did not load the crashing trace properly, we gotta abort.
    if num_success == 0:
        print(f' 🫣 Could not load PPTs for the crashing trace. Outputting empty report.')
        raise KamikazeException()

    print(f' - Checking violations!')
    violations, ppts_unique_to_crash = inv_checker.check_violations(PPTs)

    if len(violations) != 0:

        # print violations
        for violated_ppt, violation_diff in violations.items():
            #print(f"Program Point (violation): {violated_ppt}")
            file, loc, func, key_index = tracepoint_to_file(probes_metadata, violated_ppt, tracepoints_to_func, tracepoints_to_key_index)
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
            file, loc, func, key_index = tracepoint_to_file(probes_metadata, interesting_ppt, tracepoints_to_func, tracepoints_to_key_index)
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
