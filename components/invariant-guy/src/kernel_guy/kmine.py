
import os
import argparse
import json
import subprocess

from rich import print

from carrot.carrot import InvChecker
from carrot.carrot import ProgramPoint

from .kutils import *


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
                _l = line.split("probe:")[1]
                ppt_name = _l.split(":")[0]

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
                num_fail+=1
                print(f"Error loading trace {trace_file}: {e}")
                continue

    return num_success, num_fail


def tracepoint_to_file(probes_metadata, tracepoint_name, tracepoints_to_func, tracepoints_to_key_index):
    file = "?"
    loc = "?"
    func = "?"
    key_index= "?"
    try:
        # examples:
        #  tracepoint_name: 'select_c_664' (no binary name prefixed to the tracepoint name)
        file = probes_metadata[tracepoint_name].split(":")[0]
        loc = probes_metadata[tracepoint_name].split(":")[1].split(" ")[0]

        func = tracepoints_to_func[f'{file}:{loc}']
        key_index = tracepoints_to_key_index[f'{file}:{loc}']
        return file, loc, func, key_index

    except Exception:

        return file, loc, func, key_index

'''
def tracepoint_to_file(tracepoint, kernel_src_dir):
    vmlinux_path = kernel_src_dir + "/vmlinux"

    try:
        tracepoint_name = '_'.join(tracepoint.split("_")[:-1])
        tracepoint_offset = int(tracepoint.split("_")[-1],16)

        cmd = f'nm {vmlinux_path} | grep {tracepoint_name}'
        result = subprocess.Popen(cmd, shell=True, text=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        res = result.stdout.read().decode('utf-8', errors='ignore').strip()
        address = int(res.split(" ")[0],16)
        tracepoint_loc_address  = hex(address + tracepoint_offset)

        cmd = f'addr2line -e {vmlinux_path} {tracepoint_loc_address}'
        result = subprocess.Popen(cmd, shell=True, text=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        loc = result.stdout.read().decode('utf-8', errors='ignore').strip()
        file = loc.split(":")[0]
        line = loc.split(":")[1]

    except Exception:
        # worst case, we just give up on this
        return '?', '?'

    return file, line
'''


'''
 __           .__
|  | __ _____ |__| ____   ____
|  |/ //     \|  |/    \_/ __ \
|    <|  Y Y  \  |   |  \  ___/
|__|_ \__|_|  /__|___|  /\___  >
     \/     \/        \/     \/

    This is mining the invariants and check for violations in the execution of the
    crashing input. It will generate a report.

    Example of VIOLATIONS_REPORT:

    {
        'switch_fpu_return_0x1af': {'violations': ['cpu==1', 'cpu!=0'], 'file': 'bugs.c', 'line': '?'},
        'process_backlog_0x1f2': {'violations': ['napi==18446612686726988944', 'sd>skb', 'napi>sd', 'sd==18446612686726988672'], 'file': '/src/./include/linux/rcupdate.h', 'line': '779'},
        'net_rx_action_0x4fb': {'violations': ['repoll==18446612686726799136', 'n>repoll', 'sd>repoll', 'sd==18446612686726988672', 'n==18446612686726988944', 'n>sd'], 'file': '/src/net/core/dev.c', 'line': '6572'},
        'tipc_rcv_0x1b07': {'violations': ['n==2305826585840849690'], 'file': '/src/net/tipc/node.c', 'line': '2173'},
        'tipc_crypto_msg_rcv_0x336': {'violations': ['keylen<size', 'rx>skb', 'keylen==956'], 'file': '/src/./include/linux/slab.h', 'line': '558'},
        'tipc_crypto_msg_rcv_0x3fa': {'violations': ['keylen<size', 'rx>skb', 'keylen==956'], 'file': '/src/net/tipc/crypto.c', 'line': '2314'},
        'handle_irq_event_0xb8': {
            'violations': ['d!=0', 'desc>ret', 'ret==1', 'd<desc', 'd>ret', 'ret!=0', 'd==47244640256', 'desc==18446612686366880768', 'desc!=0'],
            'file': '/src/./include/asm-generic/bitops/instrumented-non-atomic.h',
            'line': '141'
        }
    }

    NOTE: If we cannot recover the file:line, we just put a "?". Downstream tools
    will decide what to do with this information.

'''

def kmine(kernel_src_dir, crash_workdir, probes_metadata, tracepoints_to_func, tracepoints_to_key_index, output_report_at):
    print(f'🥕⛏️ Starting mining invariants!')
    PPTs = {}
    VIOLATIONS_REPORT = dict()

    benign_traces_dir = crash_workdir + BENIGN_TRACES_DIR
    crash_trace_dir = crash_workdir + CRASH_TRACES_DIR

    print(f'Loading program points from benign traces in {benign_traces_dir}')

    # for every trace in benign_traces, extract the ppts
    num_success, num_fail = load_ppts(PPTs, benign_traces_dir)

    # 🛡️: if we did not load any PPTs we have some problems.
    if num_success == 0:
        print(f' 🥶 Could not load any meaningful benign trace. Outputting empty report.')
        raise KamikazeException()

    inv_checker = InvChecker()
    inv_checker.extract(PPTs)

    print(f'Loading program points from crashing trace in {crash_trace_dir}')

    # Load the crashing trace!
    num_success, num_fail = load_ppts(PPTs, crash_trace_dir, crash_ppts=True)

    # 🛡️: if we did not load the crashing trace properly, we gotta abort.
    if num_success == 0:
        print(f' 🫣 Could not load PPTs for the crashing trace. Outputting empty report.')
        raise KamikazeException()

    violations, ppts_unique_to_crash = inv_checker.check_violations(PPTs)

    VIOLATIONS_REPORT = dict()
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
    with open(output_report_at, "w") as f:
        f.write(json.dumps(VIOLATIONS_REPORT))

def main():
    argparser = argparse.ArgumentParser(description='Check invariants for a kernel crash')

    # Location of the kernel source code (the root of the .config)
    argparser.add_argument('--kernel-src-dir', type=str, help='src of the kernel')
    argparser.add_argument('--benign-traces', type=str, help='path to the folder containing the benign traces')
    argparser.add_argument('--crash-traces', type=str, help='path to the folder containing the crashing traces')
    argparser.add_argument('--out', type=str, help='path to the file where to store the invariants violations reports')

    args = argparser.parse_args()

    kernel_src_dir = args.kernel_src_dir
    benign_traces = args.benign_traces
    crash_traces = args.crash_traces
    out = args.out

    kmine(kernel_src_dir, benign_traces, crash_traces, out)



if __name__ == '__main__':
    main()