import argparse
import os
import subprocess
import json
import random
import shlex
import shutil
import string

'''
This script MUST be constructed by the ctrace.py and run inside the CP docker
container with ./run.sh custom 'python in_docker_ctrace.py'.

When this script runs, we have:
  - /work --> the workdir we are using to work on this crash 
  - /src  --> the target directory where we can find the CP
  - /out 
'''

# Where to find benign seeds
BENIGN_SEEDS_AT = "<BENIGN_SEEDS_AT>"
# Where to find crashing seeds
CRASH_SEEDS_AT = "<CRASH_SEEDS_AT>"

# Where to put benign traces
BENIGN_TRACES_AT = "<BENIGN_TRACES_AT>"
# Where to put the crash trace
CRASH_TRACES_AT = "<CRASH_TRACES_AT>"
# Where to put the metadata related to the probes we add
PROBES_META_AT = "<PROBES_META_AT>"
# Name of the target harness
TARGET_HARNESS_NAME = "<TARGET_HARNESS_NAME>"
# Classpath of the target harness
TARGET_HARNESS_CLASSPATH = "<TARGET_HARNESS_CLASSPATH>"
# Path to the jar
TARGET_HARNESS_JAR = "<TARGET_HARNESS_JAR>"

TRACE_BENIGN_TIMEOUT = 30

TRACE_CRASH_TIMEOUT = None

SCRIPT_NAME = "ShitTrace"
#SKIP_CLASSES = ["java.lang.String"]
SKIP_CLASSES = []
TYPES_IN_SCOPE = ["java.lang.Boolean", "java.lang.Integer", "java.lang.String"]

JAZZER_ARGS = None
JAZZER_CMD = None


def parse_stacktrace(frames, full_clazz, method):
    clazz = full_clazz.split('.')[-1]
    caller = None
    callee = None

    for frame in frames:
        method_cp, fileinfo = frame.split('(')
        method = method_cp.split('.')[-1]
        fcp = '.'.join(method_cp.split('.')[:-1])
        
        if ':' not in fileinfo: continue
        fname, ln = fileinfo[:-1].split(':')
        fclazz = fname.split('.')[0]
        
        if callee:
            caller = (fcp, fname, ln)
            return callee, caller
        if fcp.endswith(full_clazz) and fclazz == clazz:
            callee = (fcp, fname, ln)
    
    return (None, None, None), (None, None, None)


def parse_trace_to_json(input_text):
    entries = []
    current_entry = {}
    args_list = []
    accumulating_args = False
    arg_type = None

    # for stack
    start_cur_thread = False
    stackframes = []

    for line in input_text.splitlines():
        line = line.strip()
        if line.startswith("jazzer exit="): continue
        if line.endswith(' -------------------') and ("ENTRY" in line or "RETURN" in line):
            # clear shit
            start_cur_thread = False
            if current_entry != {}:
                current_entry['arguments'] = args_list.copy()
                callee, caller = parse_stacktrace(stackframes, current_entry['class'], current_entry['method'])
                current_entry['caller'] = caller
                current_entry['callee'] = callee

                entries.append(current_entry.copy())
                args_list = []
                current_entry = {}
                stackframes = []

            point_type = line[1:-1].strip().split(' ')[0]
            current_entry['ppt_type'] = point_type
        elif line.startswith('[+] CLASS:'):
            current_entry['class'] = line.split(': ')[1]
        elif line.startswith('[+] METHOD:'):
            current_entry['method'] = line.split(': ')[1]
            accumulating_args = True
        elif line == '': continue
        # for args
        elif accumulating_args and line.startswith('[-]'):
            line = line[4:]
            if arg_type is None:
                arg_type = line
            else:
                if arg_type in TYPES_IN_SCOPE:
                    args_list.append({"type": arg_type, "value": line})
                arg_type = None
        # for stackframe
        elif accumulating_args:
            if "java.lang.Thread.dumpThreads(Native Method)" in line:
                start_cur_thread = True
            if line.startswith("Thread["):
                start_cur_thread = False
                continue
            if start_cur_thread:
                stackframes.append(line)

    if current_entry:
        current_entry['arguments'] = args_list.copy()
        callee, caller = parse_stacktrace(stackframes, current_entry['class'], current_entry['method'])
        current_entry['caller'] = caller
        current_entry['callee'] = callee
        entries.append(current_entry.copy())

    return entries
    # return json.dumps(entries, indent=4)


def run_command(cmd, timeout=None):
    try:
        # randomize stdout and stderr filenames because this is run in parallel
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        stdout_filename = f"/tmp/cmd_stdout_{suffix}"
        stderr_filename = f"/tmp/cmd_stderr_{suffix}"

        with open(stdout_filename, "wb") as cmd_stdout, open(stderr_filename, "wb") as cmd_stderr:
            print(f"Running command: {cmd}")
            pid = subprocess.Popen(cmd, shell=True, text=False, stdout=cmd_stdout, stderr=cmd_stderr)
            pid.communicate(timeout=timeout)
            exit_code = pid.returncode

        with open(stdout_filename, "r", encoding='utf-8', errors='replace') as cmd_stdout, open(stderr_filename, "r", encoding='utf-8', errors='replace') as cmd_stderr:
            cmd_stdout_text = cmd_stdout.read()
            cmd_stderr_text = cmd_stderr.read()
        
        # Remove files after we read the content
        os.remove(stdout_filename)
        os.remove(stderr_filename)

        return exit_code, cmd_stdout_text, cmd_stderr_text
    
    except subprocess.TimeoutExpired:
        print(f" >>> ⏰ Timeout expired for command {cmd} <<<")
        pid.kill()
        
        with open(stdout_filename, "r", encoding='utf-8', errors='replace') as cmd_stdout, open(stderr_filename, "r", encoding='utf-8', errors='replace') as cmd_stderr:
            cmd_stdout_text = cmd_stdout.read()
            cmd_stderr_text = cmd_stderr.read()
            # Remove files after we read the content
            os.remove(stdout_filename)
            os.remove(stderr_filename)
        return -1, cmd_stdout_text, cmd_stderr_text
    
    except subprocess.CalledProcessError as e:
        print(e)
        # Remove files after we read the content
        os.remove(stdout_filename)
        os.remove(stderr_filename)
        return -1, "", ""



btrace_head = f"""
import static org.openjdk.btrace.core.BTraceUtils.*;

import org.openjdk.btrace.core.annotations.*;
import org.openjdk.btrace.core.types.AnyType;

@BTrace(trusted = true)
public class {SCRIPT_NAME} {{
"""

context_var_decl = """
    @TLS
    private static int insideMethod = 0;
"""

def second_pass_gen_btrace_for_method(clazz, method):
    return '''
    @OnMethod(
        clazz="''' + clazz + '''",
        method="/.*/",
        location=@Location(Kind.ENTRY)
    )
    public static void '''+ f"{clazz.replace('.', '_')}_{method}_entry" +'''(
            @ProbeClassName String probeClass,
            @ProbeMethodName String probeMethod,
            AnyType[] args) {

        if (insideMethod>0) {
            print("-ENTRY -------------------");
            print(Strings.strcat("[+] CLASS: ", probeClass));
            print(Strings.strcat("[+] METHOD: ", probeMethod));
            for(int i = 0; i < args.length; i++) {
                print(Strings.strcat("[-] ", name(classOf(args[i]))));
                print(Strings.strcat("[-] ", str(args[i])));
            }
            print(jstackAllStr());
        }
    }
'''


def second_pass_gen_btrace_for_return(clazz, method):
    return '''
    @OnMethod(
        clazz="''' + clazz + '''",
        method="/.*/",
        location=@Location(Kind.RETURN)
    )
    public static void '''+ f"{clazz.replace('.', '_')}_{method}_return" +'''(
            @ProbeClassName String probeClass,
            @ProbeMethodName String probeMethod,
            @Return AnyType ret) {

        if (insideMethod>0) {
            print("-RETURN -------------------");
            print(Strings.strcat("[+] CLASS: ", probeClass));
            print(Strings.strcat("[+] METHOD: ", probeMethod));
            if (ret != null) {
                print(Strings.strcat("[-] ", name(classOf(ret))));
                print(Strings.strcat("[-] ", str(ret)));
            }
            print(jstackAllStr());
        }
    }
'''


def gen_tracker(clazz, method):
    return '''
    // coming in
    @OnMethod(
        clazz="''' + clazz + '''",
        method="''' + method + '''",
        location=@Location(value=Kind.ENTRY)
    )
    public static void context_in'''+ f"_{clazz.replace('.', '_')}_{method}" +'''(
            @ProbeClassName String probeClass,
            @ProbeMethodName String probeMethod,
            AnyType[] args) {

        if (insideMethod == 0) {
            print("-ENTRY -------------------");
            print(Strings.strcat("[+] CLASS: ", probeClass));
            print(Strings.strcat("[+] METHOD: ", probeMethod));
            for(int i = 0; i < args.length; i++) {
                print(Strings.strcat("[-] ", name(classOf(args[i]))));
                print(Strings.strcat("[-] ", str(args[i])));
            }
            print(jstackAllStr());
        }
        insideMethod++;
    }

    // going out
    @OnMethod(
        clazz="''' + clazz + '''",
        method="''' + method + '''",
        location=@Location(value=Kind.RETURN)
    )
    public static void context_out'''+ f"_{clazz.replace('.', '_')}_{method}" +'''(
        @ProbeClassName String probeClass,
        @ProbeMethodName String probeMethod,
        @Return AnyType ret) {
        insideMethod--;
        if (insideMethod == 0) {
            print("-RETURN -------------------");
            print(Strings.strcat("[+] CLASS: ", probeClass));
            print(Strings.strcat("[+] METHOD: ", probeMethod));
            if (ret != null) {
                print(Strings.strcat("[-] ", name(classOf(ret))));
                print(Strings.strcat("[-] ", str(ret)));
            }
            print(jstackAllStr());
        }
    }

'''


def gen_btrace_for_method(clazz, method):
    return '''
    @OnMethod(
        clazz="''' + clazz + '''",
        method="''' + method + '''"
    )
    public static void '''+ f"{clazz.replace('.', '_')}_{method}" +'''(
            @ProbeClassName String probeClass,
            @ProbeMethodName String probeMethod,
            AnyType[] args) {
        print(Strings.strcat("[+] ", probeClass));
        for(int i = 0; i < args.length; i++) {
            print(Strings.strcat("[+] ", name(classOf(args[i]))));
        }
    }
'''


def gen_first_pass_script(tracepoints_to_func, dump_dir):
    btrace_script = btrace_head

    seen_stuff = set()
    for loc, func in tracepoints_to_func.items():
        clazz_name = '.'.join(func.split('.')[:-1])
        func_name = func.split('.')[-1]
        
        # 🛡️ extra sanitization: remove any white spaces
        clazz_name = clazz_name.replace(" ", "_")
        func_name = func_name.replace(" ", "_")

        cf = f'{clazz_name}:{func_name}'
        # Skip if we have already seen this class:method
        if cf in seen_stuff:
            continue
        
        seen_stuff.add(cf)
        btrace_script += gen_btrace_for_method(clazz_name, func_name)
    btrace_script += "\n}"

    fp = os.path.join(dump_dir, f'{SCRIPT_NAME}.java')
    print("First pass btrace script dumped:", fp)
    with open(fp, 'w') as f:
        f.write(btrace_script)
    return fp


def parse_first_pass(fp):
    interesting_classes = []
    with open(fp, 'r') as f:
        for line in f.readlines():
            if line.startswith('[+]'):
                class_to_track = line[3:].strip()
                interesting_classes.append(class_to_track)
    return set(interesting_classes) - set(SKIP_CLASSES)


def gen_second_pass_script(tracepoints_to_func, first_pass_output_fp, dump_dir):
    btrace_script = btrace_head
    
    # put in the context tracker
    btrace_script += context_var_decl

    seen_stuff = set()
    for loc, func in tracepoints_to_func.items():
        clazz_name = '.'.join(func.split('.')[:-1])
        func_name = func.split('.')[-1]

        # 🛡️ extra sanitization: remove any white spaces
        clazz_name = clazz_name.replace(" ", "_")
        func_name = func_name.replace(" ", "_")

        cf = f'{clazz_name}:{func_name}'
        # Skip if we have already seen this class:method
        if cf in seen_stuff:
            continue
        
        seen_stuff.add(cf)

        btrace_script += gen_tracker(clazz_name, func_name)

    first_pass_output_classes = parse_first_pass(first_pass_output_fp)
    first_pass_output_classes.add("java.lang.String")
    
    # put in the actual tracing shit
    for clazz_name in first_pass_output_classes:
        btrace_script += second_pass_gen_btrace_for_method(clazz_name, "whatever")
    
    # put in the return values
    for clazz_name in first_pass_output_classes:
        btrace_script += second_pass_gen_btrace_for_return(clazz_name, "whatever")

    # the end
    btrace_script += "\n}"

    fp = os.path.join(dump_dir, f'{SCRIPT_NAME}.java')
    print(f"Second pass btrace script dumped: {fp}")
    with open(fp, 'w') as f:
        f.write(btrace_script)
    return fp

def process_seed(seed):
    seed_fp = os.path.join(BENIGN_SEEDS_AT, seed)
    shutil.copy(seed_fp, "/work/pov")
    exit_code, out, stderr = run_command(JAZZER_CMD)

    if exit_code == -1:
        print(f'🤡 Clowned it up while processing seed {seed}')
        return
    
    if exit_code != 0:
        print(f'🤔  Running challenge exited with: {exit_code}. stderr: {stderr}')

    # DEBUG: Save intermediate result
    #with open(BENIGN_TRACES_AT + f"/{seed}.raw_trace", "w") as f:
    #   f.write(out)
    
    trace_json = parse_trace_to_json(out)
    trace_fp = os.path.join(BENIGN_TRACES_AT, seed)
    with open(trace_fp, 'w') as f:
        json.dump(trace_json, f)

def main():

    # Open the tracepoints_to_func
    with open(f'/work/crash-workdir/tracepoints_to_func', "r") as f:
        tracepoints_to_func = json.load(f)

    # ============================================================
    # First pass: this is needed to expand our scope to the methods 
    # called over the arguments 👆🏻
    # ============================================================

    # First generate the script
    print(f' 🤸🏻 First pass: expanding scope of tracing...')
    print(f'  - Generating btrace script...')
    btrace_java_fp = gen_first_pass_script(tracepoints_to_func, f"/work/crash-workdir/")
    print(f'  - Compiling btrace script...')
    print(f'    - cd /shellphish && ./btrace/bin/btracec {btrace_java_fp}')
    os.system(f'cd /shellphish && ./btrace/bin/btracec {btrace_java_fp}')

    if not os.path.exists(f'/shellphish/{SCRIPT_NAME}.class'):
        print(f' 🤡 Compilation with btracec failed...')
        assert(False)

    print(f'  - Tracing crashing seed...')
    # Now trace the crashing input to expand our scope.
    seed_fp = os.path.join(CRASH_SEEDS_AT, "c000.seed")
    shutil.copy(seed_fp, "/work/pov")
    exit_code, out, stderr = run_command(JAZZER_CMD)
    
    if exit_code == -1:
        print(f'💀 Error while executing harness')
        assert(False)

    if exit_code != 0:
        print(f'🤔  executing harness exited with: {exit_code}. stderr: {stderr}')

    with open("/work/crash-workdir/first_pass_output", "w") as f:
        f.write(out)

    # Remove previous btrace script
    os.system(f'rm /shellphish/{SCRIPT_NAME}.class')

    print(f' 🤸🏻🤸🏻 Second pass: generating final btracer...')
    print(f'  - Generating refined btrace script...')

    # Refine btrace script for the second pass
    btrace_java_fp = gen_second_pass_script(tracepoints_to_func, f"/work/crash-workdir/first_pass_output", f"/work/crash-workdir/")
    print(f'  - Compiling btrace script...')
    print(f'    - cd /shellphish && ./btrace/bin/btracec {btrace_java_fp}')
    os.system(f'cd /shellphish && ./btrace/bin/btracec {btrace_java_fp}')

    if not os.path.exists(f'/shellphish/{SCRIPT_NAME}.class'):
        print(f' 🤡 Compilation with btracec failed...')
        assert(False)

    print(f'  - Finally tracing everything!')

    seeds = os.listdir(BENIGN_SEEDS_AT)
    for seed in seeds:
        process_seed(seed)

    # Trace the crashing input now
    seed_fp = os.path.join(CRASH_SEEDS_AT, "c000.seed")
    shutil.copy(seed_fp, "/work/pov")
    exit_code, out, stderr = run_command(JAZZER_CMD)
    
    if exit_code == -1:
        print(f'💀 Error while executing harness')
        assert(False)
    if exit_code != 0:
        print(f'🤔  executing harness exited with: {exit_code}. stderr: {stderr}')
    
    trace_json = parse_trace_to_json(out)
    trace_fp = os.path.join(CRASH_TRACES_AT, "c000.seed.trace")
    with open(trace_fp, 'w') as f:
        json.dump(trace_json, f)


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--jazzer-args', nargs=argparse.REMAINDER)
    args = argparser.parse_args()

    JAZZER_ARGS = args.jazzer_args
    JAZZER_CMD = shlex.join(['/work/crash-workdir/jazzer_btrace', *JAZZER_ARGS])

    main()
