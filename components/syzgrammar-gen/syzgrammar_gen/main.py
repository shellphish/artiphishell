from .verify import CompilationConfig, try_compile_grammar
from .agent import run as run_agent
from pathlib import Path
import subprocess
import tempfile
import argparse
import json
import sys
import os

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser("syzgrammar-gen")
    parser.add_argument('syzkaller_path', type=str, help="The path of the syzkaller repository to use")
    parser.add_argument('harness_path', type=str, help="The path to the harness")
    parser.add_argument('joern_path', type=str, help="The path to the joern executable")
    parser.add_argument('grammar_out', type=str, help="The output path for the grammar")
    parser.add_argument('filter_out', type=str, help="The output path for the syscall filter")
    return parser.parse_args(sys.argv[1:])

def project_path(name: str) -> str:
    # Get the path to a file included in this project's source
    return os.path.join(os.path.dirname(__file__), name)

def generate_grammar(compile_config: CompilationConfig, harness_path: Path):
    with open(harness_path, "r") as fp:
        harness_code = fp.read()

    syzlang_grammar = run_agent(compile_config, harness_code)

    if syzlang_grammar is None:
        print("Failed to generate grammar!")
        exit(1)

    return syzlang_grammar

def reachable_args(joern_path: Path, harness_path: Path):
    """
    Get a list of call names and argument indicies which may be tainted
    by the contents of the input blob
    returns: the loaded Json output from the joern argument finding scripts
    """
    with tempfile.NamedTemporaryFile() as temp_file:
        tempfile_path = temp_file.name
        command = [
            "clang",
            "-E",
            harness_path,
            "-o",
            "/tmp/preprocessed.c"
        ]
        subprocess.run(command)

        command = [
            str(joern_path),
            "--script",
            project_path("externs.sc"),
            "--param",
            f"inputFilePath={harness_path}",
            "--param",
            f"outputFilePath=externs"
        ]
        subprocess.run(command)

        command = [
            str(joern_path),
            "--script",
            project_path("args.sc"),
            "--param",
            f"inputFilePath=/tmp/preprocessed.c",
            "--param",
            f"outputFilePath={tempfile_path}"
        ]
        subprocess.run(command)
        with open(tempfile_path, 'r') as fp:
            call_args = json.load(fp)

    return call_args

def main():
    ns: argparse.Namespace = parse_args()

    syzkaller_path = Path(ns.syzkaller_path)
    harness_path = Path(ns.harness_path)
    joern_path = Path(ns.joern_path)
    grammar_out_path = Path(ns.grammar_out)
    filter_out_path = Path(ns.filter_out)

    compiler_threads = 2
    compile_config = CompilationConfig(syzkaller_path, compiler_threads)

    # Determine external call arguments which may be affected by the input blob
    call_args = reachable_args(joern_path, harness_path)
    print(call_args)

    with open(syzkaller_path / "sys/json/linux/amd64.json") as fp:
        syzlang = json.load(fp)

    syscall_filter = set()
    syzkalls = {s['NR']: s['CallName'].split('$')[0] for s in syzlang['Syscalls'] if not s['CallName'].startswith('syz')}
    print("syzkalls:", syzkalls)
    for call_arg in call_args:
        name = call_arg['callName']

        if name in ['exit', 'exit_group', 'unshare']: continue
        if name in ['send', 'sendto', 'sendmmsg']:
            syscall_filter.add('sendmsg');
        if name in ['sleep']:
            syscall_filter.add('clock_nanosleep');

        if name in syzkalls.values():
            syscall_filter.add(call_arg['callName']);
        elif name.startswith("syscall#"):
            syscall_number = int(name.split('#')[1])
            syscall_name = syzkalls.get(syscall_number)
            if not syscall_name is None:
                syscall_filter.add(syzkalls[syscall_number])
            else:
                print("ERROR: COULD NOT FIND SYSCALL FOR SYSCALL NUMBER", syscall_number)
    print("syscall_filter:", syscall_filter)

    with open(filter_out_path, "w+") as fp:
        fp.write(str(list(syscall_filter)))

    # Generate syzlang grammar for the harness using an LLM agent
    generated_grammar = generate_grammar(compile_config, harness_path)

    result = try_compile_grammar(compile_config, generated_grammar)

    if not result.success:
        print("[FAIL] generated grammar failed to compile")
        print("Output:\n", result.output)
        print("[FAIL] exiting with code 1")
        exit(1)

    grammar = generated_grammar

    if not " array[int8]\n" in grammar and not " buffer[in]\n" in grammar:
        print("[INFO] generated grammar did not contain any buffers to replace, emitting unmodified grammar")
        print("Grammar:\n", grammar)

        with open(grammar_out_path, "w") as fp:
            fp.write(generated_grammar)

        exit(0)

    # Filter call_args down by trying to match them to syscalls in syzlang
    syscall_args = set()
    for syscall in syzlang['Syscalls']:
        for call_arg in call_args:
            if call_arg['isLiteral']: continue

            name = call_arg['callName']
            arg = call_arg['argumentIndex']

            # Special case for sendto, since syzlang uses sendmsg in nearly
            # all cases instead, maybe we should do the same for write/send?
            if name in("sendto", "send") and arg == 1:
                # print("adding packet argument")
                for s in syzlang['Syscalls']:
                    if s['CallName'] == "sendmsg":
                        try:
                            # fun! ( rips the message type out of all the msghdrs )
                            syscall_args.add(syzlang['Types'][syzlang['Types'][syzlang['Types'][syzlang['Types'][syzlang['Types'][s['Args'][1]['Type']]['Value']['Elem']]['Value']['Fields'][3]['Type']]['Value']['Elem']]['Value']['Fields'][0]['Type']]['Value']['Elem'])
                        except Exception as e:
                            pass
            if syscall['CallName'] == name:
                print("LOOP:", name, arg)
                syscall_arg = syscall['Args'][arg]
                arg_type = syzlang['Types'][syscall_arg['Type']]

                # We assume we won't be inserting resources, e.g. fd, socket
                # numbers into the input blob
                if arg_type['Name'] == "ResourceType":
                    continue

                if arg_type['Name'] == "PtrType":
                    # Take the inner type of pointer arguments
                    syscall_args.add(arg_type['Value']['Elem'])
                else:
                    syscall_args.add(syscall_arg['Type'])

    # Create an Enum of all the possible input types
    arg_type_names = set()
    for arg in syscall_args:
        # TODO: For now just doing struct types (other types will require a little
        #       bit more work, and structs are the most important anyways)
        if syzlang['Types'][arg]['Name'] == 'StructType':
            arg_type_names.add(syzlang['Types'][arg]['Value']['TypeName'])

    inputs_enum = "syz_harness_arg_types [\n" # ]
    for idx, arg in enumerate(arg_type_names):
        inputs_enum += f"\tharness_t{idx} {arg}\n"
    inputs_enum += "] [varlen]"

    # Replace buffer types (array[int8], buffer[in]) with the Enum
    grammar = grammar.replace(" array[int8]\n", " syz_harness_arg_types\n")
    grammar = grammar.replace(" buffer[in]\n", " syz_harness_arg_types\n")

    # TODO: should make sure if there is a 'len[fieldname]' on the buffer type
    #       in the same struct, it should be updated to be bytesize[fieldname]
    #       it could be worth doing edits in the json rather than to the text
    #       of the harness...

    grammar += "\n" + inputs_enum

    result = try_compile_grammar(compile_config, grammar)

    if not result.success:
        print("[FAIL] modified grammar failed to compile final grammar")
        print("Output:\n", result.output)
        print("[INFO] emitting generated grammar instead of modified due to failure")

        with open(grammar_out_path, "w") as fp:
            fp.write(generated_grammar)

        exit(0)

    print("[INFO] emitting modified grammar")
    with open(grammar_out_path, "w") as fp:
        fp.write(grammar)

    print("Done!")
