'''
TODO: 
    1. Test the tool with nginix challenge
    2. Make sure GDB works properly 
    3. Proper Exception Handling
'''
import os
import argparse
import subprocess
import yaml
import requests
import json

from pathlib import Path

from universal_dbg.engine.openai_utils import chatgpt_functions
from universal_dbg.engine.openai_utils import (
    print_colored_messages,
    call_chatgpt_function,
    get_function_call_result_message,
    # check how does this generate function_schema
    get_chatgpt_function_schema,
    chatgpt_function,
)

from universal_dbg.engine.openai_utils.functions_api import extract_stack_trace_from_poi, fetch_function_source_using_signature, generate_function_list, format_srcdict_to_str, convert_python_dictionary_to_string
from universal_dbg.engine.openai_utils import globals
import os
from universal_dbg.engine.openai_utils.chatgpt_functions import set_globals, get_crash_context, obtain_directory_structure_as_str, get_input_data
# from globals import MODEL, CLIENT
import shutil

MODEL = globals.MODEL
# AVAILABLE_FUNCTIONS = globals.AVAILABLE_FUNCTIONS
# CLIENT = globals.CLIENT
PROPOSED_ROOT_CAUSE = False
AVAILABLE_FUNCTIONS = globals.AVAILABLE_FUNCTIONS
# remember to set the environment variable LITELLM_URL to the URL of the LitELLM server
url = os.environ.get("AIXCC_LITELLM_HOSTNAME")
master_key = os.environ.get("LITELLM_KEY")

headers = {
    "Authorization": f"Bearer {master_key}",
    "Content-Type": "application/json"
}
endpoint = f"{url}/chat/completions"

## writing 3 expert problem for finding root cause of crashes



global REPORT_DATA
global POI_STACK_TRACE
@chatgpt_function
def description_of_fix(description: str):
    """
    :param name: description of the fix
    """
    print("source patch: {}".format(description))
    return "Thanks! now call appropritate functions to report the fix"
STOP = False


# @chatgpt_function
# def retry_build():
#     """
#     Call this function after editing all the source code or after calling 'finish_task'.
#     """
#     global STOP
#     STOP = True


EXIT = False


@chatgpt_function
def finish_task():
    """
    Call this funtion once there are no more build errors
    """
    global STOP
    STOP = True


MESSAGES = []


def append_message(msg):
    global MESSAGES
    print_colored_messages([msg])
    MESSAGES.append(msg)


def try_make_file(make_file_dir):
    cur_dir = os.getcwd()
    os.chdir(make_file_dir)
    os.system("make clean")
    # os.system("make > output.txt 2>&1")
    # instead, use subprocess so we can get the return code
    p = subprocess.Popen(["make"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # get the interleaved output and error
    output, err = p.communicate()
    retcode = p.returncode
    with open("output.txt", "w") as f:
        f.write(
            f"""
# Build status
Return Code: {retcode}
Build succeeded: {retcode == 0}

# Stdout
```{output.decode("utf-8")}```
# Stderr
```{err.decode("utf-8")}```
"""
        )
    subprocess.check_call(["make", "clean"])
    os.chdir(cur_dir)
    return retcode


def main(
    input_file_path: Path, src_root_path: Path, binary_path: Path, output_path: Path, poi_report: Path, functions_file_path: Path, functions_dir: Path, is_argv: bool = False, remote: str = None):
    for path_arg in [input_file_path, src_root_path, binary_path, poi_report, functions_file_path, functions_dir]:
        assert os.path.exists(path_arg)

    chatgpt_functions.IS_ARGV = is_argv
    chatgpt_functions.GDB_REMOTE = remote
    
    set_globals(src_root_path, binary_path, output_path, is_argv, remote)
    print("Set the globals ✅")
    chatgpt_functions.set_input_data(input_file_path)
    print("Set the globals ✅")
    ret = generate_function_list(functions_dir)
    print("Generating stack trace from poi report .... ⏰")
    crashing_function_signature, src_file, crashing_func_start_line, filtered_trace = extract_stack_trace_from_poi(poi_report)
    print("Got the stack trace ✅")
    
    crashing_function_path = os.path.join(src_root_path, src_file)
    
    crashing_function_src_dict = fetch_function_source_using_signature(function_signature=crashing_function_signature, file_path=crashing_function_path,line_number=crashing_func_start_line)
    if "error" in crashing_function_src_dict:
        print("Failed to fetch the crashing function source 😞")
        print("ERROR MESSAGE: {}".format(crashing_function_src))
        crashing_function_src_dict = {}
        exit(1)
    else:
        crashing_function_src = format_srcdict_to_str(crashing_function_src_dict, crashing_function_signature)
        print("Crashing function source fetched ✅")
    
    SRC_ROOT_PATH = src_root_path

    #crashing_input = chatgpt_functions.get_input_data()
    #crashing_function_src = chatgpt_functions.get_function_source("menu()")
    #crash_report = chatgpt_functions.get_gdb_crash_report()

    available_functions = [
        chatgpt_functions.get_lines_from_src,
        chatgpt_functions.get_function_source,
        chatgpt_functions.get_context_and_registers_between_lines,
        chatgpt_functions.get_context_and_registers_for_function,
        chatgpt_functions.set_break_point_and_get_context,
        chatgpt_functions.propose_root_cause,
        finish_task,
        ]
    #available_functions =  AVAILABLE_FUNCTIONS
    
    crashing_context = get_crash_context()
    #crashing_context = {}
    print("Got the crashing context ✅")

    """
        Arguments to pass:
        1. root_dir: root_directory 
        2. root_directory_structure: directory structure 
        3. source_file_path: path to the source file, from the root path.
        4. crash_line: This is the line number where the crash occurred.
        5. crashing_function_src: This is the source of function where the crash occurred.
        6. crashing_context: This provides information about the state of the program at the time of crash, and includes backtrace, local variables, and register values.
        7. stack_trace: This is the stack trace of the crash. It contains the following info: function, function_name, line_number, and relative_file_path from the source
        8. crashing_input: This is the input that caused the crash.
    """

    INPUT_DATA = get_input_data()
    directory_structure_str =obtain_directory_structure_as_str(SRC_ROOT_PATH)
    
    
    crash_report = { 
        "root_dir": SRC_ROOT_PATH,
        "root_directory_structure": directory_structure_str,
        "source_file_path": src_file,
        "crash_line": crashing_func_start_line,
        "crashing_function_src": crashing_function_src,
        "crashing_context": crashing_context,
        "stack_trace": filtered_trace,
        "crashing_input": INPUT_DATA
        }
    print("crash report: {}".format(crash_report))
    crash_report_str = convert_python_dictionary_to_string(crash_report)
    print("Crash report generated ✅")
    # directory_structure_str = obtain_directory_structure_as_str(SRC_ROOT_PATH)
    SEEN = set()
    STOP = False

    INITIAL_PROMPT = """
    You act as 3 program analysis experts assessing a software application to discover and fix build errors for program analysis tasks.
    The first expert states assumptions and makes conclusions based on their assumptions about the root cause of the error. Then the 3 experts converse, and logically lay out their reasoning for each of their arguments.
    They engage in constructive disagreement, in which the other two experts discuss the validity of expert 1's claims. One expert leans towards agreement, the other towards disagreement. Each of the three experts is willing to concede a point when proven wrong.
    They continue arguing until they eventually reach an agreement, indicating the root cause of the crash and devising a solution to fix it.

    They are initially given with a crash report with the following information:
    1. root_dir: root_directory of the source
    2. root_directory_structure: directory structure of the source
    3. source_file_path: path to the source file
    4. crash_line: This is the line number where the crash occurred.
    5. crashing_function_src: This is the source of function where the crash occurred.
    6. crashing_context: This provides information about the state of the program at the time of crash, and includes backtrace, local variables, and register values.
    7. crashing_input: This is the input that caused the crash.

    The experts are allowed to ask for further analysis to be performed on the program. They can ask for the following information (only when necessary):
    1. Provide a start and end line number in the source file to obtain the context information (the context includes changes in local variables, registers, and backtrace at each line) during the program's execution. This information will be extracted by running a debugger.
    2. Provide a proper function name to obtain execution context at each line of the function. A debugger will extract this information.
    3. Provide a proper function name to get the code of the function.
    4. Provide a start and end line number and the source file to get the source between the lines.

    Once the experts have reached an agreement, they will provide the root cause for the crash in the form of a YAML report and propose a patch to fix the bug.

    Note: There may be 1 or more than 1 root cause for the crash. You need to analyze and point all the root causes.
    """

    INITIAL_PROMPT += "##CRASHING REPORT:\n"
    INITIAL_PROMPT += crash_report_str
   
    append_message({"role": "system", "content": INITIAL_PROMPT})

    current_message_id = 0
    for i in range(20):
        if STOP:
            break

        
        request_dict = dict(model=MODEL,
                        messages=MESSAGES,
                        tools=get_chatgpt_function_schema(available_functions),
                        tool_choice="auto",
                        temperature=0.7,)
        request_data = json.dumps(request_dict)
        
        response = requests.post(endpoint, headers=headers, data=request_data)

        if response.status_code == 200:
            response_dict = response.json()
        else:
            print(f"Failed to perform query: {response.status_code} - \n\n{response.text}")
            continue

        # response_message = response['choices'][0]['message']

        response_message = response_dict['choices'][0]['message']
        if "function_call" in response_message:
            del response_message["function_call"]
        append_message(response_message)
        #import IPython; IPython.embed(); assert False
        if response_message.get("tool_calls"):
            for function_call in response_message["tool_calls"]:
                function_name = function_call["function"]["name"]
                arguments = function_call["function"]["arguments"]

                if (function_name, arguments) in SEEN:
                    append_message({
                        "tool_call_id": function_call["id"],
                        "role": "tool",
                        "name": function_name,
                        "content": "ERROR: You already called this function with these arguments.",
                    })

                    continue

                SEEN.add((function_name, arguments))

                if function_name == "propose_root_cause":
                    PROPOSED_ROOT_CAUSE = True
                elif function_name == "finish_task" and not PROPOSED_ROOT_CAUSE:
                        append_message({
                            "tool_call_id": function_call["id"],
                            "role": "tool",
                            "name": function_name,
                            "content": "ERROR: You must propose a root cause before finishing the task.",
                            "message_id": current_message_id
                        })
                        #current_message_id += 1
                
                    
                
                success, res = call_chatgpt_function(
                        function_name,
                        arguments,
                        prompt_for_confirmation=False,
                        available_functions=available_functions,
                    )
                
                append_message(get_function_call_result_message(
                    function_call['id'], function_name, success, res, current_message_id))
                current_message_id += 1

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root_path", default="root_path", help="Path to root_path which contains all src files")
    parser.add_argument("--poi_report", default="root_path", help="Path to poi report")
    parser.add_argument("--binary_path", default="False", help="Path to binary executable file")
    # We have to figure a way to provide input from some report
    parser.add_argument("--input_file_path", default="False", help="Path to the crashing input")
    parser.add_argument("--output_path", default="False", help="Path to root_path")
    parser.add_argument("--functions_file_path", default="False", help="path to the json containing list of all functions")
    parser.add_argument("--functions_dir", default="False", help="path to the dir where each function from functions_file_path is stored")
    parser.add_argument("--is_argv", action="store_true", default=False, help="If the input is a file")
    parser.add_argument("--gdb_remote", type=str, default=None, help="Remote location of gdb")
    args = parser.parse_args()
    return args





if __name__ == "__main__":
    args = get_args()
    main(input_file_path =args.input_file_path, src_root_path=args.root_path, binary_path=args.binary_path,output_path=args.output_path, poi_report=args.poi_report, functions_file_path=args.functions_file_path, functions_dir=args.functions_dir, is_argv=args.is_argv, remote=args.gdb_remote)
