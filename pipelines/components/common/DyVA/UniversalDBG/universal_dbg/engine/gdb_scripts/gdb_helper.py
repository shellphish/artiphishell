import pprint
from pathlib import Path
import re
import sys

sys.path.append(str(Path(__file__).absolute().parent.parent.parent))

from universal_dbg.debuggers import GDBDebugger



def parse_context_string(context_str):
    """
    param context_str: str - Context string from GDB
    return: dict 
    Parse the context string from GDB and return a dictionary with the extracted information.
    """
    
    lines = context_str.split('\n')
    result = {}
    
    # Extract function
    function_match = re.search(r'Function: (.+)', context_str)
    if function_match:
        result['function'] = function_match.group(1)
    
    # Extract line number and source mapping
    line_match = re.search(r'Line: (\d+)\s+(.+)', context_str)
    if line_match:
        result['line'] = int(line_match.group(1))
        result['src_mapping'] = line_match.group(2).strip()
    
    # Extract local variables
    local_vars = []
    for line in lines:
        var_match = re.match(r'\s*<Variable: (\w+) (\[[^\]]+\]|\w+) (\w+) = (.+)>', line)
        if var_match:
            local_vars.append({
                'name': var_match.group(3),
                'type': f"{var_match.group(1)} {var_match.group(2)}".strip(),
                'value': var_match.group(4)
            })
    result['local_variables'] = local_vars
    
    # Extract backtrace
    backtrace = []
    for line in lines:
        bt_match = re.match(r'\s*<BacktraceLine: (.+)>', line)
        if bt_match:
            backtrace.append(bt_match.group(1))
    result['backtrace'] = backtrace
    
    return result

def get_debugger(binary_path, input_data, remote):
    is_file = False
    try:
        is_file = Path(input_data).exists()
    except:
        pass
    if is_file:
        gdb = GDBDebugger(binary_path, argv=[input_data], remote=remote)
    else:
        gdb = GDBDebugger(binary_path, stdin=input_data, remote=remote)
    return gdb

# If this function exists why is there a need of get_local_variable_and_backtrace???
def get_context_and_registers_between_addresses_helper(start_line: str, end_line: str, input_data: str, binary_path: str, src_path: str, remote: str):
    """
    Retrieves the local variables, registers, and backtrace of the program for each instruction between the specified start and end lines.

    :param start_line: The starting line number of the code segment to analyze.
    :param end_line: The ending line number of the code segment to analyze.
    :param input_data: Input data to provide to the program during execution.
    :param binary_path: Path to the binary file of the program.
    :param src_path: Path to the source file of the program.
    
    :return: A dictionary containing context and register information each instruction in the specified code segment.
    """
    
    gdb = get_debugger(binary_path, input_data, remote)
    gdb.set_breakpoint(f"{src_path}:{start_line}")
    gdb.set_breakpoint(f"{src_path}:{end_line}")
    gdb.run()
    gdb.next()
    
    breakpoints = [hex(addr) for addr in gdb.get_breakpoint_info()][::-1]
    
    all_outputs = {}
    end_addr = breakpoints[0]
    context_info = parse_context_string(str(gdb.context))
    registers_info = str(gdb.register_info)
    all_outputs[start_line] = {"context": context_info, "registers": registers_info}
    for i in range(50):
        instruction_index = int(start_line) + i
        
        # Capture context and registers
        context_info = parse_context_string(str(gdb.context))
        registers_info = str(gdb.register_info)
        all_outputs[instruction_index] = {"context": context_info, "registers": registers_info}
        
        try:
            pc = hex(gdb.program_counter())
            all_outputs[instruction_index]["context"]["program_counter"] = pc
        except Exception as e:
            all_outputs[instruction_index]["context"]["program_counter"] = {
                "action": "debugger crash",
                "exception": str(e)
            }
            break

        # Check if the program counter has reached the end address
        if pc == end_addr:
            break
        
        if i == 49:
            all_outputs[instruction_index + 1] = {
                "exception": "Reached 50 instructions budget. If you want to continue, recall this function with a new start_line and end_line."
            }
            break
        try:
            gdb.next()
        except Exception as e:
            all_outputs[instruction_index + 1] = {
                "exception": str(e)
            }
            break
    
    return all_outputs
    

def get_context_and_registers_for_function_helper(function_name: str, input_data:str, binary_path: str, src_path:str):
    """
    param function_name: str
    param input_data: str
    param binary_path: str
    param src_path: str
    return: dict

    This function is used to get the local variables, registers and backtrace of the program for each instruction of the entire function
    """
    
    print("extracting function src for {}".format(function_name))
    
    function_src = get_function_src(src_path, function_name)
    
    start_line = function_src.split("\n")[0].split(":")[0].split(" ")[1]
    end_line = function_src.split("\n")[-2].split(":")[0].split(" ")[1]
    all_outputs = get_context_and_registers_between_addresses_helper(start_line, end_line, input_data, binary_path, src_path)
    return all_outputs
    
    
def get_function_src(src_path: str, function_signature: str):
    """
    Extract the code of the function with the given signature from the file src_path. Note function signature should be in the form of "function_name()" or "function_name(int a, int b)".
    :param src_path: str - Path to the source file 
    :param function_signature: str - Signature of the function to extract (e.g., "function_name()" or "function_name(int a, int b)"). 
    :return: str - Function code with line numbers, or None if function is not found
    """
    with open(src_path, "r") as f:
        content = f.read()
    
    # Extract function name and parameters
    try:
        function_name, params = re.match(r"(\w+)\s*\((.*?)\)", function_signature).groups()
    except Exception as e:
        return {"error": "Invalid function signature", "message": str(e), "hint": "Function signature should be in the form of 'function_name()' or 'function_name(int a, int b)'"}
    
    # Create a regex pattern for the function declaration
    pattern = rf"(^|\n)\s*(\w+\s+)*{re.escape(function_name)}\s*\({re.escape(params)}\)\s*{{?"
    
    match = re.search(pattern, content, re.MULTILINE)
    if not match:
        ## Now we try to do the match based on just function_name without arguments and paranthesis
        lines = content.split("\n")
        lines_to_take = []
        for i, line in enumerate(lines):
            if function_name in line and '(' in line and ')' in line:
                lines_to_take.append(line)
        if len(lines_to_take) == 0:
            return "{'error': 'Function not found'}"
        else:
            return_dict = {"error": "Function not found", "all_keyword_matches": lines_to_take, "message": "Function not found, but found keyword matches, maybe try again with proper function signature, eg. if function takes argument, then instead of 'function_name()', pass 'function_name(int a, int b)' as function_signature"}
            return str(return_dict)
        
    
    start = match.start()
    
    # Find the end of the function
    brace_count = 0
    end = start
    for i, char in enumerate(content[start:], start):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                end = i + 1
                break
    
    if brace_count != 0:
        #function_code = "Maybe an incomplete function\n"
        function_code = content[start:end]
        lines = function_code.splitlines()
        while lines and not lines[0].strip():
            lines.pop(0)
            start += 1
        start_line = content[:start].count('\n') + 1
        formatted_lines = [f"line {i}:\t{line}\n" for i, line in enumerate(lines, start_line)]
        formatted_function = "".join(formatted_lines)
        formatted_function = "Maybe incomplete function\n" + formatted_function
        print("Function maybe incomplete")
        return formatted_function  
    
    function_code = content[start:end]

    # Remove leading empty lines and get the actual start of the function
    lines = function_code.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
        start += 1
    
    # Calculate the correct starting line number
    start_line = content[:start].count('\n') + 1
    
    # Format lines with line numbers and a tab
    formatted_lines = [f"line {i}:\t{line}\n" for i, line in enumerate(lines, start_line)]
    formatted_function = "".join(formatted_lines)
    return formatted_function


def get_line_src(src_path: str, start_line: str, end_line: str):
    start_line = int(start_line)
    end_line = int(end_line)
    #src_path = Path(__file__).absolute().parent.parent.parent.parent / "tests/c/crashing_progs/buffer_overflow/prog.c"
    #src_path = "/home/clasm/projects/aixcc/shellphish-crs/pipelines/components/common/DyVA/UniversalDBG/tests"

    """
    Extract the code between the given start and end line numbers from the file src_path.
    
    :param src_path: str - Path to the source file
    :param start_line: int - Starting line number
    :param end_line: int - Ending line number
    :return: str - Code snippet with line numbers
    """
    with open(src_path, "r") as f:
        content = f.read()
    
    lines = content.split("\n")
    start_line -= 1  # Adjust for 0-based indexing
    end_line -= 1
    
    if start_line < 0 or start_line >= len(lines) or end_line < 0 or end_line >= len(lines):
        return "Invalid line numbers"
    
    snippet = lines[start_line:end_line + 1]
    formatted_lines = [f"line {i + 1}:\t{line}\n" for i, line in enumerate(snippet, start_line + 1)]
    formatted_snippet = "".join(formatted_lines)
    return formatted_snippet

def set_breakpoint_and_get_context(src_path: str, line_number: int, binary_path: str, input_data: str, remote: str):
    """
    param src_path: str
    param line_number: int
    param binary_path: str
    param input_data: str
    return: dict

    This function is used to set a breakpoint at the given line number and get the context and registers of the program at that point
    """
    
    gdb = get_debugger(binary_path, input_data, remote)
    gdb.set_breakpoint(f"{src_path}:{line_number}")
    gdb.run()
    context_info = parse_context_string(str(gdb.context))
    registers_info = str(gdb.register_info)
    gdb.continue_execution()
    return {"context": context_info, "registers": registers_info}
    

def crash_and_get_context(binary_path: str, input_data: str, remote: str):
    """
    param binary_path: str
    param input_data: str
    return: dict

    This function is used to crash the program and get the context and registers of the program at that point
    """
    print("correct")
    
    gdb = get_debugger(binary_path, input_data, remote)
    print('running gdb')
    gdb.continue_execution()
    context_info = parse_context_string(str(gdb.context))
    registers_info = str(gdb.register_info)
    return {"context": context_info, "registers": registers_info}
