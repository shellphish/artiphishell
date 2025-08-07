import subprocess
import tiktoken
import pathlib
import difflib
import logging
import random
import time
import json
import yaml
import re
import os

os.chdir(os.path.dirname(__file__))

from config import *
from agentlib import (
    Agent, PlanExecutor,
    AgentResponse,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    CriticReview, WebConsoleLogger
)
from shellphish_crs_utils.utils_grammar_guy.coverage import collect_coverage_in_docker, generate_coverage_report, print_goodboi, print_info, print_warn
from agentlib import enable_event_dumping, set_global_budget_limit
from itertools import repeat

enc = tiktoken.encoding_for_model("gpt-4o")

    # TODO make this file automatically read depending on target
    # TODO parse coverage files by splitting on | taking 0 as line number, 1 as hitcount and rest as "line_content"
    # TODO retrieve the generated coverage file as "function coverage" and diff it with the previous iteration
    # TODO add retrieval of allowlist and write relevant functions to allowlist

  
class SimpleChatCompletion(Agent[dict,str]):
    # Choose a language model to use (default gpt-4-turbo)
    #__LLM_MODEL__ = 'claude-3-sonnet'    
    __LOGGER__ = logging.getLogger('SimpleChatCompletion')
    __LOGGER__.setLevel('ERROR')
    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        return vars
    
BASIC_PLAN = AgentPlan(steps=[
      AgentPlanStep(
          description='Analyze the source code and identify the conditions that need to be met in order to reach the target line.'),
      AgentPlanStep(description='Evaluate the coverage dictionary to determine where the program stalls or fails checks necessary for reaching the target line.'),
      AgentPlanStep(description='Based on the results of the previous tasks, derive a new Antlr4 grammar that incorporates all the necessary and optional improvements towards hitting the target line.',),
      # AgentPlanStep(description='Document the changes made to the grammar and the rationale behind them for future reference and maintenance.'),
])

# the actual planExecutor
class RefinementExecutor(PlanExecutor[str, str]):
    # All the same config and overrides are available from Agent
    # Here are the new ones
    # Max times a step can be attempted before failing
    __MAX_STEP_ATTEMPTS__ = 2
    __SYSTEM_PROMPT_TEMPLATE__ = 'refine_agent.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'refine_agent.user.j2'
    counter: int = 0

    # Similar to Agent.get_input_vars, but includes the current step as context
    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        vars = super().get_step_input_vars(step)
        # Can add vars like this. vars["some_thing"] = self.some_thing
        vars['goal'] = 'Adjust the current antlr4 grammar such that it improves upon the existing one and is able to reach the target line. Serve it starting with ```antlr and ending with ```'
        return vars

    def extract_final_results(self) -> str:
        return self.plan.steps[-1].attempts[-1].result

    # Override this function to determine if the step has been completed
    def validate_step_result(self, step: AgentPlanStep, attempt: AgentPlanStepAttempt, result) -> bool:
        # Here we can perform validation on the result of the step
        # If we return False, the agent will retry the step with our feedback
        if step.name == 'generate_new_grammar_step':
            gen_flag = generate_input()
            if gen_flag[0] == -1:
                attempt.critic_review = CriticReview(success=False, feedback=f"The input generation failed with the error: {gen_flag[1]}. Please analyze the error message and fix the grammar accordingly.")
                return False
        return super().validate_step_result(step, attempt, result)
    
    def on_step_success(self, step: AgentPlanStep, res: AgentResponse):
        print(f"Step {step} succeeded with {res}")
        super().on_step_success(step, res) # needed to trigger next step

def setup_simple_agent(system_prompt_template:str = 'init.system.j2', user_prompt_template:str = 'init.user.j2', llm_model:str = 'gpt-4o'):
    ''' Initialize OpenAI client with API key
    :return: OpenAI client
    :rtype: OpenAI
    '''
    agent = SimpleChatCompletion(__SYSTEM_PROMPT_TEMPLATE__ = system_prompt_template,
    __USER_PROMPT_TEMPLATE__ = user_prompt_template, __LLM_MODEL__ = llm_model)
    agent.use_web_logging_config(clear=True)
    return agent

def read_grammar(grammar_file_path):
    ''' Reads file and hands it to split_grammar_from_message
    :param str grammar_file_path: path to the file containing the grammar
    :return: grammar string or None if not found'''
    assert(os.path.isfile(grammar_file_path))
    
    # print(f"READING GRAMMAR FROM {grammar_file_path}")
    grammar=""
    with open(grammar_file_path, "r") as f:
        try:
            grammar = f.read()
        except Exception as e:
            print("Could not read grammar file")
            raise AssertionError(f"Grammar not found @ {grammar_file_path}")
    return split_grammar_from_message(grammar)

def split_grammar_from_message(grammar: str):
    ''' Splits the grammar from the given string
    :param str grammar: the grammar string
    :return: the grammar string or None if not found
    '''
    split_grammar: list = grammar.split("```antlr")
    if 'grammar spearfuzz' not in grammar: 
        raise AssertionError(f"Grammar not found in grammar string {grammar}")
    
    grammar: str=""
    for i in split_grammar:
        if f"grammar spearfuzz" in i:
            grammar = i
    
    return grammar.split("```")[0]

def find_function_in_source_str(source_str, function_name, file_ending) -> str:
    '''
    Uses regex to find the function start and end in the source string.
    :param str source_code: the source code string
    :param str function_name: the name of the function to find
    :param str file_ending: the file extension to determine the parsing strategy
    :return: the source code of the function or None if not found
    '''
    if file_ending == "c":
        function_signature_pattern = re.compile(
            rf'(?P<return_type>\w[\w\s\*]*)\s+(?P<name>{function_name})\s*\((?P<params>[^)]*)\)\s*\{{',
            re.VERBOSE
        )
    elif file_ending == "txt":
        function_signature_pattern = re.compile(
            rf'{function_name}:\n\s*\d+\|\s*\d+\|\{{(?P<function_body>.*?)\d+\|\s*\d+\|\}}',
            re.DOTALL
        )
    else:
        raise AssertionError("File ending not supported - this might break")

    pos = 0
    while True:
        match = function_signature_pattern.search(source_str, pos)
        if not match:
            break

        if file_ending == "c":
            start_index = match.start()
            end_index = match.end()
            brace_count = 1
            for i in range(end_index, len(source_str)):
                if source_str[i] == '{':
                    brace_count += 1
                elif source_str[i] == '}':
                    brace_count -= 1

                if brace_count == 0:
                    return source_str[start_index:i+1]
        else:  # for 'txt' file ending
            start_index = match.start()
            return source_str[start_index:match.end()]

        pos = match.end()

    raise AssertionError("This would be none. We dont want none anywhere")
                
def retrieve_function_src(filepath, function_name:str) -> str:
    ''' Opens src file and feeds it to find_function_in_source_str
    :param str filepath: the path to the target program
    :param str function_name: the name of the function to retrieve
    :return: the source code of the function
    '''
    with open(filepath, "r") as f:
        source_code = f.read()
        
    if len(source_code) == 0:
        AssertionError(f"Could not read source code @ {str(filepath)}")
    source = find_function_in_source_str(source_code, function_name, str(filepath).split(".")[-1])
    if source is None:
        print(f"Function '{function_name}' at {str(filepath)}' not found.")
    return source

def write_to_file(filepath, filename:str, content:str , write_mode:str = "w+") -> None:
    ''' Write content to a file
    :param str filepath: path to file to write to
    :param str content: content to write to the file
    :param str write_mode: the write mode to use (default: "w+")
    '''
    print_info(f"GG (write_to_file): Writing {filename} @ {filepath}")
    if not os.path.exists(str(filepath)):
        print_info(f"GG: Creating directory in write_file: {str(filepath)}")
        os.makedirs(str(filepath))
    
    with open(str(filepath) + f"/{filename}", write_mode) as f:
        try:
            f.write(content)
            f.close()
        except Exception as e:
            raise IOError(f"Could not write to file {filename} @ {filepath} \n Exception {e}")
    
def diff_function_coverage(function_cov_paths: tuple) -> str:
    ''' Get tuple of paths for old and new coverage files and diffs the files in the directory
    '''
    if function_cov_paths[1] == "Initial iteration":
        print("No previous coverage to diff with")
        return {'No previous coverage': 'Initial Iteration'}
    assert(os.path.exists(function_cov_paths[0])) 
    assert(os.path.exists(function_cov_paths[1]))
    
    num_old = len(os.listdir(function_cov_paths[0]))
    num_new = len(os.listdir(function_cov_paths[1]))
    
    old_path = function_cov_paths[0]
    new_path = function_cov_paths[1]
    
    # changed to list to make handling easier
    diff_list = []
    if num_old != num_new:
        print('Rethink your life if this case appears. You can apparently not read code.')
            
    for old_file in os.listdir(old_path):
        for new_file in os.listdir(new_path):
            if old_file == new_file:
                with open(old_path + f"/{old_file}", "r") as old_f:
                    with open(new_path + f"/{new_file}", "r") as new_f:
                        # fix when time at hand. Just sticked to the example.
                        old_lines = old_f.read()
                        new_lines = new_f.read()
                        old_lines = re.sub(r'\x1b\[.*?m', '', old_lines)
                        new_lines = re.sub(r'\x1b\[.*?m', '', new_lines)

                        line_diff = difflib.ndiff(old_lines.splitlines(keepends=True), new_lines.splitlines(keepends=True))
                        line_diff = ''.join(line_diff)

                        diff_list.append(line_diff)
    return diff_list      

def log_grammar_changes():
    ''' Log the changes made to the grammar of "target"
    :param str target: the name of the target whose grammar changes shall be logged
    :return: None
    '''
    try: 
        subprocess.run(['./scripts/log_changes.sh', str(grammar_path())], cwd=gg_source(), check=True)
    except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")
            print(f"Standard Error: {e.stderr}")
            raise e

def wrap_message_body(new_info_from_coverage: list) -> dict:
    ''' Wrap the new information from coverage in a message body
    :param list new_info_from_coverage: the new information to wrap
    :return: a dict containing the wrapped information
    :rtype: dict
    '''
    message_body = {
        "role": "user",
        "content": f"{new_info_from_coverage}"
    }
    return message_body

def split_coverage_file_by_function(split_triple, iteration):
    ''' Receives a triple of (path, start_line, end_line)
        Extract the function coverage from the file @ path using these lines
    '''
    path = split_triple[0]
    start_line = split_triple[1]
    end_line = split_triple[2]
    with open(path, 'r') as f:
        # dropping first five lines until lines contain. Only indicate report and file path
        lines = f.readlines()[start_line-1:]
        function_coverage = []
        for line in lines:
            current_split = line.split('|')[0].strip()
            if int(current_split) >= start_line and int(current_split) < end_line:
                function_coverage.append(line)
                if int(current_split) == (end_line-1):
                    break

        write_to_file(coverage_path() / str(iteration) / 'functions', f"{str(path.stem)}.txt", "".join(line for line in function_coverage))
    
def parse_stack_strace(stack_trace:str, flag:str) -> list:
    ''' Parse crash report into list of function names of called functions to crash
    :param str stack_trace_path: the stack trace file
    :parmar str flag: indicates the kind of trace handed in (osscrash or functions)
    :return: list of called function_names + path
    :rtype: list of tuples
    '''
    if (flag == 'osscrash'):
        block_pattern = re.compile(r'SCARINESS:.*?DEDUP_TOKEN:', re.DOTALL)
        block_match = block_pattern.search(stack_trace)
        if block_match:        
            block_text = block_match.group(0) 
            line_regex = re.compile(r'#\d+.*')
            numbered_lines = line_regex.findall(block_text)
            function_list = []
            for line in numbered_lines:
                split = line.split(" ")
                function_list.append(split[-2]) # (function name)
            return function_list
        else:
            raise AssertionError("Could not parse stack trace")    
    elif (flag == "functions"):
        line_regex = re.compile(r'#\d+.*')
        numbered_lines = line_regex.findall(stack_trace)
        function_list = []
        for line in numbered_lines:
            split = line.split(" ")
            function_list.append(split[-2]) # (function name)
        return function_list
    else:
        raise AssertionError("Flag not recognized")
 
def retrieve_source_from_index(function_name: str) -> str:
    fun_source = ""
    with open(str(functions_index_path()), 'r') as f:
        function_index = json.loads(f.read())
        for key in function_index.keys():
            if function_name in key:
                path_to_json_file = str(jsons_dir_path() / function_index[key])
                with open(path_to_json_file, 'r') as f2:
                    function_info_dict = json.loads(f2.read())
                    fun_source = function_info_dict['code']
    
    # print(f"GG: Function source retrieved from index: {fun_source}")      
    return fun_source    

'''def refine_grammar(fuzz_function_paths, base_function_name, target_function_name) -> str:
    with open(str(harness_info_path()), 'r') as f:
        harness_info = yaml.load(f, Loader=yaml.FullLoader)    
        
    harness_bin_path_relative = pathlib.Path(harness_info['cp_harness_binary_path'])
    initial_grammar = read_grammar(str(grammar_path() / 'spearfuzz.g4'))
    old_grammar = initial_grammar
    new_grammar = initial_grammar
    
    print(f"GG: Starting Loop for grammar improvement {base_function_name} -> {target_function_name}")
    for i in range(1, int(iterations()) + 1):
        # new_grammar = read_grammar(str(grammar_path() / 'spearfuzz.g4'))

        generate_input(num_input(), grammar_path(), generated_inputs_path(), gg_source())
        collect_coverage_in_docker(harness_bin_path_relative)
        generate_coverage_report(i, harness_bin_path_relative, target_source_path())
        
        # In order for this to work as intended, all scoped functions must be in the allowlist.        
        assert(os.path.exists(str(target_source_path() / f'{fuzz_function_paths[0]}')))
        assert(os.path.exists(str(target_source_path() / f'{fuzz_function_paths[1]}')))
        
        base_function_src_path = target_source_path() / fuzz_function_paths[0]
        target_function_src_path = target_source_path() / fuzz_function_paths[1]
        
        # split coverage files
        split_coverage_file_by_function(base_function_src_path, i)
        split_coverage_file_by_function(target_function_src_path, i)
        
        # split_coverage_file_by_functi on(grammar_path(), i)
        function_coverage_dict = "" #parse_split_function_reports(coverage_path() / f'{i}' / 'functions/')
        
        # iterate through all subfolders of coverage_path, find txt files and add them to covered_function list
        for dir_entry in coverage_path().iterdir():
            if dir_entry.is_dir():
                for txt_file in dir_entry.iterdir():
                    if txt_file.is_file():
                        strippd = txt_file.stem
                        if strippd == base_function_name or strippd == target_function_name:
                            function_coverage_dict.update({
                                f"{strippd}": parse_coverage_file(str(txt_file))
                                })
            elif dir_entry.is_file():
                strippd = dir_entry.stem
                if strippd == base_function_name or strippd == target_function_name:
                    function_coverage_dict.update({f"{strippd}": parse_coverage_file(str(dir_entry))})
       
        print('GG: Function coverage dict: \n', function_coverage_dict)
        base_function_source = retrieve_source_from_index(base_function_name)
        target_function_source = retrieve_source_from_index(target_function_name)

        print(f"GG: Base function source: {base_function_source}")
        print(f"GG: Target function source: {target_function_source}")
        
        # This is where the plan stuff starts
        basic_plan = BASIC_PLAN.save_copy()
        grammar_agent: RefinementExecutor = RefinementExecutor(
            plan=basic_plan
        )

        grammar_agent.use_web_logging_config()
        response = grammar_agent.invoke(input=dict(goal="Improve the current grammar so that it hits the target function",
                                                    old_grammar=str(old_grammar),
                                                    function_coverage_dict=str(function_coverage_dict), 
                                                    base_function_source=str(base_function_source),
                                                    target_function_source=str(target_function_source)
                                                   )
                                        )
        
        previous_response = response
        write_to_file(grammar_path(), "new_grammar.tmp", previous_response)
        if len(previous_response) > 0:
            new_grammar = read_grammar(str(grammar_path() / "new_grammar.tmp"))
            write_to_file(grammar_path(), 'new_grammar.g4', new_grammar)
            old_grammar = new_grammar
            log_grammar_changes()
            print(f"\033[94m NEW Grammar \n {response} \u001b[0m")
            print(f"\033[92m Grammar changes logged, iteration complete\u001b[0m")
        else:
            print(f"\u001bALAAAAARM!! Empty response for iteration\u001b[0m")
            
        # if int(function_coverage_dict[target_function_name][line]['hitcount']) != 0:
        #     print(f"\033[92mTarget line {line} reached in iteration {i} with hitcount {function_coverage_dict[target_function_name][line]['hitcount']}\u001b[0m")
        #     break
        
        # TODO How the frickedy frog do we determine if function was hit? Chceking hitcount can not be the actual solution. Maybe checking hit count
        # for a certain line in the function specific coverage report?  

def parse_split_function_reports(split_report_folder) -> list:
   
    # Given a folder that contains split coverage format=text reports, parse them into a list of dictionaries
    # :param split_report_folder: the folder containing the split reports
    # :return: a list of dictionaries containing the parsed split reports
    
    function_coverage_dict = {}
    print_info("GG: Parsing split function reports")
    for file in os.listdir(split_report_folder):
        with open(split_report_folder / file, 'r') as f:
            lines = f.read().split('\n')
            fun_name_pattern = re.compile(r'\d+\|\s*\|.+\(.+\)')
            # match the pattern for function name and store 
            fun_name = lines[0].split(':')[0].replace(":", "") # TODO: anschauen funktionen namen splitten
            for line in lines[1:]:
                split_line = line.split("|")
                if len(split_line) > 2:
                    function_coverage_dict[fun_name] = {
                        split_line[0].strip(): {
                            "hitcount": split_line[1].strip(),
                            # "source_code": split_line[2:]
                            }
                }
    return function_coverage_dict

def this_is_to_go_even_further_beyooooooond(fuzz_function_paths, base_function_name, target_function_name, fun_index: dict) -> str:
    assert(os.path.exists(str(target_source_path()) / f'{fuzz_function_paths[0]}'))
    assert(os.path.exists(str(target_source_path()) / f'{fuzz_function_paths[1]}'))
    
    # given paths are relative (e.g. what we get from the index)
    with open(str(harness_info_path()), 'r') as f:
        harness_info = yaml.load(f, Loader=yaml.FullLoader)    
    harness_bin_path_relative = pathlib.Path(harness_info['cp_harness_binary_path'])
    initial_grammar = read_grammar(str(grammar_path() / 'spearfuzz.g4'))
    old_grammar = initial_grammar
    new_grammar = initial_grammar
    
    print(f"GG: Starting Loop for grammar improvement {base_function_name} -> {target_function_name}")
    for i in range(1, int(iterations()) + 1):
        # create new input and check if it is valid. If not refine grammar. 
        generate_response = generate_input(num_input(), grammar_path(), generated_inputs_path(), gg_source())
        correct_me = initial_grammar
        while generate_response[1] == 1:
            # TODO: Maybe add limit to how often this is done before we stop? Fail safe against infinite loop?
            correct_grammar(correct_me, generate_response[0])
            correct_me = read_grammar(grammar_path() / 'spearfuzz.g4')
            generate_response = 0
            generate_response = generate_input(num_input(), grammar_path(), generated_inputs_path(), gg_source())
        
        # TODO: needs to remove the previous coverage files, make sure all
        collect_coverage_in_docker(harness_bin_path_relative)
        generate_coverage_report(i, harness_bin_path_relative, target_source_path())
        
        # In order for this to work as intended, all scoped functions must be in the allowlist.        
        print("GG: Function source path @ 0", str(target_source_path() / f'{fuzz_function_paths[0]}'))
        print("GG: Function source path @ 1", str(target_source_path() / f'{fuzz_function_paths[1]}'))
        assert(os.path.exists(str(target_source_path() / f'{fuzz_function_paths[0]}')))
        assert(os.path.exists(str(target_source_path() / f'{fuzz_function_paths[1]}')))
        
        base_function_src_path = target_source_path() / fuzz_function_paths[0]
        target_function_src_path = target_source_path() / fuzz_function_paths[1]
        
        # split coverage files
        base_split_path = coverage_path() / str(i) / "coverage" / "tmp" / f"{str(fun_index[base_function_src_path]['filepath'])}.txt"
        src_split_path = coverage_path() / str(i) / "coverage" / "tmp" / f"{str(fun_index[target_function_src_path]['filepath'])}.txt"
        print(f"GG: Splitting coverage files after run: {base_split_path} and {src_split_path}")
        
        split_coverage_file_by_function(base_split_path, i)
        split_coverage_file_by_function(src_split_path, i)
        print_goodboi("GG: SPLITTOOOOO")
        function_coverage_dict = parse_split_function_reports(coverage_path() / f'{i}' / 'functions/')
        
        print('GG: Function coverage dict: \n', function_coverage_dict)
        base_function_source = fun_index[base_function_name]['code']
        target_function_source = fun_index[target_function_name]['code']
        scoped_fun_dict = {function_coverage_dict[base_function_name], function_coverage_dict[target_function_name]}
        
        print_goodboi("GG: Base function source: ", base_function_source)
        print_goodboi("GG: Target function source: ", target_function_source)
        print_goodboi("GG: Scoped functions: ", scoped_fun_dict)
        
        # This is where the plan stuff starts
        basic_plan = BASIC_PLAN.save_copy()
        grammar_agent: RefinementExecutor = RefinementExecutor(
            plan=basic_plan
        )
        grammar_agent.use_web_logging_config()
        response = grammar_agent.invoke(input=dict(goal="Improve the current grammar so that it hits the target function",
                                                    old_grammar=str(old_grammar),
                                                    function_coverage_dict=str(function_coverage_dict), 
                                                    base_function_source=str(base_function_source),
                                                    target_function_source=str(target_function_source)
                                                   )
                                        )
        write_to_file(grammar_path(), 'new_grammar.tmp', response) # maybe response.value
        print(f"This is the temp path for the new grammar: {str(grammar_path() / 'new_grammar.tmp')}")
        if len(response) > 0:
            new_grammar = read_grammar(str(grammar_path() / 'new_grammar.tmp'))
            write_to_file(str(grammar_path()  / 'new_grammar.g4'), new_grammar)
            old_grammar = new_grammar
            log_grammar_changes()
            print_goodboi(f"NEW Grammar \n {response}")
            print_goodboi(f"Grammar changes logged, iteration complete")
        else:
            print_warn(f"ALAAAAARM!! Empty response for iteration")
            
        for i in function_coverage_dict[target_function_name].keys():
            if int(function_coverage_dict[target_function_name][i]['hitcount']) != 0:
                print_goodboi(f"Target line {i} reached in iteration {i} with hitcount {function_coverage_dict[target_function_name][i]['hitcount']}")
                return old_grammar
    
def shoot_for_the_moon(list_of_functions: list, harness_bin_path_relative: pathlib.Path, fun_index):
    # Shoot for the moon - aim for the stars. 
    #   This will do things that need doing.
    
    save_init_grammar = read_grammar(grammar_path() / 'spearfuzz.g4')
    generate_response = generate_input(num_input(), grammar_path(), generated_inputs_path(), gg_source())
    correct_me = save_init_grammar
    while generate_response[1] == 1: 
        correct_grammar(correct_me, generate_response[0])
        correct_me = read_grammar(grammar_path() / 'spearfuzz.g4')
        generate_response = 0
        generate_response = generate_input(num_input(), grammar_path(), generated_inputs_path(), gg_source())        
    
    # collect coverage
    set_allowlist(list_of_functions)
    collect_coverage_in_docker(harness_bin_path_relative)
    generate_coverage_report(0, harness_bin_path_relative, target_source_path())
    
    # gather list of paths for the functions source files (unique)
    covered_function_names = []
    list_of_fucking_death = []
    fun_path_list_for_splitting = []
    for function_name in list_of_functions:
        start_of_fun = fun_index[function_name]["start_line"]
        end_of_fun = fun_index[function_name]["end_line"]
        fun_path = coverage_path() / str(0) / "coverage" / "tmp" / f"{str(fun_index[function_name]['filepath'])}.txt"
        if os.path.exists(fun_path):
           fun_path_list_for_splitting.append((fun_path, start_of_fun, end_of_fun))
        else:
           print_warn(f"Skipping for: {function_name}")
           list_of_fucking_death.append(str(fun_path))

    fun_path_list_for_splitting = list(set(fun_path_list_for_splitting))
    list_of_fucking_death = list(set(list_of_fucking_death))
    print_warn(f"List of death: {list_of_fucking_death}")

    # split files in paths from above by function
    for triple in fun_path_list_for_splitting:
        split_coverage_file_by_function(triple, 0)

    # create coverage dict from split function files in path below and determine if they were hit
    # TODO: coverage dir parsing borken - fix
    print_warn(f"IF THIS IS EMPY U FKDUP: {os.listdir(coverage_path() / f'{0}' / 'functions/')}")
    function_coverage_dict = parse_split_function_reports(coverage_path() / f'{0}' / 'functions/')
    for fun_name in function_coverage_dict.keys(): 
        sub_dict = function_coverage_dict[fun_name]
        for lines in sub_dict.keys():
            if str(sub_dict[lines]['hitcount'].strip()) != "0" and fun_name in list_of_functions:
                covered_function_names.append(fun_name)
    print_info(f"GG: Function coverage dict: \n {function_coverage_dict}")
    return
    # Starting with the shot to the moon
    # ACTUALLY
    covered_base_function_names = [] # all the functions used as base functions
    functions_to_hit = list_of_functions
    if len(covered_function_names) == 0: 
        print("GG: MOON: WE fkd!")
        return
    else: 
        print(f"GG: MOON: Base function {base_function_name} and covered_function_names {covered_function_names}")
        base_function_name = random.choice(covered_function_names)
    it_count = 0
    
    # we have covered_function_names, list_of_functions and fun_index 
    print("ENTERING THE REALM OF POSSIBLITIES - THE MOON")
    while(len(functions_to_hit) > 0):
        print("GG: MOON: Remaining", len(functions_to_hit))
        # get new reachable functions from base function source
        in_reach_of_base_function = []
        for function in list_of_functions:
            if function in fun_index[base_function_name]["code"]:
                in_reach_of_base_function.append(function)

        if len(in_reach_of_base_function) == 0:
            # need new base function - select from covered_function_names
            non_used_bases = list(set(covered_function_names).difference(set(covered_base_function_names)))
            print("GG: Non used bases: ", non_used_bases)
            if len(non_used_bases) == 0:
                print("GG: MOON: No more bases available. Returning")
                return
            covered_base_function_names.append(base_function_name)
            base_function_name = random.choice(non_used_bases)
            covered_base_function_names.append(base_function_name)
            print(f"GG: Base function could not reach. Selected new base function to {base_function_name}")
            continue
            
        # check which functions are relevant and can be hit
        hit_from_base_function = list(set(functions_to_hit) & set(in_reach_of_base_function))
        print(f"GG: Functions that are relevant and can be hit: ", len(hit_from_base_function))        
        
        # Do this for every functino that CAN be hit from my current base function. 
        # GOAL: Get coverage on all functions that can be hin from base function. Incrementally return adjusted grammar and if function was hit.
        while(len(hit_from_base_function) > 0):
            print(f"GG: MOON: Hitting the base function: {base_function_name}, n={len(hit_from_base_function)}")
            target_function_name = hit_from_base_function.pop()
            base_function_source_path = fun_index[base_function_name]["code"]
            target_function_source_path = fun_index[target_function_name]["code"]
            
            # grammar needs to be written to spearfuzz.g4 in grammar_path() / spearfuzz.g4
            it_count += 1
            step_grammar = this_is_to_go_even_further_beyooooooond((base_function_source_path, target_function_source_path), base_function_name, target_function_name, fun_index)
            if step_grammar == "Could not hit target function":
                # for now just ignore and assume that there is another path to find coverage for this function
                print("GG: Could not hit target function")
            else:
                print("GG: Grammar improved")
                write_to_file(str(grammar_path(), f'{it_count}_grammarimprov.g4'), step_grammar)
                covered_function_names.append(target_function_name)
                functions_to_hit.remove(target_function_name)
                
        # use new base function from the ones that were already covered.
        if len(functions_to_hit) > 0:
            non_used_bases = list(set(covered_function_names).difference(set(covered_base_function_names)))
            print("GG: Non used bases: ", non_used_bases)
            if len(non_used_bases) == 0:
                print("GG: MOON: No more base available. Done?")
                return
            covered_base_function_names.append(base_function_name)
            base_function_name = random.choice(in_reach_of_base_function)

        print(f"GG: MOON: Iteration complete, covered function names: {covered_function_names} and new base function {base_function_name}")
        print("GG: MOON: Remaining functions to hit: ", functions_to_hit)

    print("GG: SHOOT FOR THE MOON: All functions hit. Returning")
'''

def check_token_limit(llm_arguments: list, token_limit= 110000): 
    '''Does not return grandma if tokenlimit exceeded
    :return: not a grandma
    '''
    encoded_source = enc.encode_batch(llm_arguments)
    if len(encoded_source) > token_limit:
        print_warn(f"GG (check_token_limit): Token limit exceeded - got {len(encoded_source)} tokens")
        return "Not a grandma"
    else:
        print_info(f"GG (check_token_limit): Token limit not exceeded - got {len(encoded_source)} tokens")
        return "This is a grandma"
    
def correct_grammar(broken_grammar:str, error_message:str):
    ''' Correct the grammar based on the error message
    :param str broken_grammar: the broken grammar as string
    :param str error_message: the error message as string
    :return: the corrected grammar'''
    
    print_info(f"GG (correct_grammar): Correcting grammar based on error message {error_message}") 
    # But are you a grandma ? 
    limit_flag = check_token_limit([broken_grammar, error_message])
    if limit_flag == "Not a grandma":
        # No
        print_warn("GG (correct_grammar): Token limit exceeded. Skipping grammar correction.")
        write_to_file(grammar_path(), 'spearfuzz.g4', broken_grammar)
        return broken_grammar
    # Yes
    correct_grammar_agent = setup_simple_agent(system_prompt_template='grammar_correct.system.j2', user_prompt_template='grammar_correct.user.j2')
    correct_grammar_agent.use_web_logging_config()
    response = correct_grammar_agent.invoke(input=dict(
                                                        myquestion=f"Please fix the grammar. Adjust the rules based on the given error message to make the grammar valid and parsable.",
                                                        broken_grammar=broken_grammar,
                                                        error_message=error_message
                                            ))
    if response.value == None: 
        raise AssertionError("Grammar correction response must not be none")
    write_to_file(grammar_path(), 'spearfuzz.g4', response.value)

def copy_inputs_to_grave():
    ''' Move the generated inputs to the grave
    ''' 
    print_info("GG (copy_inputs_to_grave): Moving inputs to shared folder & Removing files.")
    commands = [
                f"cp {str(generated_inputs_path() / '*')} {str(input_final_destination())}/" ,
                f"rm -rf {str(generated_inputs_path() / '*')}",
                f"rm {str(grammar_path() / 'spearfuzz.g4')}"
            ]        
    for cmd in commands:
        # shell true for * comprehension
        run_output = subprocess.run(cmd, cwd=(gg_source()), shell=True, capture_output=True, text=True)
        if run_output.returncode != 0: 
            print_warn(f"GG (copy_inputs_to_grave): Could not copy and remove the files: {str(cmd)} \n {run_output.stderr} \n {run_output.stdout}")
            raise AssertionError(f"Something went wrong when copying and removing the files: {str(cmd)}")
    print_info(f"GG (copy_inputs_to_grave): Inputs successfully moved to grave @ {input_final_destination}")

def one_shot_grammar(function_1_src, function_2_src):
    # 1 is from, 2 is target
    print_info(f"GG (one_shot_grammar): Creating grammar for given function pair.")
    example_grammar_agent = setup_simple_agent(system_prompt_template='grammar_init.system.j2', user_prompt_template='grammar_init.user.j2')
    example_grammar_agent.use_web_logging_config()
    
    # But are you a grandma? 
    token_oversize_flag = check_token_limit([function_1_src, function_2_src])
    if token_oversize_flag == "Not a grandma":
        # No
        return token_oversize_flag
    # Yes
    response = example_grammar_agent.invoke(input=dict(
                                                        myquestion=f"Provide a grammar that is effective for generating inputs that maximize coverage in the two given functions. The goal is to make the grammar as extensive and specific as possible to trigger coverage in the function to hit.",
                                                        harness=function_1_src,
                                                        function_to_hit=function_2_src
                                            ))
    grammar = split_grammar_from_message(response.value)
    log_event("gg_oneshot_grammar", {
        "function_1_src": function_1_src,
        "function_2_src": function_2_src,
        "grammar": grammar,
    })
    if grammar is None: 
        raise AssertionError("Split grammar must not be null")
    return grammar

def gg_is_dumb(list_of_functions, fun_index, harness_src):
    '''
    The dumb version of the grammar generation.
    :param list list_of_functions: the list of functions to hit
    :param dict fun_index: the index of the functions
    :param str harness_src: the source of the harness
    :return: a list of tuples containing the (function name, grammar)
    :return: list(tuples)
    '''
    grammar_stack = []
    print_info(f"GG (gg_is_dumb): function list = {list_of_functions}")
    log_event("gg_is_dumb", {
        "list_of_functions": list_of_functions,
        "num_functions": len(list_of_functions),
        "fun_index": fun_index,
        "harness_src": harness_src
    })
    curr_num = 0
    for target in list_of_functions:
        curr_num += 1
        print_info(f"GG (gg_is_dumb): Rolling with function {target}, {curr_num} out of {len(list_of_functions)} functions")
        if target not in fun_index.keys():
            print_warn(f"GG (gg_is_dumb): Function {target} not in the index. Skipping")
            continue
        target_src = fun_index[target]["code"]
        
        # salvatore would be proud (if not)
        step_grandma = one_shot_grammar(harness_src, target_src)
        # token limit exceeded if not a grandma
        if step_grandma != "Not a grandma": 
            gen_tuple = generate_input_check_grammar(step_grandma, 2)
        else: 
            print(f"GG (gg_is_dumb): Not a grandma. Skipping due to oversized grandma llm seed (should rarely happen)")
            continue
        # success in correction or none needed
        if gen_tuple[1] == 0:
            print_info("GG (gg_is_dumb): Appending generated or fixed grammar.")
            if gen_tuple[0] == None:
                raise AssertionError("Grammar must not be None")
            grammar_stack.append((gen_tuple[0], target))
        else:
            # correction failed
            print_warn("GG (gg_is_dumb): Appending broken grammar to not lose all its information")
            if gen_tuple[0] == None:
                raise AssertionError("Grammar must not be None")
            grammar_stack.append((gen_tuple[0], target))
    return grammar_stack

def merge_grammars(grammar_stack: list) -> str:
    ''' Merge the grammars in the stack into one grammar using llm power
    :param list grammar_stack: the stack of grammars to merge
    :return: the merged grammar
    :rtype: str
    '''
    print_info(f"GG (merge_grammars): Merging grammars {grammar_stack[0:2]}")
    example_grammar_agent = setup_simple_agent(system_prompt_template='grammar_merge.system.j2', user_prompt_template='grammar_merge.user.j2')
    example_grammar_agent.use_web_logging_config()
    
    # Are you grandma ?
    limit_flag = check_token_limit([grammar_stack[0][0], grammar_stack[1][0]])
    if limit_flag == "Not a grandma":
        # No - return the shorter grammar from grammar stack 
        print_warn(f"GG (merge_grammars): Token limit exceeded. Skipping grammar merge.")
        if len(grammar_stack[0][0]) < len(grammar_stack[1][0]):
            return grammar_stack[0][0]
        else:
            return grammar_stack[1][0]
    # Yes
    merged_grammar = example_grammar_agent.invoke(input=dict(
                                                myquestion=f"Provide a grammar that is effective for generating inputs and maximizes coverage in the two given functions. \
                                                            The grammar should be comprehensive and combine the functionality of the two given grammars, while removing non important and duplicate rules.",
                                                grammar_stack = grammar_stack,
                                            ))
    if merged_grammar == None: 
        raise AssertionError("Merged grammar must not be None")
    return merged_grammar.value

def get_harness_info(): 
    ''' Returns the parsed harness_info from argument passed path as a triple 
    :return: (harness_bin_path_relative, harness_src_path, harness_src)
    '''
    
    with open(str(harness_info_path()), 'r') as f:
        harness_info = yaml.load(f, Loader=yaml.FullLoader)
    
    harness_bin_path_relative = pathlib.Path(harness_info['cp_harness_binary_path'])    
    harness_src_path = harness_info['cp_harness_source_path']
    with open(str(target_source_path() / f'{harness_src_path}'), 'r') as f:
        harness_src = f.read()

    return (harness_bin_path_relative, harness_src_path, harness_src)

def generate_input(num_input, grammar_path: pathlib.Path, generated_inputs_path: pathlib.Path, gg_root: pathlib.Path) -> tuple:
    '''Generate input for the target program in batches. Remove excess files.
    :param num_input: number of input files to generate
    :param grammar_path: path to the grammar file
    :param generated_inputs_path: path to store the generated inputs
    :param gg_root: path to the outer docker root such as /shellphish/
    :return: tuple (stdstream, returncode)
    '''
    print_info(f"GG (generate_input): Starting input generation")
    log_event(type="generate_input_regular", data={
        "num_input": num_input,
        "grammar_path": read_grammar(grammar_path / "spearfuzz.g4"),
        "generated_inputs_path": str(generated_inputs_path),
        "gg_root": str(gg_root)
    })
    iteration_count = 0
    num_unique_files = 0
    # loop to create files. trying 4 times. fail if num_input not reached
    while num_unique_files < int(num_input):
        
        log_event(type="generate_input_cont.", data={
        "num_input": num_input,
        "grammar_path": read_grammar(grammar_path / "spearfuzz.g4"),
        "generated_inputs_path": str(generated_inputs_path),
        "iteration": iteration_count
        })
        iteration_count += 1
        if iteration_count > 4:
            print_info(f"GG (generate_input): Iteration {iteration_count} - {num_unique_files} unique files. Aborting, too many tries.")
            print_warn(f"GG (generate_input) {read_grammar(grammar_path / 'spearfuzz.g4')}")
            return ("Too many tries, grammar complexity does not allow for enough diversity", 1)
        
        # generate the next batch of inputs
        cmd = [
            './scripts/generate_input.sh',
            '400',
            str(grammar_path / "spearfuzz.g4"), 
            f'{str(generated_inputs_path)}', 
        ]
        output = subprocess.run(cmd, cwd=gg_root, text=True, capture_output=True, timeout=180)
        
        # Check return code and parse error message to be usable by the correction agent
        if output.returncode != 0:
            print_warn(f"GG (generate_input): Could not generate input files for grammar \n {read_grammar(grammar_path / 'spearfuzz.g4')}")
            subprocess.run(['rm', '-r', f'tmp_hashes'], cwd=str(generated_inputs_path), check=True)
            known_error_list = ["AssertionError: ('", "ValueError: Rule redefinition(s):", "AttributeError: 'NoneType'"]
            
            # split error message into lines and find lines that contain any of the values in known_errors_list
            error_stack = []
            error_lines = output.stderr.split('\n')
            print_warn(f"GG (generate_input): [DEBUG] STDERR {output.stderr}")
            for line in error_lines: 
                if any(error in line for error in known_error_list):
                    error_stack.append(line)
            add_msg = ""
            print_goodboi(f"GG (generate_input): [DEBUG] Error stack: {error_stack}")
            if len(error_stack) == 1:
                error_dump = ''.join(error_stack)
                if "AssertionError" in error_dump:
                    add_msg = "'AssertionError: ('rule_name',) not in vertices.' indicates that the grammar rule 'rule_name' does not exist in the grammar. Add the missing rules according to the error message below."
                elif "ValueError: Rule redefinition(s):" in error_dump:
                    add_msg = "'ValueError: Rule redefinition(s):' gives a list of rules that are defined more than once. Remove or merge the duplicate rules according to the error message below."
                elif "AttributeError: 'NoneType'" in error_dump:
                    add_msg = "'AttributeError: 'NoneType'' indicates that a rule is not defined. Add the missing rules according to the error message below."
            
            if add_msg == "":
                error_dump = f"{output.stderr}"
            else:
                error_dump = f"{add_msg} \n {error_dump}"
                    
            print_info(f"GG (generate_input):  [DEBUG]: Error Dump == {error_dump}")
            log_event("generate_input_error", {
                "error_message": output.stderr, 
                "known_errors": known_error_list, 
                "error_stack": str(error_stack), 
                "retuned_msg": error_dump
            })
            return (str(error_dump), 1)

        num_unique_files = len(os.listdir(str(generated_inputs_path)))
    
    # files created - remove excess 
    if num_unique_files >= int(num_input):
        too_many = num_unique_files - int(num_input)

        subprocess.run(['rm', '-r', f'tmp_hashes'], cwd=str(generated_inputs_path), check=True)
        for _ in range(0, too_many):
            to_be_removed = random.choice(os.listdir(str(generated_inputs_path)))
            try:
                subprocess.run(['rm', f'{to_be_removed}'], cwd=str(generated_inputs_path), check=True)
            except subprocess.CalledProcessError as e:
                raise ChildProcessError(f"Could not remove file {to_be_removed} @ {str(generated_inputs_path)} \n {e}")

        print_info(f"GG (generate_input): {len(os.listdir(str(generated_inputs_path)))} inputs, stored @ {generated_inputs_path}")
        return (str(output.stdout), 0)
    
    if num_unique_files == 0:
        raise AssertionError("No unique files generated")
    
    return (str(output.stderr), 1)

def generate_input_check_grammar(grammar_string: str, max_retries: int) -> tuple:
    '''
    Generate input and check if the grammar is valid. If not, correct it
    :param str grammar_string: the grammar as string
    :param int max_retries: the maximum number of retries
    :return: a tuple (corrected_grammar, 0) if the grammar is valid, (original_grammar, 1) else
    :rtype: tuple
    '''
    print_info(f"GG (generate_input_check_grammar): Generating input and checking grammar for {max_retries} retries")
    retry_count = 0
    return_code = 0
    correct_me = grammar_string
    write_to_file(grammar_path(), 'spearfuzz.g4', grammar_string)
    generate_response = generate_input(num_input(), grammar_path(), generated_inputs_path(), gg_source())
    print_info(f"GG (generate_input_check_grammar): Initial response code: {generate_response[1]}")
    while generate_response[1] == 1:
        log_event(
            "grammar_correction_attempt",
            {
                "grammar": correct_me,
                "retry_count": retry_count
            }
        )
        if retry_count != 0: 
            print_warn(f"GG (generate_input_check_grammar): Grammar could not be fixed step {retry_count}")
        if retry_count > max_retries:
            return_code = 1
            break
        retry_count += 1
        correct_grammar(correct_me, generate_response[0])
        correct_me = read_grammar(grammar_path() / f'spearfuzz.g4')
        generate_response = generate_input(num_input(), grammar_path(), generated_inputs_path(), gg_source())
        if generate_response[1] == 0:
            print_info(f"GG (generate_input_check_grammar): Grammar fixed after {retry_count} retries")
            log_event("grammar_correction_success", {
                "grammar": correct_me,
                "retries": retry_count
            })
            break
    if return_code == 1:
        log_event("grammar_correction_failed", {
            "grammar": correct_me,
            "error_message": generate_response[0]
        }
        )
        print_warn("GG (generate_input_check_grammar): Grammar could not be fixed.")
        return (grammar_string, return_code)
    else:
        print_goodboi("GG (generate_input_check_grammar): Grammar is valid - inputs were generated and copied to grave")
        copy_inputs_to_grave()
        return (correct_me, return_code)
    
def get_function_index(list_of_functions: list) -> str:
    log_event(
        "get_function_index",
        {
            "list_of_functions": list_of_functions
        }
    )
    fun_index = {}
    with open(str(functions_index_path()), 'r') as f:
        function_index_json = json.loads(f.read())
        for fun_name in list_of_functions:
            for key in function_index_json.keys():     
                if fun_name in key:
                    with open(str(jsons_dir_path() / function_index_json[key]), 'r') as fo:
                        function_json_dict = json.loads(fo.read())
                        if fun_name == function_json_dict["funcname"]:
                            fun_index[fun_name] = function_json_dict
    return fun_index

def grammar_fusion(grammar_stack: list):
    ''' Merges the given list of grammars 2 by 2 or 2 by 3 if odd number of grammars
    :param list grammar_stack: the stack of grammars to merge [(function_name, grammar_string) ...]
    :return: final grammar
    '''
    log_event("grammar_fusion", {
        "num_grammars": len(grammar_stack),
        "grammar_stack": grammar_stack
    })
    fk_sht_up = []
    for i in grammar_stack: 
        print(f"GG: FK APPEND {i[1]}")
        fk_sht_up.append(i[0])
         
    print_info(f"GG (grammar_fusion): Fusion grammar_stack: {len(grammar_stack)}; fk_sht_up {len(fk_sht_up)} grammars")
    while len(fk_sht_up) > 1:
        merge_stack = fk_sht_up
        fk_sht_up = []
        print(f"GG (grammar_fusion): length of merge stack {len(merge_stack)}")
        for idx in range(0, len(merge_stack)-1, 2):
            log_event("grammar_fusion_iteration", {
                "idx": idx,
                "idx_2": idx+1
                }
            )
            print(f"GG (grammar_fusion): Merging idx {idx} and {idx+1}")
            if idx == 0 and len(merge_stack) % 2 != 0:
                print_info("GG (grammar_fusion): Triple merge done")
                # threefold merge
                merged_grammar = merge_grammars([merge_stack[idx], merge_stack[idx+1]])
                merged_grammar = merge_grammars([merged_grammar, merge_stack[idx+2]])
                fk_sht_up.append(merged_grammar)
            else:
                print("GG (grammar_fusion): regular merge")
                merged_grammar = merge_grammars([merge_stack[idx], merge_stack[idx+1]])
            
            write_to_file(grammar_path(), f'{idx}_merged_{time.time()}.g4', merged_grammar)
            fk_sht_up.append(merged_grammar)
            gen_tuple = generate_input_check_grammar(merged_grammar, 2)
            if(gen_tuple[1] == 1):
                print_warn(f"GG (grammar_fusion): Could not generate inputs for merged grammar {idx} and {idx+1}")

        for grammar in fk_sht_up: 
            print(f"GG (grammar_fusion): Merged all the grammars - creating intermediate merge inputs for {len(fk_sht_up)} grammars")
            gen_tuple = generate_input_check_grammar(grammar, 2)
        
        print_goodboi(f"Merge went from {len(merge_stack)} to {len(fk_sht_up)}")  
        
    if len(fk_sht_up) != 1: 
        raise AssertionError("Grammars were not merged properly. Die!")
    return str(fk_sht_up)

def log_event(type, data):
    ''' Log an event to the log file
    :param str type: the type of the event
    :param str data: the data of the event
    '''
    print_info(f"GG (log_event): Logging event {type} to {str(stats_dir())}")
    if stats_dir():
        os.makedirs(stats_dir(), exist_ok=True)
        with open(str(stats_dir() / str(int(time.time()))) + '.log', 'w') as f:
            yaml.safe_dump({"event": type, "data": data, "time": time.time()}, f)

def main():        
    
    # load yaml and read all functions from key "target_functions"
    with open(input_list_of_functions()) as foeee:
        input_function_yaml = yaml.safe_load(foeee)
    list_of_functions = list(set(input_function_yaml["target_functions"]))
    
    # Getting function index
    print_goodboi(f"GG: Running gg_boi on {len(list_of_functions)} functions {list_of_functions}")
    fun_index = get_function_index(list_of_functions)
    harness_info = get_harness_info()
    
    # Remove files that are not in index.               
    if len(list_of_functions) != len(fun_index.keys()):
        list_of_functions = [x for x in list_of_functions if x in fun_index.keys()]        
        if len(fun_index.keys()) > len(list_of_functions):
            raise AssertionError("Function index keys are more than the functions in the list. How possibru")

    # Check if the list of functions is too small. If so, multiply it by 2 and log the event
    multiplier = 200 // len(list_of_functions)
    if multiplier > 1:
        print_info(f"GG: Multiplying list of functions by {multiplier} - now is: \n {list_of_functions}")
        log_event("multiplying_list_of_functions", {
            "list_of_functions": list_of_functions,
            "fun_index": fun_index,
            "multiplier": f"{multiplier}"
        })
        for i in range(multiplier):
            log_event("multiplier_run", {
                "list_of_functions": list_of_functions,
                "run_id": i,
                "multiplier": f"{multiplier}"
            })
            grammar_stack = gg_is_dumb(list_of_functions, fun_index, harness_info[2])
            iter_count = 0
            for i in grammar_stack:
                print_info(f"Current grammar stack element {i} in iteration {iter_count}")
                if os.path.isfile(grammar_path() / f'{i[1]}.g4'):
                    print_info(f"GG: Removing old grammar file {i[1]}.g4")
                    out = subprocess.run(f"rm {str(grammar_path() / f'{i[1]}.g4')}", shell=True, capture_output=True, text=True)
                    if out.returncode != 0:
                        print_warn(f"GG: Could not remove the old grammar file {i[1]}.g4")
                        
                iter_count += 1
                write_to_file(grammar_path(), f'{str(time.time())}_{i[1]}.g4', i[0])
    else: 
        # Create grammar and generate inputs from that grammar for all functions is list_of_functions
        grammar_stack = gg_is_dumb(list_of_functions, fun_index, harness_info[2])
        iter_count = 0
        for i in grammar_stack:
            print_info(f"Current grammar stack element {i} in iteration {iter_count}")
            if os.path.isfile(grammar_path() / f'{i[1]}.g4'):
                print_info(f"GG: Removing old grammar file {i[1]}.g4")
                out = subprocess.run(f"rm {str(grammar_path() / f'{i[1]}.g4')}", shell=True, capture_output=True, text=True)
                if out.returncode != 0:
                    print_warn(f"GG: Could not remove the old grammar file {i[1]}.g4")
                    
            iter_count += 1
            write_to_file(grammar_path(), f'{str(time.time())}_{i[1]}.g4', i[0])
    
    for i in grammar_stack: 
        print_goodboi(f"GG: Grammar stack element: {i}")
        print("")
    print_goodboi("GG (main). Actually finished running!!!")   
    
if __name__ == "__main__":
    enable_event_dumping(str(stats_dir()))
    set_global_budget_limit(
        price_in_dollars=5,
        exit_on_over_budget=True
    )
    parse_config_from_args()
    main()
    
    
''' DEPRECATED
    # fun_tuple_list = []
    # input_function_json = None
    # with open(input_list_of_functions()) as lof:
    #     # load yaml and read all functions from key "target_functions"
    #     input_function_json = yaml.safe_load(lof)                 

    # for commits in input_function_json:
    #     fun_tuple_list.append((commits["funcname"], commits["max_score"]))

    # fun_tuple_list.sort(key=lambda x: x[1], reverse=True)
    # for i in fun_tuple_list:
    #     print(i)  

    #     list_of_functions = []
    #     for tup in fun_tuple_list:
    #         list_of_functions.append(tup[0])
    
    # print_goodboi(f"GG (main): Final grammar stack {grammar_stack}")
    # final_grammar = grammar_fusion(grammar_stack)    
    # print(f"GG (main): Final grammar {final_grammar}")
    # gen_tuple = generate_input_check_grammar(final_grammar, 4)[0]
    # if gen_tuple[1] == 1:
    #     print_warn("GG (main): Could not generate inputs for final grammar")
'''