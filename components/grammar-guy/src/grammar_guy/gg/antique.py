# -------------------------- imports --------------------------
from collections import defaultdict
from typing import Dict
import subprocess
import logging
import random
import yaml
import os

from analysis_graph.api.dynamic_coverage import register_grammar_function_coverage, get_functions_harness_reachability, get_one_covering_grammar_for_functions
from analysis_graph.models.grammars import Grammar
from analysis_graph.models.cfg import CFGFunction

# Agentlib and CRS Utils stuff
from agentlib import enable_event_dumping, set_global_budget_limit
from agentlib.lib.common import LLMApiBudgetExceededError

from shellphish_crs_utils.models.coverage import CoverageLine, FunctionCoverageMap, LinesCoverage, FileCoverageMap
from shellphish_crs_utils.models.indexer import FUNCTION_INDEX_KEY
from crs_telemetry.utils import init_otel, init_llm_otel, get_otel_tracer, status_ok
# grammar-guy common imports
os.chdir(os.path.dirname(__file__))
from grammar_guy.common import config
from grammar_guy.common.utils import *
from grammar_guy.common.improvement_strategies import *
from grammar_guy.common.generate import invoke_generator
from grammar_guy.common.agents.grammar_agent_generic import setup_grammar_agent, submit_grammar
from grammar_guy.common.agents.report_agent import setup_report_agent, submit_report
from grammar_guy.common.agents.grammar_agent_incremental import apply_grammar_changes

# -------------------------- end of imports --------------------------

init_otel("grammar-guy", "input-generation", "llm_grammar_generation")
init_llm_otel()
tracer = get_otel_tracer()

# SET LOGGING LEVEL
log = logging.getLogger("antique.grammar_guy")
log.setLevel(logging.INFO)

def add_line_numbers(text: str) -> str:
    ''' Adds line numbers to the given text.
    :param str text: the text to add line numbers to
    :return: the text with line numbers added
    '''
    raw_text = text
    numbered_text = "\n".join(f"{i+1}: {line}" for i, line in enumerate(raw_text.splitlines()))
    return numbered_text

def fix_grammar(broken_grammar:str, error_message:str): # used to be correct_grammar
    '''Generates a possibly corrected grammar based on the error message.
    :param str broken_grammar: the broken grammar as string
    :param str error_message: the error message as string
    :return: None if fix not possible, fixed grammar if fixed'''
    log.info(f"👨🏻‍🏫 Correcting grammar based on error message \n {error_message}")
    limit_exceeded = check_token_limit([broken_grammar, error_message])
    if limit_exceeded:
        log.warning("🔥🔥🔥 Token limit exceeded. Skipping.🔥🔥🔥")
        return None
    correct_grammar_agent = setup_grammar_agent(
        system_prompt_template='correct.system.j2', 
        user_prompt_template='correct.user.j2',
        agent_type='incremental'
    )
    correct_grammar_agent.use_web_logging_config()

    while True:
        config.set_new_grammar(None)
        try:
            while config.get_new_grammar() is None:
                log.debug(f"👨🏻‍🏫 Correcting grammar: \n {broken_grammar} \n with error message: \n {error_message}")
                res = correct_grammar_agent.invoke(input=dict(
                                                            broken_grammar=add_line_numbers(broken_grammar),
                                                            error_message=error_message,
                                                            ))
                corrected_grammar = apply_grammar_changes(broken_grammar, res.value)
                if corrected_grammar is None:
                    log.error("🤡 Could not apply grammar changes. Returning None.")
                    return None
                log.info(f"👑 Corrected grammar: \n {corrected_grammar}")
                submit_grammar(corrected_grammar)
        except LLMApiBudgetExceededError:
            log.error("LLM API budget exceeded in fix_grammar(). Waiting for 1 minute before retrying.")
            time.sleep(60)
            continue
        except Exception as e:
            log.error(f"An error occurred invoking grammar_fix function on {broken_grammar}: {e}")
            return None
        break
    
    grammar = config.get_new_grammar()
    log.debug(f"👨🏻‍🏫 Corrected grammar: \n {grammar}")
    if grammar is None: 
        log.warning("🔥 Grammar was None in after split_grammar_from_message()🔥")
        return None
    # TODO Add diff between fixed and broken grammar. 4-21
    return grammar

def check_grammar(grammar: str):
    ''' Fixes grammar if necessary, returns working grammar or (none, none).
    :param str improved_grammar: the improved grammar as string
    :param int max_retries: the maximum number of retries
    :return: valid_grammar if successful, None if not
    '''
    log.info("---------------------------------")
    log.info("🧪 Checking grammar ...")
    log.info("---------------------------------")
    if grammar is None:
        return None
    generation_result = generate_input_fix_grammar(grammar) # None, None if failed, (grammar, True) if success
    if generation_result == None:
        log.warning("🤡 Fixing grammar failed!")
        return None
    log.info(f"🎉 Grammar improved")
    return generation_result

def generate_batch_of_inputs(batch_size, grammar_content):
    ''' Generate a batch of inputs for the target program, return error message if generation fails.
    :param int batch_size: the number of inputs to generate
    :return: (Error message, False) on error, (None, True) on success
    '''
    if os.path.isfile(str(config.grammar_path() / f"spearfuzz{config.grammar_type()}")):
        if artiphishell_should_fail_on_error():
            raise AssertionError("Old grammar existed when generating seeds for new one. Should not happen.")
        
    write_to_file(config.grammar_path(), f"spearfuzz{config.grammar_type()}", grammar_content)
    success, std_out, std_err = invoke_generator('nautilus', batch_size, str(config.grammar_path() / f"spearfuzz{config.grammar_type()}"), config.generated_inputs_path(), 25)
    if not success:
        stdout = '\n'.join(std_out)
        stderr = '\n'.join(std_err)
        error_dump = f"Standard Output:\n{std_out}\nStandard Error:\n{std_err}"
        log.warning(f" ❌ Failed to generate batch of inputs ❌ \n {grammar_content} - cleared input dir \
                    -----------------------------------------------------------------")
        config.log_event("generate_input_error", {
            "stdout": stdout,
            "stderr": stderr,
            "returncode": success,
            "batch_size": batch_size,
        })
        if 'no way to derive START' in error_dump:
            return (error_dump + "The grammar is too deeply nested. Reduce nesting by resolving rules or appropriately adjusting \ "
            "non-terminals to be terminal rules with the right contents.", False)
        subprocess.run(['rm', '-rf', f'tmp_hashes'], cwd=str(config.generated_inputs_path()), check=True)
        remove_old_grammar()
        return (error_dump, False)
    remove_old_grammar()    
    return (None, True)

def generate_inputs(num_desired_files, grammar) -> tuple:
    '''Generate input for the target program in batches and removes excess files. Before generating, the grammar is checked.
    :param num_desired_files: number of input files to generate
    :return: Tuple of (None, True) or (error_message, False) on failure to generate inputs
    '''
    # has to return tuple (Error MESSAGE; TRUE/FALSE) -> TRUE IF CAN GENERATE INPUTS
    num_unique_files = 0
    log.info(f"Generating input for grammar")
    log.debug(f"Generate input for grammar: \n {grammar}")
    if config.FUZZER_NAME == 'grammarinator' and ('{' in grammar or '}' in grammar):
        return (f"Grammar contains '{{' or '}}' characters. This is not allowed.", False)

    for i in range(0, 3):
        log.debug(f"Iteration {i} with currently {num_unique_files}/{num_desired_files} generated")
        if num_unique_files >= int(num_desired_files):
            break
        config.log_event(type="generate_input_cont", data={
            "num_unique_files": num_unique_files,
            "num_desired_files": num_desired_files,
            "grammar_path": grammar,
            "generated_inputs_path": str(config.generated_inputs_path()),
            "iteration": i})
        batch_generated = generate_batch_of_inputs(batch_size=100, grammar_content=grammar)
        num_unique_files = len(os.listdir(str(config.generated_inputs_path())))
        if not batch_generated[1]:
            return (batch_generated[0], False)

    # files created - remove excess
    if num_unique_files > int(num_desired_files):
        remove_excess_files(num_unique_files, num_desired_files)
    elif num_unique_files < int(num_desired_files):
        log.warning(f"❌ Could not generate enough unique files ❌ - PROCEEDING with {num_unique_files} seeds")
    cleanup_tmp_hashes()

    log.info(f"🎉 Generated {len(os.listdir(config.generated_inputs_path()))}/{num_desired_files} inputs.")        
    assert num_unique_files > 0, "No unique files generated"
    return None, True

def check_input_generation(grammar):
    ''' Wrapper for generate_inputs. Writes grammar to file and generates two inputs before clearing dir.
    :param grammar: the grammar to generate inputs for
    :return: passes through tuple with (None, True) or (error_message, False) on failure
    '''
    log.debug(f"Testing input geneartion for grammar: \n {grammar}")
    ret = generate_inputs(2, grammar)
    log.debug(f"Input generation check returned: {ret}")
    clear_input_directory()
    return ret

def generate_example_input(grammar) -> bytes:
    remove_old_grammar()
    remove_all_generated_files()
    log.info("Generating example input for grammar")
    write_to_file(config.grammar_path(), f"spearfuzz{config.grammar_type()}", grammar)
    error, success = generate_inputs(1, grammar)
    assert success, f"Could not generate example input for grammar: {grammar}: {error}"

    # find the generated input
    input_files = os.listdir(str(config.generated_inputs_path()))
    assert len(input_files) == 1, f"Expected 1 input file, got {len(input_files)}"
    input_file = input_files[0]
    with open(config.generated_inputs_path() / input_file, 'rb') as f:
        input_content = f.read()
    return input_content

def generate_input_fix_grammar(grammar_content: str) -> str:
    ''' Generates input to check whether grammar is productive. Attempts to fix grammar 3 times
    :param str grammar_content: the grammar as string
    :return: None if grammar broken, grammar if fixed/working
    '''
    assert grammar_content is not None
    grammar = grammar_content
    
    log.info("🤔 Checking and fixing grammar 🤔")
    can_generate_inputs = check_input_generation(grammar)
    grammar_fixed = grammar
    if not can_generate_inputs[1]:
        # grammar is broken
        log.debug(f"🤡 Could NOT generate inputs for \n {grammar_content}")
        fixed_can_generate_inputs = can_generate_inputs
        for step in range(0, 8):
            config.log_event(
                "grammar_correction_attempt",
                {
                    "grammar": grammar_content,
                    "retry_count": step,
                    "error_message": fixed_can_generate_inputs[0],
                    "can_generate_inputs": fixed_can_generate_inputs[1],
                })
            grammar_tmp = fix_grammar(grammar_fixed, fixed_can_generate_inputs[0])
            if grammar_tmp is None:
                log.error(f"Fix {step} failed. Retrying... - This will cause Issues")
                continue
            grammar_fixed = grammar_tmp
            fixed_can_generate_inputs = check_input_generation(grammar_fixed) 
            if fixed_can_generate_inputs[1]:
                # Can generate inputs
                log.debug(f"Can generate inputs for fixed grammar \n {grammar_content}")
                return grammar_fixed
    else:
        # grammar is fine
        config.log_event("grammar_correction_not_needed", {
            "grammar": grammar_content,
            "error_message": 'None',
        })
        log.info(f"✅ No need to fix grammar - it worked already.")
        submit_grammar(grammar_content)
        return grammar_content

    config.log_event("grammar_correction_failed", {
        "grammar": grammar_content,
        "error_message": "redacted for now",
    })
    log.warning("⛓️‍💥 Grammar could not be fixed.")
    clear_input_directory()
    return None

def trace_workdir_inputs(grammar: str) -> FunctionCoverageMap:
    ''' Start tracing on previously generated inputs @ /work/inputs
        Uses coveragelib
        :return: the path to the coverage report folder containing index, coverage
    '''
    parsed_report: FileCoverageMap = config.COVERAGE_TRACER.trace_dir(config.generated_inputs_path())
    func_resolver = config.FUNCTION_RESOLVER
    assert func_resolver is not None, "Function resolver not set"
    
    result: FunctionCoverageMap = func_resolver.get_function_coverage(parsed_report)
    try:
        harness_info_id_cur_first_hack, harness_info_cur_first_hack = next(iter(sorted(config.HARNESS_INFO_DICT.items())))
        register_grammar_function_coverage(
            harness_info_id_cur_first_hack,
            harness_info_cur_first_hack,
            'nautilus-json',
            grammar,
            result,
        )
    except Exception as e:
        log.error(f"Could not register grammar coverage: {e}", exc_info=True)
        if artiphishell_should_fail_on_error():
            raise
    return result

def generate_improvement_report_hit_function(curr_grammar, curr_grammar_coverage, function_to_improve, function_to_improve_towards):
    test_engineer = setup_report_agent()
    log.info(f"🧑‍🏫 Generating improvement report for {function_to_improve} -> {function_to_improve_towards}")
    function_to_improve_towards_source = config.FUNCTION_RESOLVER.get(function_to_improve_towards).code
    # output_format_path = config.get_output_format_path('nautilus-python')
    # output_format = "HECK"
    # with open(output_format_path, 'r') as f:
    #     output_format = f.read().strip()

    report = config.get_new_report()
    input_dict = dict(
        current_grammar = curr_grammar,
        function_to_improve = function_to_improve,
        coverage = curr_grammar_coverage,
        function_to_improve_towards = function_to_improve_towards,
        function_to_improve_towards_source = function_to_improve_towards_source,
        # output_format = output_format
    )
    while True:
        config.set_new_report(None)
        try:
            while config.get_new_report() is None: 
                res = test_engineer.invoke(input=input_dict)
                submit_report(res.value['report'])
            report = config.get_new_report()
        except LLMApiBudgetExceededError:
            log.error("LLM API budget exceeded in generate_improv_report(). Waiting for 1 minute before retrying.")
            time.sleep(60)
            continue
        except Exception as e:
            log.error(f"An error occurred while generating improvement report: {e}")
            report = None
        break
    
    config.set_new_report(None)
    log.info(f"Proposed improvement report: {report}")
    config.log_event('improvement_report', {'improvement_report': report})
    return report

def try_generate_grammar_random_reachable(prev_grammar, fun_name, fun_coverage):
    harness_source = config.get_harness_src()
    log.info(f"🫥 Trying to generate better grammar (random)")
    improve_grammar_agent = setup_grammar_agent(
        system_prompt_template='random.system.j2', 
        user_prompt_template='random.user.j2', 
        agent_type='incremental'
    )
    improve_grammar_agent.use_web_logging_config()
    sample_input = generate_example_input(prev_grammar)

    input_dict = dict(
        prev_grammar = add_line_numbers(prev_grammar),
        fun_name = fun_name,
        fun_coverage = fun_coverage,
        harness_source = harness_source,
        input_example=repr(sample_input),
    )
    config.log_event("grammar_random_reachable", input_dict)
    if check_token_limit(input_dict.values()):
        from pprint import pprint; pprint(input_dict)
        log.error(f"Token limit exceeded for {input_dict}")
    else:
        config.set_new_grammar(None)
        while True:
            try:
                while config.get_new_grammar() is None:
                    res = improve_grammar_agent.invoke(input=input_dict)
                    improved_grammer = apply_grammar_changes(prev_grammar, res.value)
                    submit_grammar(improved_grammer)
                improved_grammar = config.get_new_grammar()
                config.log_event("improved_grammar", {'grammar': improved_grammar})
                return check_grammar(improved_grammar)
            except LLMApiBudgetExceededError:
                log.error("LLM API budget exceeded in try_generate_grammar_random_reachable(). Waiting for 1 minute before retrying.")
                time.sleep(60)
                continue
            except Exception as e:
                log.error(f"An error occurred while generating grammar_random_reachable: {e}")
                return None

def try_generate_grammar_random_unhit(function_src):
    ''' Generate a grammar for the given function. If too many tokens, returns "Not a grandma"
    :param str function_1_src: the source of the first function
    :return: the grammar
    :rtype: str / "Not a grandma" if oversize tokens
    '''
    # 1 is from, 2 is target
    harness_source = config.get_harness_src()
    one_shot_agent = setup_grammar_agent(
        system_prompt_template='one_shot.system.j2', 
        user_prompt_template='one_shot.user.j2', 
        agent_type='no_tool'
    )
    input_dict = dict(
                myquestion=f"Provide a grammar that is effective for generating inputs that maximize coverage in the two given functions. \
                            The goal is to make the grammar as extensive and specific as possible to trigger coverage in the function to hit.",
                function_source = function_src,
                harness_source = harness_source,
                )
    
    while True:
        config.set_new_grammar(None)
        try:
            while config.get_new_grammar() is None:
                res = one_shot_agent.invoke(input=input_dict)
                submit_grammar(res.value['grammar'])
            grammar = config.get_new_grammar()
            if grammar is None:
                return None
            return grammar
        except LLMApiBudgetExceededError:
            log.error("LLM API budget exceeded in try_generate_grammar_random_unhit(). Waiting for 1 minute before retrying.")
            time.sleep(60)
            continue
        except Exception as e:
            log.error(f"An error occurred while generating grammar_random_unhit: {e}")
            return None

def try_generate_grammar_callable_pair(prev_grammar, fun_name, fun_coverage, fun_to_hit, improvement_report, prompt_template="callable-pair", retry_count=4):
    for i in range(retry_count):
        improve_grammar_agent = setup_grammar_agent(
            system_prompt_template=f'{prompt_template}.system.j2', 
            user_prompt_template=f'{prompt_template}.user.j2', 
            agent_type='incremental'
        )
        improve_grammar_agent.use_web_logging_config()
        sample_input = generate_example_input(prev_grammar)

        input_dict = dict(
            prev_grammar = add_line_numbers(prev_grammar),
            fun_name = fun_name,
            fun_coverage = fun_coverage,
            function_to_hit = fun_to_hit,
            report = improvement_report,
            input_example=repr(sample_input),
            )
        config.log_event("grammar_callable_pair", input_dict)
        log.debug(f"Input dict for callable pair approach: {input_dict}")
        if check_token_limit(input_dict.values()):
            from pprint import pprint; pprint(input_dict)
            log.error(f"Token limit exceeded for {input_dict}")
        else:
            while True:
                config.set_new_grammar(None)
                try:
                    while config.get_new_grammar() is None:
                        res = improve_grammar_agent.invoke(input=input_dict)
                        improved_grammar = apply_grammar_changes(prev_grammar, res.value)
                        submit_grammar(improved_grammar)
                    improved_grammar = config.get_new_grammar()
                    config.log_event("improved_grammar", {'grammar': improved_grammar})
                    return check_grammar(improved_grammar)
                except LLMApiBudgetExceededError:
                    log.error("LLM API budget exceeded. In try_generate_grammar_callable_pair(). Waiting for 1 minute before retrying.")
                    time.sleep(60)
                    continue
                except Exception as e:
                    log.error(f"An error occurred while generating grammar_callable_pair: {e}")
                    return None
                
def generate_initial_grammar() -> str:
    '''
    :param function_source: the source code of the function to generate grammar for
    :param retries: the number of retries to attempt
    :return: None or new grammar
    '''
    log.info("---------------------------------")
    log.info("⚙️ Generating initial grammar ...")
    log.info("---------------------------------")
    init_grammar_agent = setup_grammar_agent(
        system_prompt_template='initial.system.j2', 
        user_prompt_template='initial.user.j2',
        agent_type='no_tool'
    )
    init_grammar_agent.use_web_logging_config()

    while True:
        config.set_new_grammar(None)
        try:
            while config.get_new_grammar() is None:
                res = init_grammar_agent.invoke(input=dict(function_source=config.get_harness_src()))
                submit_grammar(res.value['grammar'])
            grammar = config.get_new_grammar()
            log.debug(f'Initial Agent response: \n {grammar}')
            log.info(f'📜 Initial grammar: \n {grammar}')
            return grammar
        except LLMApiBudgetExceededError:
            log.error("LLM API budget exceeded. In generate_initial_grammar(). Waiting for 1 minute before retrying.")
            time.sleep(60)
            continue
        except Exception as e:
            log.error(f"An error occurred while generating initial grammar: {e}")
            return None
        break

def improve_grammar_callable_function_pair_selection(grammar_dict, per_grammar_coverage: Dict[str, FunctionCoverageMap]):
    log.info("🧑‍🤝‍🧑 Improving grammar using pair approach.")
    pair_for_improvement_list = find_function_pairs_to_improve(random.choice(list(per_grammar_coverage.values())))
    if pair_for_improvement_list is None or len(pair_for_improvement_list) == 0:
        log.warning("❌ No pairs for improvement found ❌")
        return None, None
    
    pair_for_improvement = random.choice(pair_for_improvement_list)
    function_to_improve_from = pair_for_improvement[0]
    function_to_improve_towards = pair_for_improvement[1]
    assert pair_for_improvement is not None, "🤡 No function pair to improve towards found (this should be impossible)"

    grammar_to_improve = random.choice(grammar_dict[function_to_improve_from]) 
    previous_function_coverage_report = config.FUNCTION_RESOLVER.get_function_coverage_report([], per_grammar_coverage[grammar_to_improve], keys_of_interest=[function_to_improve_from])
    
    # -- use llm to generate report on how to improve grammar --
    improvement_report = generate_improvement_report_hit_function(grammar_to_improve, previous_function_coverage_report, function_to_improve_from, function_to_improve_towards)
    if improvement_report is None:
        log.warning(f"🔥 Could not generate improvement report for {function_to_improve_from} ❌")
        return None, None
    log.debug(f"Improvement report: {improvement_report}")
    if not (improved_grammar := try_generate_grammar_callable_pair(grammar_to_improve, function_to_improve_from, previous_function_coverage_report, function_to_improve_towards, improvement_report)):
        log.warning(f"🔥 Could not improve grammar for {function_to_improve_from} 🔥")
        return None, None

    valid_grammar = check_grammar(improved_grammar) # this always returns a functioning grammar or None, use for evaluation!!
    if valid_grammar is None:
        return None, None
    else:
        new_coverage : FunctionCoverageMap = evaluate_grammar_coverage(valid_grammar)
        return valid_grammar, new_coverage

def improve_grammar_random_unhit(curr_grammar_coverage: FunctionCoverageMap):
    ''' Choose a random function and try to one shot getting there based on harness_src and function_src
    :param grammar_dict: Stores the functions and reaching grammars. Keyed by function
    :param per_grammar_coverage: Stored coverage for grammars. Keyed by grammar
    :param curr_grammar_coverage: coverage achieved with given grammar
    :return (improved_grammar, new_coverage)
    '''
    log.info("----------------------------------------------")
    log.info("🎲 Improving grammar using random approach.")
    log.info("----------------------------------------------")
    # -- harness and function to hit --
    function_to_improve_towards = find_random_unhit_function_to_improve(curr_grammar_coverage)
    if function_to_improve_towards is None:
        log.warning("❌ No unhit functions found ❌")
        return None, None
    one_shot_grammar = try_generate_grammar_random_unhit(config.FUNCTION_RESOLVER.get(function_to_improve_towards).code)
    if one_shot_grammar is None:
        log.warning(f"❌ Could not generate one shot grammar for {function_to_improve_towards} ❌")
        return None, None
    valid_grammar = check_grammar(one_shot_grammar)
    config.log_event("grammar_random_unhit", {"grammar": valid_grammar})
    if valid_grammar is None:
        return None, None
    else:
        new_coverage = evaluate_grammar_coverage(valid_grammar)
        return valid_grammar, new_coverage

def improve_grammar_random_reachable(grammar_dict, grammar_coverage: Dict[str, FunctionCoverageMap], curr_grammar_coverage: FunctionCoverageMap):
    '''
    Choose a random function and try to one shot getting there based on harness_src and function_src
    :param grammar_dict: Stores the functions and reaching grammars. Keyed by function
    :param grammar_coverage: Stored coverage for grammars. Keyed by grammar
    :param curr_grammar_coverage: coverage achieved with given grammar
    :return (improved_grammar, new_coverage)
    '''
    log.info("---------------------------------------------")
    log.info("🎰 Improving grammar using random approach.")
    log.info("---------------------------------------------")
    function_to_improve_towards = find_random_reachable_function_to_improve(curr_grammar_coverage)
    if function_to_improve_towards is None:
        return None, None

    # get random previous grammar from grammar_dict
    grammar_to_improve = random.choice(grammar_dict[function_to_improve_towards])
    function_coverage = config.FUNCTION_RESOLVER.get_function_coverage_report([], grammar_coverage[grammar_to_improve], keys_of_interest=[function_to_improve_towards])
    if not (improved_grammar := try_generate_grammar_random_reachable(grammar_to_improve, function_to_improve_towards, function_coverage)):
        log.warning(f"❌ Could not improve grammar for {function_to_improve_towards} ❌")
        return None, None

    valid_grammar = check_grammar(improved_grammar) # does not clean inputs it creates for checking
    if valid_grammar is None:
        return None, None
    else:
        new_coverage = evaluate_grammar_coverage(valid_grammar)
        return valid_grammar, new_coverage

def improve_grammar_random(grammar_dict, grammar_coverage: Dict[str, FunctionCoverageMap], curr_grammar_coverage: FunctionCoverageMap):
    '''
    Wrapper for the random improvement strategy. Tries to improve grammar on unhit functions and falls back on
    improving grammar on reachable functions. If both fail, returns (None, None) else (improved_grammar, new_coverage)
    :return: tuple (improved_grammar, new_coverage)
    '''
    selector = random.choice([0,1])
    if selector == 0:
        res_tup = improve_grammar_random_unhit(curr_grammar_coverage)
    else:
        res_tup = improve_grammar_random_reachable(grammar_dict, grammar_coverage, curr_grammar_coverage)
    return res_tup

def evaluate_grammar_coverage(grammar) -> FunctionCoverageMap:
    ''' Generates inputs, traces them and parses coverage files for each function while applying to suffix matching to find the corresponding function.
    :param str grammar: the grammar to evaluate
    :return: FunctionCoverageMap with the coverage for all functions
    '''
    log.info("---------------------------------")
    log.info("👨‍🏫 Evaluating grammar ...")
    log.info("---------------------------------")
    can_generate_inputs = generate_inputs(config.num_input(), grammar)
    if not can_generate_inputs[1]:
        log.error(f"❌ Could not generate inputs for grammar ❌")
        log.error(f"🚨 Error message: {can_generate_inputs[0]}")
        # grammar is broken
        clear_input_directory()
        fixed_grammar = generate_input_fix_grammar(grammar)
        if fixed_grammar is None:
            log.error(f"❌ Could not fix grammar ❌")
            return None
        clear_input_directory()
        can_generate_inputs = generate_inputs(config.num_input(), fixed_grammar)
        if not can_generate_inputs[1]:
            log.error(f"❌ AGAIN ‼️ Could not generate inputs for grammar ❌")
            log.error(f"🚨 Error message: {can_generate_inputs[0]}")
            return None
        log.info(f"✅ Successfully generated inputs for grammar")
        grammar = fixed_grammar
    fun_cov_map = trace_workdir_inputs(grammar)
    return fun_cov_map

def get_coverage_line_changes(old_coverage: LinesCoverage, new_coverage: LinesCoverage) -> tuple:
    ''' Compares the coverage of two function coverage files.
    :param str old_function_coverage: the old function coverage files
    :param str new_function_coverage: the new function coverage files
    :return: a tuple with lists of lines that decreased, increased, or unchanged
    '''
    # count lines that have hitcount 0
    lines_decreased = []
    lines_increased = []
    lines_no_change = []
    parsed_newcov = {line.line_number: line for line in new_coverage}
    parsed_oldcov = {line.line_number: line for line in old_coverage}

    for line_num, line in parsed_newcov.keys():
        if line.count_covered > parsed_oldcov[line_num].count_covered:
            lines_increased.append(line_num)
        elif line.count_covered < parsed_oldcov[line_num].count_covered:
            lines_decreased.append(line)
        else:
            lines_no_change.append(line)
    return (lines_decreased, lines_increased, lines_no_change)

def update_grammar_dict(grammar_dict, grammar_coverage, new_grammar, new_grammar_coverage) -> Dict[FUNCTION_INDEX_KEY, List[str]]:
    log.info("---------------------------------")
    log.info("🏋️ Updating Grammar Dict ...")
    log.info("---------------------------------")
    updated = False
    # -- map coverage to grammar --
    grammar_coverage[new_grammar] = new_grammar_coverage

    # -- map grammar to all functions it has reached --
    update_count = 0
    newly_reached_functions = []
    newly_reached_files = [] # NOTE: CURRENTLY NEVER SET. 
    for function in new_grammar_coverage.keys():
        if is_covered_function(new_grammar_coverage[function]):
            if grammar_dict[function] == []:
                log.info(f"🔎 Found coverage for {function} - adding grammar to grammar_dict[function]")
                newly_reached_functions.append(function)
            grammar_dict[function].append(new_grammar)
            updated = True
            update_count = update_count + 1
    if updated:
        list_of_input_paths = [pathlib.Path(config.generated_inputs_path() / f) for f in os.listdir(str(config.generated_inputs_path()))]
        save_inputs_and_grammar('nautilus-python', new_grammar, list_of_input_paths, newly_reached_files=newly_reached_files, newly_reached_functions=newly_reached_functions)
        move_files_to_afl_dir(config.generated_inputs_path())
        log.info("␖ Synced inputs to AFL directory (in eval)␖")
    else:
        log.warning("❌ No coverage improvement found ❌")
        os.system(f'rm -rf {str(config.generated_inputs_path())}/*')
    return updated

def select_strategy_random():
    return random.choice(config.improvement_strategies())

def generate_extension_report(selected_grammar: str) -> str:
    assert selected_grammar is not None, "Selected grammar is None"
    assert type(selected_grammar) == str, "Selected grammar is not a string"
    log.info(f"🔖 Generating extension report for {selected_grammar}")
    extender = setup_report_agent(system_prompt_template='extender.system.j2', user_prompt_template='extender.user.j2')
    input_dict = dict(grammar_string=selected_grammar)
    while True:
        config.set_new_report(None)
        try: 
            while config.get_new_report() is None: 
                res = extender.invoke(input=input_dict)
                submit_report(res.value['report'])
            report = config.get_new_report()
        except LLMApiBudgetExceededError:
            log.error("LLM API budget exceeded in generate_improv_report(). Waiting for 1 minute before retrying.")
            time.sleep(60)
            continue
        except Exception as e:
            log.error(f"An error occurred while generating improvement report: {e}")
            report = None
        break
    
    config.set_new_report(None)
    log.info(f"Proposed extension report: {report}")
    config.log_event('improvement_report', {'improvement_report': report})
    return report

def extend_grammar(grammar_coverage: Dict[str, FunctionCoverageMap]):
    ''' Selects a random grammar and extends it with a random function from the grammar_dict
    :param grammar_dict: the grammar dictionary
    :return: the extended grammar
    '''
    log.info("🧌 Improving grammar using extender approach.")
    # -- select random grammar and extend it --
    if len(grammar_coverage.keys()) == 0:
        log.warning("❌ No grammars to extend ❌")
        return None, None
    selected_grammar_key = random.choice(list(grammar_coverage.keys()))
    selected_grammar = random.choice(grammar_coverage[selected_grammar_key])
    extension_report = generate_extension_report(selected_grammar)
    if extension_report is None:
        log.warning("❌ Could not generate extension report ❌")
        return None, None
    grammar_builder = setup_grammar_agent(
        system_prompt_template='compose.system.j2', 
        user_prompt_template='compose.user.j2',
        agent_type='incremental'
    )
    while True:
        config.set_new_grammar(None)
        try:
            while config.get_new_grammar() is None:
                res = grammar_builder.invoke(input=dict(
                    build_report = extension_report, 
                    unrefined_grammar = add_line_numbers(selected_grammar)
                ))
                new_grammar = apply_grammar_changes(selected_grammar, res.value)
                submit_grammar(new_grammar)
            new_grammar = config.get_new_grammar()              
            config.set_new_grammar(None)
        except LLMApiBudgetExceededError:
            log.error("LLM API budget exceeded in generate_improv_report(). Waiting for 1 minute before retrying.")
            time.sleep(60)
            continue
        except Exception as e:
            log.error(f"An error occurred while generating improvement report: {e}")
            return None, None
        break
    log.info(f"📖 Proposed extension grammar: {new_grammar} 📖 ")
    check_and_fix_grammar: tuple = check_grammar(new_grammar)
    if check_and_fix_grammar is None:
        log.warning("❌ Could not extend grammar ❌")
        return None, None
    else:
        new_coverage = evaluate_grammar_coverage(check_and_fix_grammar)
        return check_and_fix_grammar, new_coverage

def build_grammar_corpus(grammar_cycles: int = 2000):
    log.info("====================================================================")
    log.info("🛠️ Building grammar corpus ...")
    log.info("====================================================================")
    grammar_dict = defaultdict(list) # make defaultdict to list
    grammar_coverage: Dict[str, FunctionCoverageMap] = dict() # maps grammars to the coverage they hit
    initial_grammar = None
    consecutive_non_improving_iterations = 0
    curr_initial_grammar_retries = 0
    while initial_grammar is None and curr_initial_grammar_retries < 15:
        initial_grammar : str = generate_initial_grammar() # Generate grammar
        initial_grammar = check_grammar(initial_grammar) # Check and fix
        if initial_grammar is not None:
            log.info("✅ Initial grammar is valid")
            initial_grammar_coverage : FunctionCoverageMap = evaluate_grammar_coverage(initial_grammar)
            if initial_grammar_coverage is None:
                log.info("❌ Initial grammar coverage is None. We will retry generating initial grammar.")
                initial_grammar = None
                config.set_new_grammar(None)
                continue
            log.info("✅ Initial grammar coverage is valid")
            break
        else:
            log.warning(f"❌ Initial grammar is None. Retrying... ({curr_initial_grammar_retries}/15)")
            curr_initial_grammar_retries += 1
    
    assert initial_grammar is not None, "❌ Initial grammar is None ❌"
    assert initial_grammar_coverage is not None, "❌ Initial grammar coverage is None ❌"
    
    update_grammar_dict(grammar_dict, grammar_coverage, initial_grammar, initial_grammar_coverage)
    config.record_grammar_success(initial_grammar, initial_grammar_coverage, {
                'source': 'initial_grammar',
                'cycle': 'initial_grammar',
                'hit_functions_total': len(grammar_dict.keys()),
            }, original_grammar="", original_coverage=dict())
    log.info("-----------------------------------------------------------------------")
    log.info(f"ℹ️ Initial grammar reached {len(grammar_dict.keys())}/{len(config.LIST_OF_FUNCTIONS)}ℹ️ functions")
    
    curr_grammar = initial_grammar
    curr_grammar_coverage = initial_grammar_coverage
    clear_input_directory()
    log.info("✅ Initial grammar generated")
    log.info("🥤 Starting iteration with clean slate. No inputs, no stored grammar.")
    log.info("====================================================================")

    # -- Iteration start - clean slate, no inputs in input dir --
    consecutive_non_improving_iterations = 0
    for cycle in range(0, grammar_cycles):
        # Ignore this - its not important)
        if len(grammar_dict.keys()) == 0:
            num_hit_functions = 0
        else:
            num_hit_functions = len(grammar_dict.keys())
        log.info("===================================================================")
        log.info(f'🔄 Cycle {cycle} hit {num_hit_functions} functions so far. Consecutive iterations without improvement = {consecutive_non_improving_iterations}')
        if num_hit_functions == len(config.LIST_OF_FUNCTIONS):
            log.info("✅✅✅✅ All functions already covered. ✅✅✅✅")
        strategy_worked = False
        improved_grammar = None
        sadness_count = 0
        hecking_died = 0

        if consecutive_non_improving_iterations > 10:
            log.warning(f"ℹ️ Consecutive non-improving iterations: {consecutive_non_improving_iterations}. Resetting to 0.")
            consecutive_non_improving_iterations = 0
            # get functions that have been reached from harness
            reachable_functions: List[CFGFunction] = get_functions_harness_reachability(config.PROJECT_HARNESS_METADATA['project_id'], config.PROJECT_HARNESS_METADATA['cp_harness_name'])
            functions_to_retrieve_from_analysisgraph = set(config.LIST_OF_FUNCTIONS) & set([reachable_functions.identifier for reachable_functions in reachable_functions])
            
            # Pull from analysis graph 
            covered_functions_grammar_dict_analysisgraph, _ = get_one_covering_grammar_for_functions(list(functions_to_retrieve_from_analysisgraph)) 
            
            # Run coverage and update grammar dict
            for grammar in covered_functions_grammar_dict_analysisgraph:
                try:
                    new_coverage = evaluate_grammar_coverage(grammar)
                    if new_coverage is None:
                        raise Exception("Grammar broken from analysis graph, skipping!")
                    update_grammar_dict(grammar_dict, grammar_coverage, grammar, new_coverage)
                except Exception as e:
                    log.error(f"Could not evaluate grammar, skipping. {e}")
                    continue

        while not strategy_worked:
            strategy = select_strategy_random()
            config.log_event("grammar_improvement_cycle",
                {
                    "strategy": strategy,
                    "num_hit_functions": num_hit_functions,
                    "cycle_number": cycle
                }
            )
            sadness_count = sadness_count + 1
            if strategy == "random":
                improved_grammar, new_grammar_coverage = improve_grammar_random(grammar_dict, grammar_coverage, curr_grammar_coverage)
            elif strategy == "uncovered_callable_function_pairs":
                improved_grammar, new_grammar_coverage = improve_grammar_callable_function_pair_selection(grammar_dict, grammar_coverage)
            elif strategy == "extender":
                improved_grammar, new_grammar_coverage = extend_grammar(grammar_dict)

            else:
                log.error("Selected non exisiting improvement strategy")
                raise NotImplementedError("🤡 No offense but ur trash")

            if sadness_count > 20 and improved_grammar is None:
                hecking_died = 1
                break
            else:
                if improved_grammar is not None:
                    strategy_worked = True
                    log.info(f"✅ {strategy}. Cycle {cycle}/{grammar_cycles}")
                    break
                else: 
                    log.info(f"❌ {strategy} - no improvement found. Cycle {cycle}/{grammar_cycles}")
                    continue

        if not hecking_died:
            assert improved_grammar is not None, "🎻 Something is wrong, I can feel it - grammar."
            # assert new_grammar_coverage is not None, "🎻 Something is wrong, I can feel it - coverage."
            if new_grammar_coverage is None:
                log.warning(f"🚨❌ New grammar coverage is None, cycle {cycle}")
                log.info(f"ℹ️ Cycle {cycle} finished.")
                log.info("===================================================================")
                continue

            updated = update_grammar_dict(grammar_dict, grammar_coverage, improved_grammar, new_grammar_coverage)
            if updated:
                consecutive_non_improving_iterations = 0
                config.record_grammar_success(improved_grammar, new_grammar_coverage, {
                'source': 'build_grammar_corpus',
                'cycle': cycle,
                'hit_functions_total': len(grammar_dict.keys()),
            }, original_grammar=curr_grammar, original_coverage=curr_grammar_coverage)
                # improved_and_logged_count+= 1
                log.info(f"ℹ️ So far total: {num_hit_functions}/{len(config.LIST_OF_FUNCTIONS)}ℹ️")
                num_hit_functions = len([func for func in grammar_dict.keys() if (len(grammar_dict[func]) != 0)])
                log.info(f"ℹ️ Improved and hit after {strategy}: {num_hit_functions}/{len(config.LIST_OF_FUNCTIONS)}ℹ️")
                log.info(f"📈 Grammar stored")
            else:
                consecutive_non_improving_iterations += 1
                log.info(f"📉 Grammar not stored - hecking died")
                # log.info(f"👴🏻 {curr_grammar} \n 👨🏻‍🦱 {improved_grammar}")
                pass
            curr_grammar = improved_grammar
            curr_grammar_coverage = new_grammar_coverage
        else:
            consecutive_non_improving_iterations += 1
            if improved_grammar is None:
                log.warning(f"DIED AND IMPROVED GRAMMAR IS NONE")
            log.warning(f"❌ Forking died and did not improve in previous iteration, cycle {cycle}")
            hecking_died = 0
        log.info(f"ℹ️ Cycle {cycle} finished.")
        log.info("===================================================================")

    write_to_file(".", 'final_grammar_dict.yaml', yaml.dump(grammar_dict))
    write_to_file(".", 'final_grammar_coverage.yaml', yaml.dump(grammar_coverage))      

def grammar_guy():
    if config.SARIF_MODE:
        func_of_interest = get_sarif_function_of_interest(config.get_sarif_results())
        log.info(f"📝 Running Grammar-guy in SARIF mode for codeflow locations: {func_of_interest}")
        config.set_target_functions(func_of_interest)
        config.adjust_improvement_strategies(new_strategy='codeflow-pairs')
    build_grammar_corpus() # TODO: Adjust for new strategy

def main():
    set_up_webview()
    grammar_guy()
    import sys; sys.exit(0)

if __name__ == "__main__":
    config.parse_config_from_args()
    logging.basicConfig(level=logging.WARNING)

    enable_event_dumping(str(config.stats_dir()))
    # TODO (finaldeploy) Update the budget here
    set_global_budget_limit(
        price_in_dollars=10,
        exit_on_over_budget=True,
        lite_llm_budget_name='grammar-openai-budget'
    )

    with tracer.start_as_current_span("grammar_guy") as span:
        with config.launch_coverage_tracer():
            main()
        span.set_status(status_ok())
#--------------------------- ---------------------------------------------------------- #
