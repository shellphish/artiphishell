import os
import logging
from typing import Dict, List, Tuple, Any, Optional, Set
import sys
import yaml
import hashlib
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.project import Project
from config import FILE_TEMPLATES, QUERY_PATHS, PROMPT_PATHS, NUM_PROCESSES,MAX_FUNCTIONS_IN_FILE_DIFF, DIFFGUY_MODELS, NAP_DURATION, NAP_BECOMES_FAIL_AFTER, NAP_SNORING, DIFFGUY_TIMEOUT
from core.utils import save_json, load_json, ensure_directories, function_resolve, get_diff
from shellphish_crs_utils.function_resolver import FunctionResolver
from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiRateLimitError
from agentlib import Agent, LocalObject, ObjectParser, Field
import agentlib
from tqdm import tqdm
from multiprocessing import Pool
import signal
from datetime import datetime, timedelta
import time

logging.getLogger("shellphish_crs_utils.function_resolver").setLevel(logging.ERROR)

global_solver = None
global_file_path = None

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException()




def init_pool(solver, path):
    global global_solver
    global global_file_path
    global_solver = solver
    global_file_path = path


def take_a_nap():
    # NOTE: this will make the agent nap until the next budget tick.
    logger.info(f'😴 Nap time! I will be back in a bit...')

    waking_up_at = datetime.now() + timedelta(minutes=NAP_DURATION - (datetime.now().minute % NAP_DURATION))

    while True:
        if datetime.now() >= waking_up_at:
            logger.info(f'🫡 Nap time is over! Back to work...')
            break
        else:
            time.sleep(NAP_SNORING)

def analyze_function(args):
    function_index, project_name, language, diff_text = args

    try:
        code = global_solver.get_code(function_index)[3]
    except Exception as e:
        logger.warning(f"Code not found for function {function_index}")
        code = ""


    try:
        diff = get_diff(global_solver, function_index, diff_text)
    except Exception as e:
        logger.warning(f"Diff not found for function {function_index}")
        diff = ""

    agent = SimpleChatCompletion()
    agent.use_web_logging_config(clear=True)

    curr_llm_index = 0
    how_many_naps = 0

    # Setting the LLM!
    agent_current_llm = DIFFGUY_MODELS[curr_llm_index]
    agent.__LLM_MODEL__ = agent_current_llm
    agent.llm  = agent.get_llm_by_name(
                                       agent_current_llm, 
                                       **agent.__LLM_ARGS__,
                                       raise_on_budget_exception=agent.__RAISE_ON_BUDGET_EXCEPTION__,
                                       raise_on_rate_limit_exception=agent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                      )

    # 💰🔄
    while True:
        try:
            res = agent.invoke(dict(
                project_name=project_name,
                language=language,
                code=code,
                diff=diff,
            ))
            result = {
                "code": code,
                "vulnerable": res.value.vulnerable,
                "reason": res.value.reason
            }
            how_many_naps = 0
            # 💰🔄⛓️‍💥
            break

        except LLMApiBudgetExceededError as e:
            curr_llm = agent.__LLM_MODEL__
            curr_llm_index += 1
            logging.warning(f"💸🤖 DiffGuy ran out of budget for model {curr_llm}")
            try:
                if curr_llm_index < len(DIFFGUY_MODELS):
                    # switch agent
                    agent = SimpleChatCompletion()
                    agent_current_llm = DIFFGUY_MODELS[curr_llm_index]
                    logger.info(f'🔁🤖 Switching DiffGuy to model {agent_current_llm}')
                    agent.__LLM_MODEL__ = agent_current_llm
                    agent.llm  = agent.get_llm_by_name(
                                                       agent_current_llm, 
                                                       **agent.__LLM_ARGS__,
                                                       raise_on_budget_exception=agent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                       raise_on_rate_limit_exception=agent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                      )
                    # 💰🔄▶️
                    continue
                else:
                    # If we run out of LLM to try, we need to take a nap...
                    how_many_naps += 1
                    if how_many_naps > NAP_BECOMES_FAIL_AFTER:
                        logging.error(f"🪦 Exhausted number of naps in a row for DiffGuy...")
                        result = {
                            "code": code,
                            "vulnerable": "Unknown",
                            "reason": "Unknown"
                        }
                        # Well, give up on this...
                        # 💰🔄⛓️‍💥
                        break
                    else:
                        # NOTE: we nap if we do not have any new LLM to switch to.
                        curr_llm_index = 0
                        take_a_nap()
                        # Switch to the first model and try again!
                        agent = SimpleChatCompletion()
                        agent_current_llm = DIFFGUY_MODELS[curr_llm_index]
                        logger.info(f'🔁🤖 Switching DiffGuy to model {agent_current_llm} after nap!')
                        agent.__LLM_MODEL__ = agent_current_llm
                        agent.llm  = agent.get_llm_by_name(
                                                           agent_current_llm, 
                                                           **agent.__LLM_ARGS__,
                                                           raise_on_budget_exception=agent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                           raise_on_rate_limit_exception=agent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                           )
                        # 💰🔄▶️
                        continue
            except Exception as e:
                logging.error(f'😮‍💨 Something went VERY wrong during DiffGuy model switching. Aborting this function.')
                result = {
                    "code": code,
                    "vulnerable": "Unknown",
                    "reason": "Unknown"
                }
                # Well, give up on this...
                # 💰🔄⛓️‍💥
                break

        except LLMApiRateLimitError as e:
            curr_llm = agent.__LLM_MODEL__
            curr_llm_index += 1
            logging.warning(f"💸🤖 DiffGuy hit rate limit for model {curr_llm}")
            try:
                if curr_llm_index < len(DIFFGUY_MODELS):
                    # switch agent
                    agent = SimpleChatCompletion()
                    agent_current_llm = DIFFGUY_MODELS[curr_llm_index]
                    logger.info(f'🔁🤖 Switching DiffGuy to model {agent_current_llm}')
                    agent.__LLM_MODEL__ = agent_current_llm
                    agent.llm  = agent.get_llm_by_name(
                                                        agent_current_llm, 
                                                        **agent.__LLM_ARGS__,
                                                        raise_on_budget_exception=agent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                        raise_on_rate_limit_exception=agent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                       )
                else:
                    # If we run out of LLM to try, we need to take a nap...
                    how_many_naps += 1
                    if how_many_naps > NAP_BECOMES_FAIL_AFTER:
                        logging.error(f"🪦 Exhausted number of naps in a row for DiffGuy...")
                        result = {
                            "code": code,
                            "vulnerable": "Unknown",
                            "reason": "Unknown"
                        }
                        # Well, give up on this...
                        break
                    else:
                        # NOTE: we nap if we do not have any new LLM to switch to.
                        curr_llm_index = 0
                        take_a_nap()
                        # Switch to the first model and try again!
                        agent = SimpleChatCompletion()
                        agent_current_llm = DIFFGUY_MODELS[curr_llm_index]
                        logger.info(f'🔁🤖 Switching DiffGuy to model {agent_current_llm} after nap!')
                        agent.__LLM_MODEL__ = agent_current_llm
                        agent.llm  = agent.get_llm_by_name(
                                                            agent_current_llm, 
                                                            **agent.__LLM_ARGS__,
                                                            raise_on_budget_exception=agent.__RAISE_ON_BUDGET_EXCEPTION__,
                                                            raise_on_rate_limit_exception=agent.__RAISE_ON_RATE_LIMIT_EXCEPTION__
                                                           )
                        continue
            except Exception as e:
                logging.error(f'😮‍💨 Something went VERY wrong during DiffGuy model switching. Aborting this function.')
                result = {
                    "code": code,
                    "vulnerable": "Unknown",
                    "reason": "Unknown"
                }
                # Well, give up on this...
                break
        except Exception as e:
            logging.error(f"Error invoking LLM for function {function_index}: {e}")
            result = {
                "code": code,
                "vulnerable": "Unknown",
                "reason": "Unknown"
            }
            # Well, give up on this...
            break
    id = hashlib.md5(function_index.encode()).hexdigest()
    save_json(os.path.join(global_file_path, f"{id}.json"), {function_index : result})
    return function_index, result

class MyObject(LocalObject):
    """An object which contains a bash command"""
    vulnerable: str = Field(description='If this function is vulnerable, return with Yes, Maybe and No, when you respond with "Yes", you should be very sure that the code is vulnerable.')
    reason: str = Field(description='The reason why this function is vulnerable or not')


class SimpleChatCompletion(Agent[dict,str]):

    __LLM_MODEL__ = "claude-4-sonnet"

    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    __OUTPUT_PARSER__ = ObjectParser(
        MyObject,
        use_structured_output=True,
        strict=False,
    )
    __SYSTEM_PROMPT_TEMPLATE__ = PROMPT_PATHS["system_prompt"]
    __USER_PROMPT_TEMPLATE__ = PROMPT_PATHS["user_prompt"]
    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        return vars
logger = logging.getLogger(__name__)

class FileDiffAnalyzer:

    def __init__(self, project: str, project_before: Project, project_after: Project, language:str, query_path: str, save_path: str, solver: FunctionResolver):
        self.name = project
        self.project_before = project_before
        self.project_after = project_after
        self.language = language
        self.query_dir = os.path.join(query_path, QUERY_PATHS["vuln_query"])
        self.save_path = save_path
        self.agent = SimpleChatCompletion()
        self.agent.use_web_logging_config(clear=True)
        ensure_directories(self.save_path)
        self.llm_response_path = os.path.join(self.save_path, "response")
        ensure_directories(self.llm_response_path)
        self.file_diff_path = os.path.join(self.save_path, FILE_TEMPLATES["file_diff_result"].format(project_name=self.name))
        self.file_diff_results = None
        self.file_diff_result_list = None
        self.file_diff_result_list_before_llm = None
        self.solver = solver
        self.load_file_diff_results()

    def load_file_diff_results(self):
        if os.path.exists(self.file_diff_path):
            logger.debug(f"file diff results already exist, loading from file")
            self.file_diff_results = load_json(self.file_diff_path)
        else:
            self.file_diff_results = self.analyze_file_differences()
        self.file_diff_result_list = self.file_diff_results.keys()
        agentlib.enable_event_dumping("/tmp/stats/")
        total_cost = agentlib.lib.agents.agent.global_event_dumper.total_cost_per_million / 1_000_000
        logger.info(f"File diff total cost: {total_cost}")

    def multi_process_query(self, file_diff_result_list):
        all_file_diff_result = {}
        diff_file = os.environ.get("DIFF_FILE")
        with open(diff_file, "r") as f:
            diff_text = f.read()
        function_data = [(function_index, self.name, self.language, diff_text) for function_index in file_diff_result_list]

        # Run the processing in parallel
        # with Pool(processes=NUM_PROCESSES) as pool:
        with Pool(processes=NUM_PROCESSES, initializer=init_pool, initargs=(self.solver,self.llm_response_path)) as pool:

            results = list(tqdm(
                pool.imap(analyze_function, function_data),
                total=len(function_data)
            ))

        for function_index, result in results:
            if result is not None:
                all_file_diff_result[function_index] = result

        return all_file_diff_result


    def analyze_file_differences(self):
        logger.info(f"Analyzing file differences for project {self.name}")
        try:
            changed_functions_path = os.environ.get("COMMIT_FUNCTIONS_INDEX")
            commits = load_json(changed_functions_path)
            commit_id = None
            for id in commits:
                if id.startswith("1_"):
                    commit_id = id
                    break
            assert commit_id is not None, "No commit found with prefix '1_'"
            changed_functions = set(commits[commit_id])
            changed_functions = set(self.solver.find_matching_indices(scope="compiled", indices=list(changed_functions))[0].values())
        except Exception as e:
            logger.error(f"Error loading function diff results: {e}")
        try:
            if self.language != "jvm":
                boundary_after = set( f"{item[0]}:{item[1]['row_start']}" for item in self.project_after.input_boundary.items())
                solved_funcs = function_resolve(boundary_after, self.language, self.solver)
                logger.info(f"Functions Resolved: {len(solved_funcs)} functions")
                boundary_after_resolved = set(solved_funcs[k] for k in solved_funcs)
                save_json(self.file_diff_path+"_boundary.json", list(boundary_after_resolved))
                save_json(self.file_diff_path+"_changed.json", list(changed_functions))
                logger.info(f"Boundary After Resolved: {len(boundary_after_resolved)} functions")
                logger.info(f"Changed Functions: {len(changed_functions)} functions")

                file_diff_result_list = boundary_after_resolved & changed_functions
            else:
                file_diff_result_list = changed_functions
        except Exception as e:
            logger.error(f"self.project_after.input_boundary error: {e}")
            file_diff_result_list = changed_functions

        save_json(self.file_diff_path+"_file_diff.json", list(file_diff_result_list))
        logger.info(f"File diff results before LLM: {len(file_diff_result_list)} functions")

        self.file_diff_result_list_before_llm = file_diff_result_list
        if os.path.exists(self.file_diff_path+"_all.json"):
            all_file_diff_result = load_json(self.file_diff_path+"_all.json")
        else:
            file_diff_result_list = set(list(file_diff_result_list))
            try:
                # Setup a timeout ⏰
                logger.info(f'⏰👀 Setting a timeout of {DIFFGUY_TIMEOUT}s to DiffGuy ⏰👀')
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(DIFFGUY_TIMEOUT)
                all_file_diff_result = self.multi_process_query(file_diff_result_list)
                signal.alarm(0)
            except TimeoutException as e:
                logger.error(f" ⏰👀 Timeout during file diff analysis: {e}. We are dumping whatever results we have!")
                files = os.listdir(self.llm_response_path)
                all_file_diff_result = {}
                for file in files:
                    with open(os.path.join(self.llm_response_path, file), "r") as f:
                        data = json.load(f)
                        all_file_diff_result.update(data)
            except Exception as e:
                all_file_diff_result = {}
                logger.error(f" 💥👀 Error during diff analysis: {e}. We are dumping whatever results we have!")
            finally:
                save_json(self.file_diff_path+"_all.json", all_file_diff_result)
        file_diff_result_after_filtered = {}
        for index in all_file_diff_result:
            if all_file_diff_result[index]["vulnerable"].lower() == "yes":
                file_diff_result_after_filtered[index] = all_file_diff_result[index]
        logger.info(f"File diff results: {len(file_diff_result_after_filtered)} functions vulnerable")
        save_json(self.file_diff_path, file_diff_result_after_filtered)

        return file_diff_result_after_filtered
