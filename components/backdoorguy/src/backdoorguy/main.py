import logging
import yaml
import statistics
import math
import time

from collections import Counter
from typing import List
from agentlib.lib.common import LLMApiBudgetExceededError
from shellphish_crs_utils.function_resolver import RemoteFunctionResolver, LocalFunctionResolver
from shellphish_crs_utils.models.oss_fuzz import AugmentedProjectMetadata
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from datetime import datetime, timedelta

from .agents import DetectorGuy
from .config import Config

logger = logging.getLogger('backdoorguy')
logger.setLevel(logging.INFO)
log = logger

class BackdoorGuy:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

        # Required parameters
        self.project_id = self.kwargs.get('project_id')
        self.project_metadata = self.kwargs.get('project_metadata')
        self.oss_fuzz_project = self.kwargs.get('oss_fuzz_project')
        self.oss_fuzz_project_src = self.kwargs.get('oss_fuzz_project_src')
        self.functions_index = self.kwargs.get('functions_index')
        self.function_jsons_dir = self.kwargs.get('functions_jsons_dir')
        self.out_path = self.kwargs.get('out_path')
        self.local_run = self.kwargs.get('local_run')

        # Process the required parameters
        with open(self.project_metadata, 'r') as f:
            self.project_yaml = AugmentedProjectMetadata.model_validate(yaml.safe_load(f))
        self.project_language = self.project_yaml.language.lower()
        self.project_name = self.project_yaml.shellphish.project_name.lower()
        with open(self.functions_index, 'r') as f:
            self.functions_index_yaml = yaml.safe_load(f)
        if self.local_run:
            self.function_resolver = LocalFunctionResolver(functions_index_path=str(self.functions_index), functions_jsons_path=str(self.function_jsons_dir))
        else:
            self.function_resolver = RemoteFunctionResolver(self.project_name, self.project_id)
        self.func_key_to_entropy = dict()
        self.cp_debug = OSSFuzzProject(project_id=self.project_id, oss_fuzz_project_path=self.oss_fuzz_project, project_source=self.oss_fuzz_project_src, use_task_service=False)

    def get_outliers(self, numbers, above_fence=True) -> List:
        """
        Calculate the Interquartile Range (IQR) of a list of numbers.
        
        IQR = Q3 - Q1, where Q1 is the first quartile (25th percentile) 
        and Q3 is the third quartile (75th percentile).
        
        Args:
            numbers (list): List of numeric values
            
        Returns:
            float: The IQR value
            
        Raises:
            ValueError: If the input list is empty
        """
        if not numbers:
            return []
        if len(numbers) == 1:
            return [0.0]
        median = statistics.median(numbers)
        q1 = statistics.quantiles(numbers, n=4)[0]
        q3 = statistics.quantiles(numbers, n=4)[2]
        iqr = q3 - q1
        upper_fence = q3 + 1.5 * iqr
        lower_fence = q1 - 1.5 * iqr
        if above_fence:
            return [num for num in numbers if num >= upper_fence]
        return [num for num in numbers if num <= lower_fence]

    def calculate_entropy(self, text):
        """
        Calculate the Shannon entropy of a string.
        
        Args:
            text (str): The input string to calculate entropy for
            
        Returns:
            float: The Shannon entropy in bits
        """
        if not text:
            return 0.0
        char_counts = Counter(text)
        text_length = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        return entropy

    def save_results(self, sus_funcs):
        if len(sus_funcs) > 0:
            # NOTE: We do not want to trigger discoveryguy if the results is empty.
            with open(self.out_path, 'w') as f:
                yaml.dump({'sus_funcs': sus_funcs}, f, default_flow_style=False)
            log.info(f'Saved the results to {self.out_path}')
        else:
            log.info(f'Not saving results since we have 0 sus functions!')

    def take_a_nap(self):
        # NOTE: this will make the agent nap until the next budget tick.
        logger.info(f'😴 Nap time! I will be back in a bit...')

        waking_up_at = datetime.now() + timedelta(minutes=Config.nap_duration - (datetime.now().minute % Config.nap_duration))

        while True:
            if datetime.now() >= waking_up_at:
                logger.info(f'🫡 Nap time is over! Back to work...')
                break
            else:
                time.sleep(Config.nap_snoring)

    def run(self):
        sus_funcs = []
        try:
            for func_key in self.functions_index_yaml.keys():
                if 'fuzz' in func_key:
                    continue
                func_index = self.function_resolver.get(func_key)
                self.func_key_to_entropy[func_key] = self.calculate_entropy(func_index.code)
            
            self.func_key_to_entropy = dict(sorted(self.func_key_to_entropy.items(), key=lambda item: item[1], reverse=False))
            func_key_to_entropy_vals = list(self.func_key_to_entropy.values())
            median_val = statistics.median(func_key_to_entropy_vals)
            
            outliers = self.get_outliers(func_key_to_entropy_vals, above_fence=True)
            
            # Limit the number of outliers.
            if len(outliers) > Config.max_outliers:
                log.info(f'Found {len(outliers)} outliers, which is more than 10. Will not print them all.')
                outliers = outliers[:Config.max_outliers]
            
            # Check all the outliers with the LLM!
            for k, v in self.func_key_to_entropy.items():
                
                if v in outliers:
                    log.info(f'Function {k} has an entropy of {v}, which is an outlier.')
                    func_index = self.function_resolver.get(k)
                    
                    curr_llm_index = 0
                    how_many_naps = 0

                    # 🐶
                    detector = DetectorGuy(
                                           language=self.project_language, 
                                           function_name=func_index.funcname, 
                                           project_name=self.cp_debug.project_name, 
                                           code=func_index.code, 
                                           local_run=True
                                           )

                    # Set the first model according to the list
                    agent_current_llm = Config.backdoorguy_models[curr_llm_index]
                    detector.__LLM_MODEL__ = agent_current_llm
                    detector.llm  = detector.get_llm_by_name(agent_current_llm, **detector.__LLM_ARGS__) 

                    # 💰🔄
                    while True:
                        try:
                            res = detector.invoke()
                            answer = res.chat_messages[-1].content

                            if answer == 'yes':
                                log.info(f'  - Detected a possible backdoor in function {k} with entropy {v}.')
                                log.info(f'    - Function code:\n{func_index.code}')
                                sus_funcs.append(k)

                            # 💰⛓️‍💥 We are done here, move to the next function.
                            break

                        except LLMApiBudgetExceededError as e:
                            curr_llm = detector.__LLM_MODEL__
                            curr_llm_index += 1
                            logging.warning(f"💸🤖🐶 Backdoorguy ran out of budget for model {curr_llm}")
                            try:
                                if curr_llm_index < len(Config.backdoorguy_models):
                                    
                                    # Switching agent to another model 🐶
                                    detector = DetectorGuy(
                                                           language=self.project_language, 
                                                           function_name=func_index.funcname, 
                                                           project_name=self.cp_debug.project_name, 
                                                           code=func_index.code, 
                                                           local_run=True
                                                           )
                                    agent_current_llm = Config.backdoorguy_models[curr_llm_index]
                                    logger.info(f'🔁🤖🐶 Switching Backdoorguy to model {agent_current_llm}')
                                    detector.__LLM_MODEL__ = agent_current_llm
                                    detector.llm  = detector.get_llm_by_name(agent_current_llm, **detector.__LLM_ARGS__)
                                    # 💰▶️
                                    continue
                                else:
                                    # If we run out of LLM to try, we need to take a nap...
                                    how_many_naps += 1
                                    if how_many_naps > Config.nap_becomes_death_after:
                                        logging.error(f"🪦 Exhausted number of naps in a row for BackdoorGuy...")
                                        self.save_results(sus_funcs)
                                        exit(0)
                                    else:
                                        # NOTE: we nap if we do not have any new LLM to switch to.
                                        curr_llm_index = 0
                                        self.take_a_nap()
                                        # Switch to the first model and try again!
                                        detector = DetectorGuy(
                                                               language=self.project_language, 
                                                               function_name=func_index.funcname, 
                                                               project_name=self.cp_debug.project_name, 
                                                               code=func_index.code, 
                                                               local_run=True
                                                               )
                                        agent_current_llm = Config.backdoorguy_models[curr_llm_index]
                                        logger.info(f'🔁🤖🐶 Switching BackdoorGuy to model {agent_current_llm} after nap!')
                                        detector.__LLM_MODEL__ = agent_current_llm
                                        detector.llm  = detector.get_llm_by_name(agent_current_llm, **detector.__LLM_ARGS__)
                                        # 💰▶️
                                        continue
                            except Exception as e:
                                logging.error(f'😮‍💨 Something went VERY wrong during BackdoorGuy model switching. Aborting.')
                                self.save_results(sus_funcs)
                                exit(0)
        
        except Exception as e:
            logger.warning(f'An error occurred while running backdoorguy - {e}. Skipping this')
            self.save_results(sus_funcs)
            exit(0)
    
        self.save_results(sus_funcs)

def main(**kwargs):
    backdoorGuy = BackdoorGuy(**kwargs)
    backdoorGuy.run()
