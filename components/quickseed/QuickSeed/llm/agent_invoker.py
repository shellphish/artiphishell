import logging
import os
import shutil
import subprocess
import tempfile

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple
import uuid
from datetime import datetime, timedelta
import time
import copy

import yaml
import hashlib
from agentlib import AgentPlanStep, AgentPlan, ObjectParser
from agentlib.lib.common import LLMApiBudgetExceededError, LLMApiRateLimitError
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from jinja2 import Environment, FileSystemLoader, Template

from agentlib.lib.agents.agent import global_event_dumper
from .agents import SeedGeneratorAgent, HaOutput, ReflectionAnalyzerAgent, RaOutput, BlockerAnalyzerAgent, SgOutput, \
    BaseTask, SeedGeneratorTask, SiOutput, SinkIdentifierAgent, WarmUpAgent, WuOutput, DetermineReachibilityOutput,\
    SarifAnalyzerAgent, DetermineVulnerabilityOutput, SarifReportAnalyzerTask, DiffAnalyzerAgent, \
    DiffAnalyzerTask, DiffBlockerAgent
from ..utils import LLMLocalBudgetExceededError
from QuickSeed.data.metadata import Config
_l = logging.getLogger(__name__)

# TODO(finaldeploy)
# Set to 60 or 80
QUICKSEED_LLM_BUDGET = 80

class AgentInvoker(ABC):
    def __init__(self, agent_plan: Path, cp_root: Path, function_indices: Path, function_json_dir: Path, model: str, benign_seeds_dir: Optional[Path] = None, fall_back_python_script: Optional[Path] = None):
        self.agent_plan = agent_plan
        self.cp_root = cp_root
        self.function_indices = function_indices
        self.function_json_dir = function_json_dir
        self.model = model
        self.fall_back_python_script = fall_back_python_script
        self.benign_seeds_dir = benign_seeds_dir

    def __repr__(self):
        return (f'AgentInvoker(agent_plan={self.agent_plan}, \n'
                f'cp_root={self.cp_root}, \n'
                f'function_indices={self.function_indices}')

    def __call__(self, task: BaseTask, *args, **kwargs):
        return self.operate(task, *args, **kwargs)

    def operate(self, task: BaseTask, *args, **kwargs):    
        return self._invoke(task, *args, **kwargs)

    def generate_plan(self, plan_file, output_object, **kwargs):
        return self._generate_plan(plan_file, output_object, **kwargs)

    @abstractmethod
    def _invoke(self, *args, **kwargs):
        """
        Invoke LLM agent
        """
        pass

    def _generate_plan(self, plan_file, output_object, **kwargs):
        """
        Generate a plan for the agent to follow
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        _l.debug(f"current_dir is {current_dir}")
        prompt_dir = os.path.join(current_dir, "agents", "prompts")
        plan_dir = os.path.join(current_dir, "agents", "plans")
        _l.debug(f"files in dirs are {os.listdir(prompt_dir)}")
        _l.debug(f"files in dirs are {os.listdir(plan_dir)}")
        plan_file = os.path.join(plan_dir, plan_file)
        with open(plan_file, 'r') as f:
            steps_yaml: List = yaml.safe_load(f).values()

        chosen_steps = steps_yaml
        _l.debug(f"chosen_steps is {chosen_steps}")
        assert chosen_steps is not None
        steps = list(map(
            lambda s: AgentPlanStep(llm_model=self.model,
                                    name=s['name'],
                                    description=Template(s['description']).render(
                                        **kwargs
                                    )),
            chosen_steps))
        for step in steps:
            if step.name == "determine_reachibility":
                step.output_parser = ObjectParser(kwargs["determine_reachibility_object"], use_fallback=True)
            if step.name == "determine_vulnerability":
                step.output_parser = ObjectParser(kwargs["determine_vulnerability_object"], use_fallback=True)
        # this would save it in json format.
        # hack - sometimes gpt changes the keys or adds spaces to json keynames. below is example of how to handle that
        # 'The output MUST be in the following JSON format and use the same keys OR I WILL DIE.\n' +
        # '{"equivalent": "Answer in Yes or No", "details": details_of_changes}'
        steps.append(AgentPlanStep(llm_model=self.model,
                                   name="some_final_step",
                                   description="Save data in a text format. ",
                                   output_parser=ObjectParser(output_object, use_fallback=True)))
        plan = AgentPlan(steps=steps)
        return plan.save_copy()

    def _render_call_chain_prompt(self, functions, calling_relationship: Optional[List] = None):
        env = Environment(loader=FileSystemLoader(Path(__file__).parent / 'agents' / 'prompts'))
        template = env.get_template('call_chain.j2')
        if not calling_relationship:
            calling_relationship = []
        function_map = {f.id: f for f in functions}
        prompt = template.render(
            functions=functions,
            function_map=function_map,
            calling_relationship=calling_relationship
        )
        return prompt
    
    def execute_generated_python_script(self, script: Path, cwd: Path) -> Path:
        try:
            p = subprocess.run(["python3", script], capture_output=True, text=True, errors="ignore",
                                cwd=cwd)
        except Exception as e:
            _l.error(f"error occured {e} when generating seeds")
            return None
        # if p.returncode != 0:
        #     _l.debug(f"{p.stderr}")
        filenames = [item.name for item in cwd.iterdir()]
        if "output" in filenames and len(os.listdir(cwd/"output")) > 0:
            seed = cwd / "output"
            for file in seed.iterdir():
                random_name = str(uuid.uuid4()) + ".bin"
                shutil.copy(file, Path(self.benign_seeds_dir) / random_name)
        else:
            seed = cwd / "output.bin"
            if seed.exists():
                random_name = str(uuid.uuid4()) + ".bin"
                shutil.copy(seed, Path(self.benign_seeds_dir) / random_name)
        return seed

    def execute_generated_python_scripts(self, script_dir: Path, md5hash: List):
        script_seed_list = []
        for gen_seed_script in script_dir.iterdir():
            if gen_seed_script.suffix != ".py":
                continue
            tmpdir = Path(tempfile.mkdtemp())
            _l.info(f"the files is saved to {tmpdir}")
            shutil.copy(gen_seed_script, tmpdir)
            new_script = tmpdir / gen_seed_script.name
            seed = self.execute_generated_python_script(new_script, tmpdir)
            if seed and seed.exists():
                found = False
                if Path(seed).is_file():
                    with open(seed, "rb") as f:
                        md5 = hashlib.md5(f.read()).hexdigest()
                    if md5 in md5hash:
                        continue
                elif Path(seed).is_dir():
                    for seed_file in seed.iterdir():
                        with open(seed_file, "rb") as f:
                            md5 = hashlib.md5(f.read()).hexdigest()
                        if md5 in md5hash:
                            found = True
                            break
                if found:
                    continue
                script_seed_list.append((new_script, seed))
                md5hash.append(md5)
        return script_seed_list

    def process_llm_gen_scripts_result(self, script: str)-> List[Tuple[Path, Path]]:
        tmpdir = Path(tempfile.mkdtemp())
        _l.info(f"the files is saved to {tmpdir}")
        seed_gen_scripts = tmpdir / "gen_seed.py"
        with open(seed_gen_scripts, "w") as f:
            f.write(script)

        script_seed_list = []
        md5hash = []
        seed = self.execute_generated_python_script(seed_gen_scripts, tmpdir)
        if seed and seed.exists():
            if Path(seed).is_file():
                with open(seed, "rb") as f:            
                    md5hash.append(hashlib.md5(f.read()).hexdigest)
            elif Path(seed).is_dir():
                for seed_file in seed.iterdir():
                    with open(seed_file, "rb") as f:
                        md5 = hashlib.md5(f.read()).hexdigest()
                        md5hash.append(md5)
            script_seed_list.append((seed_gen_scripts, seed))
        if self.fall_back_python_script:
            script_seed_list.extend(self.execute_generated_python_scripts(self.fall_back_python_script, md5hash))
            if len(script_seed_list) == 0:
                _l.error(f"No output file generated by the fallback script {self.fall_back_python_script} or the generated script {seed_gen_scripts}")
        return script_seed_list
    
    def check_local_llm_budget(self):
        llm_used = global_event_dumper.total_cost_per_million / 1000000
        if llm_used >= QUICKSEED_LLM_BUDGET:
            raise LLMLocalBudgetExceededError(
                f"LLM budget exceeded: {llm_used} >= {QUICKSEED_LLM_BUDGET}. Skipping seed generation."
            )
        
    # This agent needs to be a new fresh agent not the one that is already running.
    def retry_on_llm_budget_exceeded(self, agent):
        current_model = agent.plan.steps[0].llm_model
        # original_agent = copy.deepcopy(agent)
        # plan = original_agent.plan
        plan = agent.plan
        if "claude" in current_model:
            _l.warning("Claude model LLM budget exceeded, retrying with a different model.")
            new_model = "o4-mini"
        elif "gpt" in current_model or "o4" in current_model or "o3" in current_model:
            _l.warning("GPT model LLM budget exceeded, retrying with a different model.")
            new_model = "claude-4-sonnet"
        elif "gemini" in current_model:
            _l.warning("Gemini model LLM budget exceeded, retrying with a different model.")
            new_model = "claude-4-sonnet"
        steps = plan.steps
        for step in steps:
            step.llm_model = new_model
        # original_agent.plan = plan
        # return original_agent
        current_step = plan.get_current_step()
        if current_step:
            current_step.reset()
        agent.plan = plan
        return agent
    # make sure this is the fresh agent, not the one that is already running.
    def switch_model_for_agent(self, agent, model):
        """
        Switch the model for the agent.
        This is used when the current model is not working and we need to switch to a different model.
        """
        plan = agent.plan
        for step in plan.steps:
            step.llm_model = model
        current_step = plan.get_current_step()
        if current_step:
            current_step.reset()
        agent.plan = plan
        return agent
    
    def take_a_nap(self, nap_duration: Optional[int] = None):
        # COPY FROM DG
        # NOTE: this will make the agent nap until the next budget tick.
        _l.info('😴 Nap time! I will be back in a bit...')
        # Go to the next multiple of Config.nap_duration
        # For example, if Config.nap_duration is 5, and the current minute is 12,
        # we will wake up at 15.
        if not nap_duration:
            nap_duration = Config.nap_duration    
        waking_up_at = datetime.now() + timedelta(minutes=nap_duration - (datetime.now().minute % nap_duration))

        while True:
            if datetime.now() >= waking_up_at:
                _l.info('🫡 Nap time is over! Back to work...')
                break
            else:
                time.sleep(Config.nap_snoring)
    
    def invoke_agent_with_nap(self, agent):
        self.nap_count = 0
        llm_rate_limit_try_count = 0
        # original_agent = copy.deepcopy(agent)
        current_model = self.model
        retry_on_other_exception = 0
        if current_model in Config.backup_models:
            current_model_ind = Config.backup_models.index(current_model)
            next_model_ind = (current_model_ind + 1) % len(Config.backup_models) 
        else:
            import random
            next_model_ind = random.randint(0, len(Config.backup_models) - 1)
        while True:
            try:
                res = agent.invoke()
                return res
            except LLMApiBudgetExceededError as e:
                _l.warning(f"LLM API budget exceeded: {e}. Retrying with a different model.")
                # agent = self.retry_on_llm_budget_exceeded(original_agent)
                agent = self.retry_on_llm_budget_exceeded(agent)
                try:
                    res = agent.invoke()
                    return res
                except LLMApiBudgetExceededError as e:
                    _l.error("Both models have exceeded the budget!")
                    self.nap_count += 1
                    if self.nap_count > Config.nap_becomes_death_after:
                        _l.error("Nap time exceeded the limit, terminating the agent.")
                        raise LLMApiBudgetExceededError(
                            "LiteLLM API budget exceeded"
                        )
                    self.take_a_nap()
            except LLMApiRateLimitError as e:
                # from remote_pdb import RemotePdb; RemotePdb('0.0.0.0', 4444).set_trace()
                llm_rate_limit_try_count += 1
                _l.error(f"LLM API rate limit exceeded: {e}. Retrying with a different model.")
                try:
                    if llm_rate_limit_try_count > len(Config.backup_models):
                        _l.error("All backup models have been tried and failed due to rate limits.")
                        llm_rate_limit_try_count = 0
                        # Switch agent to the next model
                        current_model_ind = next_model_ind
                        current_model = Config.backup_models[current_model_ind]
                        # agent = self.switch_model_for_agent(original_agent, current_model)
                        agent = self.switch_model_for_agent(agent, current_model)
                        _l.info(f"We have tried all backup models, taking a nap and retrying with the next model {current_model}...")
                        if self.nap_count > Config.nap_becomes_death_after:
                            _l.error("Nap time exceeded the limit, terminating the agent.")
                            raise LLMApiRateLimitError("LiteLLM API rate limit exceeded")
                        # Take a 3 minutes nap before retrying
                        self.take_a_nap(nap_duration=3)
                        self.nap_count += 1
                        _l.info(f"We are back, switching to model {current_model} and retrying...")
                    else:
                        # Switch agent to the next model
                        current_model_ind = next_model_ind
                        current_model = Config.backup_models[current_model_ind]
                        # agent = self.switch_model_for_agent(original_agent, current_model)
                        agent = self.switch_model_for_agent(agent, current_model)
                        _l.info(f"Switching to model {current_model} and retrying...")
                    next_model_ind = (current_model_ind + 1) % len(Config.backup_models)
                except Exception as e:
                    if retry_on_other_exception > Config.max_retry_on_other_exception:
                        _l.error("Max retry on other exception reached, terminating the agent.")
                        return None
                    _l.error(f"Error occurred while switching model: {e}")
                    current_model_ind = next_model_ind
                    current_model = Config.backup_models[current_model_ind]
                    time.sleep(30)
                    retry_on_other_exception += 1
                    # agent = self.switch_model_for_agent(original_agent, Config.backup_models[next_model_ind])
                    agent = self.switch_model_for_agent(agent, Config.backup_models[next_model_ind])
                    next_model_ind = (current_model_ind + 1) % len(Config.backup_models)
                
            except Exception as e:     
                if retry_on_other_exception > Config.max_retry_on_other_exception:
                    _l.error("Max retry on other exception reached, terminating the agent.")
                    return None
                _l.error(f"Error occurred while switching model: {e}")
                current_model_ind = next_model_ind
                current_model = Config.backup_models[current_model_ind]
                time.sleep(30)
                retry_on_other_exception += 1
                # agent = self.switch_model_for_agent(original_agent, Config.backup_models[next_model_ind])
                agent = self.switch_model_for_agent(agent, Config.backup_models[next_model_ind])
                next_model_ind = (current_model_ind + 1) % len(Config.backup_models)
                
        return None
            

class SeedGenerator(AgentInvoker):
    def __init__(
            self,
            agent_plan: Path,
            cp_root: Path,
            function_indices: Path,
            function_json_dir: Path,
            model: str,
            benign_seeds_dir: Path,
            fall_back_python_script: Path
    ):
        super().__init__(agent_plan, cp_root, function_indices, function_json_dir, model, benign_seeds_dir=benign_seeds_dir, fall_back_python_script=fall_back_python_script)

    def _invoke(self, task: SeedGeneratorTask):

        """
        Generates and executes a harness agent to produce interesting seeds.

        Args:
            agent_path (str): Path to save the agent's state.
            harness_code (str): The code for the harness.
            source_and_traces (str): Source code and trace information.
            jazzer_sanitizer_description (List[str]): List of sanitizer descriptions.
            model (str): The model to use for the agent.
            pois_reason (Optional[str], optional): Reason for points of interest. Defaults to None.

        Returns:
            Tuple[Optional[Path], Optional[Path]]: Paths to the generated seed script and seed file, or None if generation failed.
        """
        self.check_local_llm_budget()
        plan = self.generate_plan("seed_generator_plans.yaml", HaOutput, 
                                  determine_reachibility_object=DetermineReachibilityOutput)
        harness_code = task.harness_code
        jazzer_sanitizer_description = task.jazzer_sanitizer_description
        source_and_traces = self._render_call_chain_prompt(task.node_path, task.edge_path)
        _l.debug(f"plan is saved at {self.agent_plan}")

        new_steps = []
        if task.node_path[0].function_name == "fuzzerTestOneInput":
            for i, step in enumerate(plan.steps):
                if step.name != "determine_reachibility":
                    new_steps.append(step)
            plan.steps = new_steps
        agent: SeedGeneratorAgent = SeedGeneratorAgent.reload_id_from_file_or_new(
            self.agent_plan,
            goal="generate interesting seeds",
            plan=plan,
            harness_code=harness_code,
            source_and_traces=source_and_traces,
            jazzer_sanitizer_description=jazzer_sanitizer_description,
            fall_back_python_script=self.fall_back_python_script
        )


        # agent.use_web_logging_config()

        agent.warn("========== Running agent ==========\n")
        res = self.invoke_agent_with_nap(agent)
        if not res:
            _l.error("Agent invocation failed, returning None.")
            return task, (None, None)
        
        if res.generate_seed_python_script.lower() == "no":
            return task, (res, [])
        script = res.generate_seed_python_script.split("\n")
        if "```" in res.generate_seed_python_script:
            script = script[1:-1]
        _l.debug(f"The script dumping in gen_seed.py is {script}")

        script = "\n".join(script)

        script_seed_list = self.process_llm_gen_scripts_result(script)
        return task, (res, script_seed_list)
    


class ReflectionAnalyzer(AgentInvoker):
    def __init__(
            self,
            agent_plan: Path,
            cp_root: Path,
            function_indices: Path,
            function_json_dir: Path,
            model: str,
            seed_output_dir: Path,
            benign_seeds_dir: Path,
            fall_back_python_script: Path
    ):
        super().__init__(agent_plan, cp_root, function_indices, function_json_dir, model, benign_seeds_dir=benign_seeds_dir, fall_back_python_script=fall_back_python_script)
        self.seed_output_dir = seed_output_dir

    def _invoke(self, task):
        self.check_local_llm_budget()
        plan = self.generate_plan("reflection_analyzer_plans.yaml", RaOutput)
        broken_call_chain = self._render_call_chain_prompt(task.node_path)
        function_names = [f.function_name for f in task.node_path]
        agent: ReflectionAnalyzerAgent = ReflectionAnalyzerAgent.reload_id_from_file_or_new(
            self.agent_plan,
            goal="generate inputs that invoke reflection call",
            plan=plan,
            broken_call_chain=broken_call_chain,
            function_names=function_names,
            fall_back_python_script=self.fall_back_python_script,
        )

        # agent.use_web_logging_config()

        agent.warn("========== Running agent ==========\n")

        env_var_config = {
            "AIXCC_FUNCTION_INDEXER_PATH": str(self.function_indices),
            "AIXCC_FUNCTION_JSON_DIR": str(self.function_json_dir),
            "AIXCC_CP_ROOT": str(self.cp_root),
            "AIXCC_HARNESS_NAME": task.harness_name,
            "AIXCC_FALLBACK_SCRIPT_DIR": str(self.fall_back_python_script),
            "AIXCC_PROJECT_SOURCE": str(task.project_source),
        }
        # set_env_vars_for_llm_tools might have porblems in multi threading
        os.environ.update(env_var_config)
        res = agent.invoke()
        _l.debug(f"res is {res}")
        script = res.generate_seed_script.split("\n")
        if "```" in res.generate_seed_script:
            script = script[1:-1]
        _l.debug(f"The script dumping in gen_seed.py is {script}")

        script = "\n".join(script)

        script_seed_list = self.process_llm_gen_scripts_result(script)
        return task, script_seed_list
    

class BlockerAnalyzer(AgentInvoker):
    def __init__(self, agent_plan: Path, cp_root: Path, function_indices: Path, function_json_dir: Path, \
                 model: str, benign_seeds_dir: Path, fall_back_python_script: Path, function_resolver: FunctionResolver,\
                    oss_fuzz_build: OSSFuzzProject):
        super().__init__(agent_plan, cp_root, function_indices, function_json_dir, model, benign_seeds_dir, fall_back_python_script)
        self.function_resolver = function_resolver
        self.oss_fuzz_build = oss_fuzz_build  
        
    def _invoke(self, task):
        # Create a plan for the agent to follow.
        self.check_local_llm_budget()
        plan = self.generate_plan("blocker_analyzer_plans.yaml", SgOutput,
                                  stuck_function_name=task.stuck_function_name, 
                                  stuck_function_src=task.stuck_function_src,
                                  next_function_name=task.next_function_name, 
                                  script=task.script)

        harness_code = task.harness_code
        source_code = task.source_code
        stuck_function_name = task.stuck_function_name
        stuck_function_src = task.stuck_function_src
        next_function_name = task.next_function_name
        next_function_src = task.next_function_src
        agent: BlockerAnalyzerAgent = BlockerAnalyzerAgent.reload_id_from_file_or_new(
            self.agent_plan,
            goal='yolo',
            plan=plan,
            harness_code=harness_code,
            source_code=source_code,
            stuck_function_name=stuck_function_name,
            stuck_function_src=stuck_function_src,
            next_function_name=next_function_name,
            fall_back_python_script=self.fall_back_python_script,
            next_function_src=next_function_src,
            jazzer_sanitizer_description=task.jazzer_sanitizer_description,
            harness_name=task.harness_name,
            function_indexer_path=self.function_indices,
            function_json_dir=self.function_json_dir,
            cp_root=self.cp_root,
            project_source=task.project_source,
            function_resolver=self.function_resolver,
            oss_fuzz_build=self.oss_fuzz_build,
        )

        # agent.use_web_logging_config()

        agent.warn('========== Agents plan ==========\n')
        # print(agent)
        # print(agent.plan)

        agent.warn('========== Running agent ==========\n')

        # env_var_config = {
        #     "AIXCC_FUNCTION_INDEXER_PATH": str(self.function_indices),
        #     "AIXCC_FUNCTION_JSON_DIR": str(self.function_json_dir),
        #     "AIXCC_CP_ROOT": str(self.cp_root),
        #     "AIXCC_HARNESS_NAME": task.harness_name,
        #     "AIXCC_FALLBACK_SCRIPT_DIR": str(self.fall_back_python_script),
        #     "AIXCC_PROJECT_SOURCE": str(task.project_source),
        # }
        # # set_env_vars_for_llm_tools might have porblems in multi threading
        # os.environ.update(env_var_config)

        res = self.invoke_agent_with_nap(agent)
        if not res:
            _l.error("Agent invocation failed, returning None.")
            return task, None
        script = res.generate_input_script.split("\n")
        if "```" in res.generate_input_script:
            script = script[1:-1]
        _l.debug(f"The script dumping in gen_seed.py is {script}")

        script = "\n".join(script)
        script_seed_list = self.process_llm_gen_scripts_result(script)
        return task, script_seed_list


class SinkIdentifier(AgentInvoker):
    def __init__(self, agent_plan: Path, cp_root: Path, function_indices: Path, function_json_dir: Path, model: str):
        super().__init__(agent_plan, cp_root, function_indices, function_json_dir, model)

    def _invoke(self, task):
        self.check_local_llm_budget()
        current_dir = os.path.dirname(os.path.abspath(__file__))
        plan_dir = os.path.join(current_dir, "agents", "plans")
        with open(Path(plan_dir) / "sink_identifiers_traits.yaml", 'r') as f:
            sink_identifiers_traits = yaml.safe_load(f)
            additional_info = sink_identifiers_traits.get(task.sanitizer_name, None)
        plan = self.generate_plan("sink_identifier_plans.yaml", SiOutput,
                                  sanitizer_name=task.sanitizer_name,
                                  additional_info=additional_info)

        agent: SinkIdentifierAgent = SinkIdentifierAgent.reload_id_from_file_or_new(
            self.agent_plan,
            goal="identify vulnerable sinks",
            plan=plan,
            methods=task.methods,
            sanitizer_name=task.sanitizer_name
        )

        # agent.use_web_logging_config()

        agent.warn("========== Running agent ==========\n")
        res = agent.invoke()

        _l.debug(f"res is {res}")
        return task, res.identified_sinks
    
    
class WarmUp(AgentInvoker):
    def __init__(self, agent_plan: Path, cp_root: Path, function_indices: Path, function_json_dir: Path, \
                 model: str, fall_back_python_script: Path, function_resolver: FunctionResolver,\
                benign_seeds_dir: Path, oss_fuzz_build: OSSFuzzProject):
        super().__init__(agent_plan, cp_root, function_indices, function_json_dir, model, benign_seeds_dir=benign_seeds_dir,fall_back_python_script=fall_back_python_script)
        self.function_resolver = function_resolver
        self.oss_fuzz_build = oss_fuzz_build  
    
    def _invoke(self, task):
        self.check_local_llm_budget()
        plan = self.generate_plan("warm_up_plans.yaml", WuOutput)
        with open(task.harness_filepath, "r") as f:
            harness_code = f.read()
        agent: WarmUpAgent = WarmUpAgent.reload_id_from_file_or_new(
            self.agent_plan,
            goal="generate initial fuzzing inputs",
            plan=plan,
            harness_code=harness_code,
            fall_back_python_script=self.fall_back_python_script,
            function_indexer_path=self.function_indices,
            function_json_dir=self.function_json_dir,
            cp_root=self.cp_root,
            project_source=task.project_source,
            function_resolver=self.function_resolver,
            oss_fuzz_build=self.oss_fuzz_build,
            harness_name=task.harness_name,
            
        )
        # agent.use_web_logging_config()

        agent.warn("========== Running agent ==========\n")

        res = self.invoke_agent_with_nap(agent)
        if not res:
            _l.error("Agent invocation failed, returning None.")
            return task, None
        script = res.generated_seed_script.split("\n")
        if "```" in res.generated_seed_script:
            script = script[1:-1]
        _l.debug(f"The script dumping in gen_seed.py is {script}")

        script = "\n".join(script)
        script_seed_list = self.process_llm_gen_scripts_result(script)

        _l.debug(f"res is {res}")
        return task, script_seed_list
    
class SarifReportAnalyzer(AgentInvoker):
    def __init__(self, agent_plan: Path, cp_root: Path, function_indices: Path, 
                 function_json_dir: Path, model: str, benign_seeds_dir: Path, 
                 fall_back_python_script: Path, oss_fuzz_build: OSSFuzzProject, 
                 function_resolver: FunctionResolver, covered_functions: Optional[str] = None, 
                 previous_script: Optional[str] = None):
        super().__init__(agent_plan, cp_root, function_indices, function_json_dir, model, 
                         benign_seeds_dir=benign_seeds_dir, fall_back_python_script=fall_back_python_script)
        self.covered_functions = covered_functions
        self.previous_script = previous_script
        self.function_resolver = function_resolver
        self.oss_fuzz_build = oss_fuzz_build

    def _invoke(self, task: SarifReportAnalyzerTask, plan_name: str, output_object):
        self.check_local_llm_budget()
        jazzer_sanitizer_description = task.jazzer_sanitizer_description
        vulnerability_types = []
        for desc in jazzer_sanitizer_description:
            vulnerability_types.append(desc["Vulnerability Class"])
        plan = self.generate_plan(plan_name, output_object,
                                  vulnerability_types=vulnerability_types,
                                  enumerate=enumerate,
                                  determine_vulnerability_object=DetermineVulnerabilityOutput,
                                  determine_reachibility_object=DetermineReachibilityOutput,
                                  functions=self.covered_functions)
        new_steps = []
        if task.node_path[0].function_name == "fuzzerTestOneInput":
            for i, step in enumerate(plan.steps):
                if step.name != "determine_reachibility":
                    new_steps.append(step)
            plan.steps = new_steps
        
        with open(task.harness_filepath, "r") as f:
            harness_code = f.read()
        source_and_traces = self._render_call_chain_prompt(task.node_path)
        agent: SarifAnalyzerAgent = SarifAnalyzerAgent.reload_id_from_file_or_new(
            self.agent_plan,
            goal="generate inputs that invoke reflection call",
            plan=plan,
            harness_code=harness_code,
            jazzer_sanitizer_description=jazzer_sanitizer_description,
            fall_back_python_script=self.fall_back_python_script,
            rule_id=task.rule_id,
            message=task.message,
            data_flows=task.data_flow_codes,
            sink_function=task.function_code,
            previous_script=self.previous_script,
            harness_name=task.harness_name,
            function_indexer_path=self.function_indices,
            function_json_dir=self.function_json_dir,
            cp_root=self.cp_root,
            project_source=task.project_source,
            function_resolver=self.function_resolver,
            oss_fuzz_build=self.oss_fuzz_build,
            source_and_traces=source_and_traces,
        )

        # agent.use_web_logging_config()
        agent.warn("========== Running agent ==========\n")
        res = self.invoke_agent_with_nap(agent)
        if not res:
            return task, (None, None)
        if "no" == res.generate_input_script.lower():
            _l.debug(f"no input script generated")
            return task, (res, None)
        script = res.generate_input_script.split("\n")
        if "```" in res.generate_input_script:
            script = script[1:-1]
        _l.debug(f"The script dumping in gen_seed.py is {script}")

        script = "\n".join(script)
        script_seed_list = self.process_llm_gen_scripts_result(script)

        _l.debug(f"res is {res}")
        return task, (res, script_seed_list)
    
class DiffAnalyzer(AgentInvoker):
    def __init__(self, agent_plan: Path, cp_root: Path, function_indices: Path, function_json_dir: Path, model: str, \
                 benign_seeds_dir: Path, fall_back_python_script: Path, previous_script: Optional[str] = None, covered_functions: Optional[List[str]] = None):
        super().__init__(agent_plan, cp_root, function_indices, function_json_dir, model, benign_seeds_dir=benign_seeds_dir, fall_back_python_script=fall_back_python_script)
        self.previous_script = previous_script
        self.covered_functions = covered_functions

    def _invoke(self, task: DiffAnalyzerTask, plan_name: str, output_object):
        self.check_local_llm_budget()
        jazzer_sanitizer_description = task.jazzer_sanitizer_description
        vulnerability_types = []
        for desc in jazzer_sanitizer_description:
            vulnerability_types.append(desc["Vulnerability Class"])
        plan = self.generate_plan(plan_name, output_object,
                                  vulnerability_types=vulnerability_types,
                                  enumerate=enumerate,
                                  determine_vulnerability_object=DetermineVulnerabilityOutput,
                                  determine_reachibility_object=DetermineReachibilityOutput,
                                  functions=self.covered_functions,
                                  call_chains=task.call_chains,
                                  )

        with open(task.harness_filepath, "r") as f:
            harness_code = f.read()
        if not self.previous_script:
            agent: DiffAnalyzerAgent = DiffAnalyzerAgent.reload_id_from_file_or_new(
                self.agent_plan,
                goal="generate inputs that trigger commit function",
                plan=plan,
                harness_code=harness_code,
                jazzer_sanitizer_description=jazzer_sanitizer_description,
                fall_back_python_script=self.fall_back_python_script,
                commit_function=task.commit_function,
                call_chains = task.call_chains,
                functions_on_call_chains = task.functions_on_call_chains,
            )
        else:
            agent: DiffBlockerAgent = DiffBlockerAgent.reload_id_from_file_or_new(
                self.agent_plan,
                goal="generate inputs that trigger commit function",
                plan=plan,
                harness_code=harness_code,
                jazzer_sanitizer_description=jazzer_sanitizer_description,
                fall_back_python_script=self.fall_back_python_script,
                commit_function=task.commit_function,
                call_chains = task.call_chains,
                functions_on_call_chains = task.functions_on_call_chains,
                previous_script=self.previous_script,
            )
        
        # agent.use_web_logging_config()

        agent.warn("========== Running agent ==========\n")

        env_var_config = {
            "AIXCC_FUNCTION_INDEXER_PATH": str(self.function_indices),
            "AIXCC_FUNCTION_JSON_DIR": str(self.function_json_dir),
            "AIXCC_CP_ROOT": str(self.cp_root),
            "AIXCC_HARNESS_NAME": task.harness_name,
            "AIXCC_FALLBACK_SCRIPT_DIR": str(self.fall_back_python_script),
            "AIXCC_PROJECT_SOURCE": str(task.project_source),
        }
        # set_env_vars_for_llm_tools might have porblems in multi threading
        os.environ.update(env_var_config)
        # with set_env_vars_for_llm_tools(env_var_config):
        #     assert os.environ["AIXCC_FUNCTION_INDEXER_PATH"] == str(self.function_indices)
        res = agent.invoke()

        if "no" == res.generate_input_script.lower():
            _l.debug(f"no input script generated")
            return task, (res, None)
        script = res.generate_input_script.split("\n")
        if "```" in res.generate_input_script:
            script = script[1:-1]
        _l.debug(f"The script dumping in gen_seed.py is {script}")

        script = "\n".join(script)
        script_seed_list = self.process_llm_gen_scripts_result(script)

        _l.debug(f"res is {res}")
        return task, (res, script_seed_list)