#!/usr/bin/env python3
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Tuple, Union
import random
import string


from agentlib import (
    PlanExecutor,
    AgentResponse,
    AgentPlan,
    AgentPlanStep,
    SaveLoadObject,
    Field,
    ObjectParser,
    AgentPlanStepAttempt,
    CriticReview,
    enable_event_dumping,
    set_global_budget_limit
)
from shellphish_crs_utils.function_resolver import FunctionResolver
from shellphish_crs_utils.oss_fuzz.project import OSSFuzzProject
from .base_agent import BaseAgent
from .tools import ToolEnvironment, create_llm_tools, retrieve_java_source, run_python_code
_l = logging.getLogger(__name__)


class WuOutput(SaveLoadObject):
    """
    This object describes the identified sinks.
    """

    generated_seed_script: str = Field(
        default="No", description="""
        The python script produced that generates the fuzzing inputs.
        """
    )


class WarmUpAgent(BaseAgent):
    """
    This agent will follow the steps above.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prompt_dir = os.path.join(current_dir, "prompts")
    _l.debug(f"llm folder is {prompt_dir}")
    system_prompt = os.path.join(prompt_dir, "wu.system.j2")
    user_prompt = os.path.join(prompt_dir, "generic.user.j2")

    __SYSTEM_PROMPT_TEMPLATE__ = system_prompt
    __USER_PROMPT_TEMPLATE__ = user_prompt
    __LLM_ARGS__ = {"temperature": 0}
    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

    harness_code: str
    fall_back_python_script: Path
    function_indexer_path: Path
    function_json_dir: Path
    project_source: Path
    cp_root: Path
    function_resolver: FunctionResolver
    oss_fuzz_build: OSSFuzzProject
    harness_name: str

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.tool_environment = ToolEnvironment(
            function_indexer_path=self.function_indexer_path,
            function_json_dir=self.function_json_dir,
            project_source=self.project_source,
            cp_root=self.cp_root,
            harness_name=self.harness_name,
            fall_back_python_script=self.fall_back_python_script,
            function_resolver=self.function_resolver,
            oss_fuzz_build=self.oss_fuzz_build,
        )
        create_llm_tools(tool_environment=self.tool_environment)

    def extract_step_attempt_context(
            self, step: AgentPlanStep, result: AgentResponse
    ) -> str:
        """
        Disable step summarization, and just use the last result from the LLM
        """
        return step.attempts[-1].result

    def extract_final_results(self) -> str:
        """
        Disable final output summarization and just use the last result from the LLM
        """
        steps = self.plan.get_past_steps()
        return steps[-1].attempts[-1].result

    def get_step_input_vars(self, step: AgentPlanStep) -> dict:
        # Template variables for the prompts
        return dict(
            **super().get_step_input_vars(step),
            harness_code=self.harness_code,
        )

    def on_step_success(self, step: AgentPlanStep, result):
        """
        This is just an example of how you could conditionally skip a step if you wanted.
        """
        if step.name == "should_we_skip_the_step":
            assert isinstance(result, str)
            if "true" in result.lower():
                # Skip over the next step
                self.plan.current_step += 1

        return super().on_step_success(step, result)

    # def validate_gen_scripts_result(self, result: str) -> CriticReview:
    #     """
    #     Validate the result of the generate_script step.
    #     """
    #     script = result.split("```")[1]
    #     if script.startswith("python"):
    #         script = script[6:]
    #     with tempfile.TemporaryDirectory() as tmpdir:
    #         with open(Path(tmpdir) / "llm_generated_script.py", "w") as f:
    #             f.write(script)
    #         _l.debug(f"Working at {tmpdir} to test llm generated script")
    #         with tempfile.NamedTemporaryFile(mode='w+') as error_file:
    #             p = subprocess.run(["python3", "llm_generated_script.py"], stdout=error_file,
    #                                 stderr=subprocess.STDOUT, text=True, errors="ignore",
    #                                 timeout=30, cwd=tmpdir)
    #             error_file.seek(0)
    #             output = error_file.read()
    #             _l.warning(f"The output of LLM generated python script is {output}")
    #             if p.returncode != 0:
    #                 return CriticReview(success=False, feedback=output).save_copy()
    #             else:
    #                 if "output.bin" not in os.listdir(tmpdir) and "output" not in os.listdir(tmpdir):
    #                     return CriticReview(success=False, feedback="No output.bin file or output directory generated after running the script").save_copy()
    #                 random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    #                 gen_seed_name = f"gen_seed_{random_string}.py"
    #                 with open(self.fall_back_python_script / gen_seed_name, "w") as f:
    #                     f.write(script)
    #                 return CriticReview(success=True, feedback="").save_copy()

    def validate_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt,
            result
    ) -> bool:
        # Here we can perform validation on the result of the step
        # If we return False, the agent will retry the step with our feedback

        # This first example will take the llm output and pass it into some other part
        # which uses that output and gives CriticFeedback
        if step.name == 'review_script':
            _l.debug(f"the script is {result}")
            assert (isinstance(result, str))
            res = self.validate_gen_scripts_result(result)
            if res.success:
                return True
            attempt.critic_review = res
            return False

        return super().validate_step_result(step, attempt, result)
    
    def get_available_tools(self) -> List[str]:
        """
        Return the list of available tools for this agent.
        """
        return [run_python_code, retrieve_java_source]
    
    # def get_cost(self):
    #     total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))
    #     return total_cost