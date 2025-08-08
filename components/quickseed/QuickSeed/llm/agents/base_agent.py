#!/usr/bin/env python3
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Any, List, Tuple, Union
from pathlib import Path
import random
import string

import yaml
from langchain_core.agents import AgentFinish
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

_l = logging.getLogger(__name__)

class BaseAgent(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    prompt_dir = os.path.join(current_dir, "prompts")
    _l.debug(f"llm folder is {prompt_dir}")
    user_prompt = os.path.join(prompt_dir, "generic.user.j2")

    __USER_PROMPT_TEMPLATE__ = user_prompt
    __LLM_ARGS__ = {"temperature": 0}
    __RAISE_ON_BUDGET_EXCEPTION__ = True
    __RAISE_ON_RATE_LIMIT_EXCEPTION__ = True

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
            hello="world",
        )

    def on_step_success(self, step: AgentPlanStep, result):
        """
        This is just an example of how you could conditionally skip a step if you wanted.
        """
        return super().on_step_success(step, result)

    def validate_gen_scripts_result(self, result: str) -> CriticReview:
        """
        Validate the result of the generate_script step.
        """
        if "```" not in result:
            script = result
        else:
            script = result.split("```")[1]
        if script.startswith("python"):
            script = script[6:]
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(Path(tmpdir) / "llm_generated_script.py", "w") as f:
                f.write(script)
            _l.debug(f"Working at {tmpdir} to test llm generated script")
            with tempfile.NamedTemporaryFile(mode='w+') as error_file:
                p = subprocess.run(["python3", "llm_generated_script.py"], stdout=error_file,
                                    stderr=subprocess.STDOUT, text=True, errors="ignore",
                                    timeout=30, cwd=tmpdir)
                error_file.seek(0)
                output = error_file.read()
                _l.warning(f"The output of LLM generated python script is {output}")
                if p.returncode != 0:
                    return CriticReview(success=False, feedback=output).save_copy()
                else:
                    if "output.bin" not in os.listdir(tmpdir) and "output" not in os.listdir(tmpdir):
                        return CriticReview(success=False, feedback="No output.bin file or output directory generated after running the script").save_copy()
                    random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
                    gen_seed_name = f"gen_seed_{random_string}.py"
  
                    with open(self.fall_back_python_script / gen_seed_name, "w") as f:
                        f.write(script)
                    return CriticReview(success=True, feedback="").save_copy()

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
        return super().validate_step_result(step, attempt, result)

    def get_cost(self):
        total_cost = sum((usage.get_costs(model)["total_cost"] for model, usage in self.token_usage.items()))
        _l.info("Total Cost: $%.2f", total_cost)
        return total_cost

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