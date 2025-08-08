#!/usr/bin/env python3
import os
import random
from typing import Optional

os.chdir(os.path.dirname(__file__))

from agentlib import (
    PlanExecutor,
    AgentResponse,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    CriticReview
)

# Create a plan for the agent to follow.
# We will hardcode our plan as a series of steps
PLAN = AgentPlan(steps=[
    AgentPlanStep(
        name='first_step',
        description='Some initial step if you need it',
    ),
    AgentPlanStep(
        # Name the step so that we can detect it later
        name='generate_seed',
        # Description can contain anything you want to describe the current step
        description='Give ma a seed string',
    ),
    AgentPlanStep(
        name='should_we_skip_the_step',
        description='Should we skip the next step? True or False',
    ),
    AgentPlanStep(
        name='skipped_this_step',
        description='This step should have been skipped! Now we are all doomed.',
    ),
    AgentPlanStep(
        name='some_final_step',
        description='The last step!',
    ),
])

def try_using_seed(seed) -> Optional[CriticReview]:
    # Do whatever you need with the output here and then give feedback based on that
    # I am just going to decide by random
    if random.randint(0,2) == 0:
        return None
    return CriticReview(
        success=False,
        feedback="""
That seed reached a part of the program
def totally_vulnerable_function(foo):
    if foo.startswith('1234567890'):
      os.system(foo)
""")
  

class PlanFollowingTest(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    __SYSTEM_PROMPT_TEMPLATE__ = 'agent.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'agent.user.j2'

    counter: int = 0

    def extract_step_attempt_context(
        self,
        step: AgentPlanStep,
        result: AgentResponse
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
            hello = 'world',
            counter = self.counter,
        )

    def validate_step_result(
            self,
            step: AgentPlanStep,
            attempt: AgentPlanStepAttempt,
            result
    ) -> bool:
        # Here we can perform validation on the result of the step
        # If we return False, the agent will retry the step with our feedback

        # This first example will take the llm output and pass it into some other part which uses that output and gives CriticFeedback
        if step.name == 'generate_seed':
            assert(isinstance(result, str))
            res = try_using_seed(result)
            if not res:
                return True
            attempt.critic_review = res
            return False

        return super().validate_step_result(step, attempt, result)

    def on_step_success(
            self,
            step: AgentPlanStep,
            result
    ):
        """
        This is just an example of how you could conditionally skip a step if you wanted.
        """
        if step.name == 'should_we_skip_the_step':
            assert(isinstance(result, str))
            if 'true' in result.lower():
                # Skip over the next step
                self.plan.current_step += 1

        return super().on_step_success(step, result)
    
def main():

    # Path to save agent data to
    agent_path = '/tmp/test_agent.json'
    plan = PLAN.save_copy()

    agent: PlanFollowingTest = PlanFollowingTest.reload_id_from_file_or_new(
        agent_path,
        goal='yolo',
        plan=plan
    )

    agent.use_web_logging_config()

    agent.warn('========== Agents plan ==========\n')
    print(agent)
    print(agent.plan)

    agent.warn('========== Running agent ==========\n')

    res = agent.invoke()
    print(res)


if __name__ == '__main__':
    main()




