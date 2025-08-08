#!/usr/bin/env python3
import os

os.chdir(os.path.dirname(__file__))

from agentlib import (
    PlanExecutor,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    Code, CriticReview, JavaCodeExtractor
)

# Create a plan for the agent to follow.
# We will hardcode our plan as a series of steps
PLAN = AgentPlan(steps=[
    AgentPlanStep(
        llm_model='claude-3.5-sonnet',
        description='Give yourself a cute nickname',
    ),
    AgentPlanStep(
        # Name the step so that we can detect it later
        name='write_code_step',
        # Description can contain anything you want to describe the current step
        description='Write a simple java program, but the first time you write it add a syntax error. Only do this once. Once asked to fix it, actually fix it and produce correct code.',
        output_parser=JavaCodeExtractor(),
    ),
])

class PlanFollowingTest(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    __SYSTEM_PROMPT_TEMPLATE__ = 'agent.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'agent.user.j2'

    counter: int = 0

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

        if step.name == 'write_code_step':
            assert isinstance(result, Code)

            if self.counter == 0:
                # We can leave a review for the attempt with feedback
                attempt.critic_review = CriticReview(
                    success=False,
                    feedback='There is a syntax error in your code, please fix it.'
                )
                self.counter += 1
                return False
            

        return super().validate_step_result(step, attempt, result)
    
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




