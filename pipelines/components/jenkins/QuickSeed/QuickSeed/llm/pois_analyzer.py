#!/usr/bin/env python3
import os
import sys
import json
import random
import subprocess
from typing import Generator, Optional, Any, List
import random
import string
import logging
from pathlib import Path
import json 

_l = logging.getLogger(__name__)

from QuickSeed.data import Node

import agentlib
from agentlib.lib import tools
from agentlib import (
    Agent, PlanExecutor,
    AgentResponse,
    AgentPlan, AgentPlanStep,
    AgentPlanStepAttempt,
    CodeExtractor, WebConsoleLogger,
    Code, CriticReview, JavaCodeExtractor,  LocalObject, SaveLoadObject,
    Field, ObjectParser
)



# @tools.tool
# def read_two_funcs() -> str:
#     """
#     This function will read the code.
#     """
#     funca = read_code(COMMITA)
#     return funca

class SG_Output(SaveLoadObject):
    """
    This object describes the change in two code snippets.
    - key1: value_description.
    - key1: value_description.
    """
    list_pois_name: List = Field(
        default=[],
        description='provide a list of interesting function names that is proposed by our agent'
    )
    reason: str = Field(
        default="No",
        description='Give us thereason why these functions are picked'
    )
    # details: str = Field(
    #     default="No",
    #     description='describe the result you want here'
    # )

def pois_agent(
    agent_path,
    model: str,
    pois: List[Node] = [],
    
):
    #FIXME: from queue we get a list of node so need to convert to string 
    pois_code = "\n".join(["" if poi.func_src is None else poi.func_src for poi in pois])
    os.chdir(os.path.dirname(__file__))
    
    # Create a plan for the agent to follow.
    PLAN = AgentPlan(steps=[
        AgentPlanStep(
        llm_model=model,
            name='analyze_functions',
            description='You are provided a list of java functions, analyze each function carefully and summarize them',
            #  available_tools=[
            #         find_code
            #         ]
        ),
        AgentPlanStep(
            llm_model=model,
            name='pick_interesting_functions',
            # Description can contain anything you want to describe the current step
            description='Choose the function that are fuzzer blockers, the function contains encryption like RSA or encoding like base64 and very complex functions that you think can be helpful in guiding our fuzzing campaign. You can find the function names in this format "#Function name is {Function name} ". You should use this function name in your output',
        ),
        AgentPlanStep(
            llm_model=model,
            name='provide_reason',
            # Description can contain anything you want to describe the current step
            description='Behave that there are three experts who are discussing about the functions you picked. The experts can share their opinions and thoughts on why or why not these functions should be selected. Experts must provide a reason to justify their thought.Ultimatly when the experts reach consensus, they should provide a list of functions they picked. You can only proceed if the the consensus is reached. ',
        ),
        
        
        # AgentPlanStep(
        #     llm_model=model,
        #     name='should_we_skip_the_step',
        #     description='Should we skip the next step? True or False',
        # ),
        # AgentPlanStep(
        #     llm_model=model,
        #     name='skipped_this_step',
        #     description='This step should have been skipped! Now we are all doomed.',
        # ),
        AgentPlanStep(
            llm_model=model,
            name='some_final_step',
            description='Save data in a text format. ',
            # this would save it in json format. 
            # hack - sometimes gpt changes the keys or adds spaces to json keynames. below is example of how to handle that
            # 'The output MUST be in the following JSON format and use the same keys OR I WILL DIE.\n' +
            #'{"equivalent": "Answer in Yes or No", "details": details_of_changes}'
            output_parser=ObjectParser(SG_Output)
        ),
    ])
    plan = PLAN.save_copy()

    agent: PoisAnalyzer = PoisAnalyzer.reload_id_from_file_or_new(
        agent_path,
        goal='yolo',
        plan=plan,
        pois_code=pois_code,
        use_model_name=model
        
    )

    agent.use_web_logging_config()

    agent.warn(f'========== Agents plan ==========\n')
    print(agent)
    print(agent.plan)

    agent.warn(f'========== Ruxnning agent ==========\n')

    res = agent.invoke()
    print(res)
    return res.list_pois_name, res.reason

# def try_using_seed(seed) -> Optional[CriticReview]:
#     # Do whatever you need with the output here and then give feedback based on that
#     # I am just going to decide by random
#     if random.randint(0,2) == 0:
#         return None
#     return CriticReview(
#         success=False,
#         feedback="""
#         That seed reached a part of the program
#         def totally_vulnerable_function(foo):
#             if foo.startswith('1234567890'):
#             os.system(foo)
# """)


class PoisAnalyzer(PlanExecutor[str, str]):
    """
    This agent will follow the steps above.
    """
    __SYSTEM_PROMPT_TEMPLATE__ = 'pa.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'pa.user.j2'

    pois_code: Optional[str]


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
            pois_code = self.pois_code,
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
            print(result)
            assert(isinstance(result, str))
            # res = try_using_seed(result)
            # if not res:
            #     return True
            # attempt.critic_review = res
            # return False

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
            print(result)
            assert(isinstance(result, str))
            if 'true' in result.lower():
                # Skip over the next step
                self.plan.current_step += 1

        return super().on_step_success(step, result)
    
def split_into_groups(lst, group_size=5):
    """
    Splits a list into groups of a specified size.
    :param lst: List to be split.
    :param group_size: Size of each group.
    :return: List of groups.
    """
    return [lst[i:i + group_size] for i in range(0, len(lst), group_size)]

        
        
        
        
        
    

    





