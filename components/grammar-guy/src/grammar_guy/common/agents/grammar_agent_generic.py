
import logging
import os

# Agentlib and CRS Utils stuff
from agentlib import Agent, tools

# grammar-guy imports
os.chdir(os.path.dirname(__file__))
from grammar_guy.common.improvement_strategies import *
from grammar_guy.common import config
from grammar_guy.common.utils import *

from grammar_guy.common.agents.grammar_agent_no_tool import GrammarAgentNoTool
from grammar_guy.common.agents.grammar_agent_incremental import GrammarAgentIncremental

logger = logging.getLogger('antique.grammar_guy')
logger.setLevel(logging.INFO)

class GrammarAgent(Agent[dict,str]):
    __LOGGER__ = logging.getLogger('GrammarAgent')
    __LOGGER__.setLevel('INFO')

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        return vars

    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost

def submit_grammar(grammar_string: str) -> str:
    '''
    Use this function when you have generated a valid grammar_string. Pass the grammar string as an argument to this function.
    You are not allowed to truncate the grammar or return partial grammars. You **MUST** use this function every time you have finished
    writing grammar to pass it to the agent. NEVER CALL THIS FUNCTION WITH AN INVALID OR EMPTY GRAMMAR STRING.

    params grammar_string: The grammar string. **The string provided as a parameter must be a valid and non empty grammar string**
    returns grammar_string: The grammar string.
    '''
    if grammar_string == '':
        return "The grammar string is empty! Please write a grammar according to your task and previous instructions. Then make sure to pass it as a parameter to this function."
    config.set_new_grammar(grammar_string)
    if config.get_new_grammar() is None:
        raise ValueError("The grammar string is empty! Please write a grammar according to your task and previous instructions. Then make sure to pass it as a parameter to this function.")
    else:
        # log.info(f"Retrieved grammar: \n {config.get_new_grammar()}")
        return config.get_new_grammar()

def setup_grammar_agent(
        system_prompt_template:str = 'report.system.j2',
        user_prompt_template:str = 'report.user.j2',
        llm_model:str = 'o3',
        temperature= 0.3,
        agent_type: str = ''
    ) -> Agent:
    ''' Initialize OpenAI client with API key
    :return: OpenAI client
    :rtype: OpenAI
    '''
    logger.info(f"🤖 Setting up Grammar Agent with model \"{llm_model}\" and agent type \"{agent_type}\" and prompt \"{system_prompt_template}\"")
    if agent_type == 'incremental':
        agent = GrammarAgentIncremental(
            __SYSTEM_PROMPT_TEMPLATE__  = f'{config.FUZZER_NAME}/{system_prompt_template}',
            __USER_PROMPT_TEMPLATE__    = f'{config.FUZZER_NAME}/{user_prompt_template}',
            __LLM_MODEL__               = llm_model,
            __LLM_ARGS__                = {'max_tokens': 16384},
        )
    elif agent_type == 'no_tool':
        agent = GrammarAgentNoTool(
            __SYSTEM_PROMPT_TEMPLATE__  = f'{config.FUZZER_NAME}/{system_prompt_template}',
            __USER_PROMPT_TEMPLATE__    = f'{config.FUZZER_NAME}/{user_prompt_template}',
            __LLM_MODEL__               = llm_model,
            __LLM_ARGS__                = {'max_tokens': 16384},
        )
    else:
        agent = GrammarAgent(
            __SYSTEM_PROMPT_TEMPLATE__  = f'{config.FUZZER_NAME}/{system_prompt_template}',
            __USER_PROMPT_TEMPLATE__    = f'{config.FUZZER_NAME}/{user_prompt_template}',
            __LLM_MODEL__               = llm_model,
            __LLM_ARGS__                = {'max_tokens': 16384},
        )
    agent.use_web_logging_config(clear=True)
    return agent
