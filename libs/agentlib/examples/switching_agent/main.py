#!/usr/bin/env python3
import os

# change dir before importing agentlib (it will create data dirs in cwd)
os.chdir(os.path.dirname(__file__))

import agentlib
from agentlib import AgentWithHistory, tools, Agent

# We can make a quick tool by using the @tool.tool decorator
# Make sure to add type hints which are provided to the LLM
# You must also include a docstring which will be used as the tool description
@tools.tool
def reverse_string(s: str) -> str:
    """Reverse the input string, a fun tool for a fun agent, and you want to be a fun agent right?"""
    return s[::-1]

# Agent takes a dict of input vars to template and returns a string
class BashBoy(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'simple.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'simple.user.j2'
    __LLM_MODEL__ = 'claude-3-7-sonnet'
    __LLM_ARGS__ = {
        'stop': ['<this-is-my-final-answer>'],
        'max_tokens': 8192,
    }

    def get_available_tools(self):
        return [
            # Import some predefined tools
            tools.run_shell_command,
            tools.give_up_on_task,
        ]

class FinalAnswerGuy(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'final.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'final.user.j2'
    __LLM_MODEL__ = 'gpt-4.1-mini'
    __LLM_ARGS__ = {
        'max_tokens': 20000,
    }

def main():
    agent = BashBoy()

    # Set it up so we can see the agentviz ui for this specific agent instance
    # (run `agentviz` it in this dir)
    agent.use_web_logging_config(clear=True)

    print("WARNING! This agent will run commands unsandboxed in the CWD, proceed with caution.")
    while True:
        msg = input('>> ')
        res = agent.invoke(dict(
            myquestion = msg
        ))
        if '<this-is-my-final-answer>' in res.value:
            final_agent = FinalAnswerGuy()
            final_agent.chat_history = agent.chat_history
            res = final_agent.invoke(dict(
                myquestion = msg
            ))
            print(res.value)
            break
        print(res.value)


if __name__ == '__main__':
    main()

