#!/usr/bin/env python3
import os

# change dir before importing agentlib (it will create data dirs in cwd)
os.chdir(os.path.dirname(__file__))

import agentlib
from agentlib import Agent

# Agent takes a dict of input vars to template and returns a string
class SimpleChatCompletion(Agent[dict,str]):
    # Choose a language model to use (default gpt-4-turbo)
    #__LLM_MODEL__ = 'claude-3-sonnet'
    __LLM_MODEL__ = 'gpt-4-turbo'

    __SYSTEM_PROMPT_TEMPLATE__ = 'simple.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'simple.user.j2'

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            any_extra_template_vars = 'here',
            style = 'a rap',
            hacker = 'geohots',
        )
        return vars

def main():
    agent = SimpleChatCompletion()

    # Set it up so we can see the agentviz ui for this specific agent instance
    # (run `agentviz` it in this dir)
    agent.use_web_logging_config(clear=True)

    # Invoke the agent with the dict input
    res = agent.invoke(dict(
        myquestion = 'how does qira work?'
    ))
    print(res.value)


if __name__ == '__main__':
    main()

