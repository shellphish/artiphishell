#!/usr/bin/env python3
import os

# change dir before importing agentlib (it will create data dirs in cwd)
os.chdir(os.path.dirname(__file__))

from agentlib import AgentWithHistory

# Agent takes a dict of input vars to template and returns a string
class LunchChat(AgentWithHistory[dict,str]):
    __SYSTEM_PROMPT_TEMPLATE__ = 'simple.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'simple.user.j2'

    description: str
    ingredients: list[str]

    def get_input_vars(self, *args, **kw):
        vars = super().get_input_vars(*args, **kw)
        vars.update(
            any_extra_template_vars = 'here',
            lunch_description = self.description,
            ingredients = self.ingredients,
        )
        return vars

def main():
    agent = LunchChat(
        description = 'A tuna sandwich',
        ingredients = ['tuna', 'bread', 'mayo', 'marmite']
    )

    # Set it up so we can see the agentviz ui for this specific agent instance
    # (run `agentviz` it in this dir)
    agent.use_web_logging_config(clear=True)

    print("You are now chatting with your lunch")
    while True:
        msg = input('>> ')
        res = agent.invoke(dict(
            chat_message = msg
        ))
        print(res.value)


if __name__ == '__main__':
    main()

