#!/usr/bin/env python3
import os


# change dir before importing agentlib (it will create data dirs in cwd)
os.chdir(os.path.dirname(__file__))

from agentlib import LLMFunction


def main():
    lf = LLMFunction.create(
'''
This is the system prompt!
 Output Schema
The user's name is {{ name }}
{{ output_format }}
''',
'''
This is the user prompt!
What is my name?
''',
        output='json',
        model='o1-mini',
        use_logging=True,
        include_usage=True,
    )

    print(lf)

    res, usage = lf(
        name='geohot',
    )
    print(res)
    print(usage)
    print(usage.get_costs('o1-mini'))


if __name__ == '__main__':

    main()

