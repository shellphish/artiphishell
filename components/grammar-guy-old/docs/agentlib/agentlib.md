# Agentlib Tutorial

## BasicExecutor
This example is how you probably want to do the inital generation:
        https://github.com/shellphish-support-syndicate/agentlib/tree/main/examples/simple_chat_completion
        
- subclass Agent
- provide a user and system prompt templates in ./prompts
- then a.invoke(dict(some_params='foo')) with a set of params to template into the prompts

The use_web_logging_config(clear=True) part lets you run agentviz in the same directory to get a web UI. It also enables logging the prompts to the current terminal.

## PlanExecutor
And then this is a "PlanExecutor" agent where you give it a series of steps (tasks) to follow

https://github.com/shellphish-support-syndicate/agentlib/blob/main/examples/follow_existing_plan/main.py

- Create a AgentPlan with at least one AgentPlanStep describing the task you want it to complete. This can be a like simple description, you probably want to put more complex instructions in the actual prompt templates.
- Start with these existing prompt templates

https://github.com/shellphish-support-syndicate/agentlib/blob/main/examples/follow_existing_plan/prompts/agent.system.j2
https://github.com/shellphish-support-syndicate/agentlib/blob/main/examples/follow_existing_plan/prompts/agent.user.j2

These have the mechanics for the feedback and iterations.
The system prompt will be given to the agent once, and then the user prompt will be given at each attempt at iteration on the task.

So you might have a history like

        [ System Prompt ]
        [ User prompt attempt #1]
        [ LLM's attempt #1 ]
        [ User prompt with feedback for attempt #2]
        [ LLM's attempt #2 ]

etc until it passes your verification function.

Override the `validate_step_result` function in the agent. This will be called with the result of each iteration. Do your validation here.
If you decide the agent has not succeeded, set the attempt.`critic_review = CriticReview(success=False, feedback="text for the llm here")` and return false from the function
itszn — 02.06.2024 15:32

For each `AgentPlanStep` you can set `output_parser` to enable post-processing on the raw LLM output text. In the linked example, it is using `JavaCodeExtractor` which looks for java code blocks and extracts them into a `Code` object.

If you want arbitrary structred output from the LLM, you can define a class that subclasses `SaveLoadObject`, and describe each field in the object with `Field`. Then set the `output_parser` to `ObjectParser(MyCustomStructure)` and the LLM will be instructed on how to construct your Class type.

Here is an example: https://github.com/shellphish-support-syndicate/agentlib/blob/main/examples/harness_scope/main.py#L23

By default the output is just the string of the llm output.
If you want to specify a model, you can add `__LLM_MODEL__ = 'claude-3-opus'` to your agent class
One last thing to note, when you are creating your prompt templates, they use jinja2: https://jinja.palletsprojects.com/en/3.1.x/

However you cannot call methods from the jinaj2 templates, as that will not work with the LLM api backend during the comp. You can only access object properties
itszn — 02.06.2024 15:42

You can test running via the LLM api by setting the env `USE_LLM_API=1`. Note that right now the llm api only has creds for openai, not anthropic. But both should be supported at game time 