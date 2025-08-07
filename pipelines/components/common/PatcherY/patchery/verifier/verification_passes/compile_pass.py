import logging
import json
import os
import requests

from jinja2 import StrictUndefined, Template
from ...utils import llm_cost
from .base_verification_pass import BaseVerificationPass

_l = logging.getLogger(__name__)

LLM_FUNCTIONS = [
    {
        "type": "function",
        "function": {
            "name": "compile_error_summary",
            "description": "Analyzes a compile error provided by the user, provides a detailed summary of why the code does not compile, and offers a reminder to help avoid the same error in the future.",
            "parameters": {
                "type": "object",
                "properties": {
                    "error_reason": {
                        "type": "string",
                        "description": "A summary of the main reason for the compile error.",
                    },
                    "error_reminder": {
                        "type": "string",
                        "description": "A reminder or guideline to help prevent the same compile error in the future.",
                    },
                },
                "required": ["error_reason", "error_reminder"],
            },
        },
    }
]

COMPILE_ERROR_SUMMARY_PROMPT = """
# TASK
You are an interactive reverse-engineering and software engineering assistant. You will be asked to analyse a compile error and propose a summary and a reminder.
You need to indicate the reason why the code does not compile, propose a reminder in order to not make this error happen again.
In the error_reason field, indicate the compile error type, such as syntax error, type error, or missing import. Also, in the error_reason field, indicate the variable or function that caused the error.
In the error_reminder field, propose a reminder or guideline to help prevent the same compile error in the future, the reminder should be a general rule or a best practice that can be applied to similar situations.
REMEMBER THAT THE BUILD SCRIPTS CANNOT BE MODIFIED AND THE COMPILIER WARNING LEVELS CANNOT BE ADJUSTED.

# COMPILE ERROR
You have been provided with the following compiler error:
```
{{ COMPILER_ERROR }}
```
you should always use the tool compile_error_summary to summarize the error and provide a reminder to help avoid the same error in the future.
"""


class CompileVerificationPass(BaseVerificationPass):
    def __init__(self, *args, use_llm_on_err=False, **kwargs):
        self.use_llm_on_err = use_llm_on_err
        super().__init__(*args, **kwargs)

    def _verify(self):
        success, reason = self._prog_info.compile(patch=self._patch)
        reasoning = None
        if not success:
            if self.use_llm_on_err:
                reason_summary, reminder, self.cost = self.llm_summarize_compiler_error(reason)
                reasoning = f"Reason Summary: {reason_summary} \n\n\nYOU MUST OBEY THE FOLLOWING RULE TO GENERATE A PATCH: {reminder} \n "
            else:
                reasoning = f"Failed to compile: {reason}"

        return success, reasoning

    @staticmethod
    def llm_summarize_compiler_error(error: str):
        """
        Extracts the error message from the compiler output.

        :param error: A string containing the full error message output from the compiler.
        :return: A string that summarizes the main point of the error, and a string serves as a reminder to help avoid the same error.
        """
        MODEL = os.getenv("MODEL")
        if not MODEL:
            MODEL = "oai-gpt-4o"
        prompt = COMPILE_ERROR_SUMMARY_PROMPT
        prompt_args = dict(COMPILER_ERROR=error[-3000:])
        debug_prompt_template = Template(prompt, undefined=StrictUndefined)
        debug_prompt = debug_prompt_template.render(prompt_args)
        _l.debug(f"Prompt for compile error summary {debug_prompt}")
        # response = requests.post('http://beatty.unfiltered.seclab.cs.ucsb.edu:4269/completions', json={
        #     "secret_key": '!!Shellphish!!',
        #     'messages': [{'role': 'system',
        #                   'message_id': 0,
        #                   'author': 'patchery.generator.chain_of_thoughts_generator',
        #                   'prompt_template': prompt,
        #                   'prompt_args': prompt_args}],
        #     "response_message_id": 1,
        #     "requested_model": MODEL,
        #     "origin": "PatcherY",
        #     "tools":LLM_FUNCTIONS,
        #     "tool_choice":{"type": "function", "function": {"name": "compile_error_summary"}},
        # })
        if os.getenv("LITELLM_KEY"):
            key = os.environ.get("LITELLM_KEY")
        else:
            raise ValueError(f"Missing LLM API KEY")
        if os.getenv("AIXCC_LITELLM_HOSTNAME"):
            query_endpoint = os.environ.get("AIXCC_LITELLM_HOSTNAME")
        else:
            raise ValueError(f"Missing LLM API ENDPOINT URL")
        query_headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        prompt = {"role": "user", "content": debug_prompt}
        query_payload = json.dumps(
            {
                "messages": [prompt],
                "model": MODEL,
                "temperature": 0,
                "tools": LLM_FUNCTIONS,
                "tool_choice": {"type": "function", "function": {"name": "compile_error_summary"}},
            }
        )
        response = requests.post(query_endpoint, headers=query_headers, data=query_payload).json()

        output = response["choices"][0]["message"]
        completion_tokens = response["usage"]["completion_tokens"]
        prompt_tokens = response["usage"]["prompt_tokens"]
        _l.debug(f"prompt use {prompt_tokens} prompts tokens and {completion_tokens} completion_tokens")
        cost = llm_cost(MODEL, prompt_tokens, completion_tokens)
        if "tool_calls" in output and output["tool_calls"]:
            function_output = json.loads(output["tool_calls"][0]["function"]["arguments"])
            error_reason = function_output.get("error_reason", "Unknown reason")
            error_reminder = function_output.get("error_reminder", "No reminder")

            return error_reason, error_reminder, cost
        return "Unknown reason", "No reminder", cost
